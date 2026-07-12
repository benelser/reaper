//! The TUI (§8): streaming, keyboard-first, loud about permanence. Both
//! surfaces share one classify() — identical verdicts by construction. The
//! render loop is sync (crossterm poll); the scan streams from a worker
//! thread over mpsc. Every safety affordance here is pure render state.

use camino::Utf8PathBuf;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row as TRow, Table, TableState};
use reaper_core::{
    admit, classify, plan, seal, Disposition, Policy, RefusalReason, Registry, SealedPlan,
};
use reaper_scan::{
    gather_facts, prober, scan, Deleter, Prober, ScanEvent, StepOutcome, SystemClock,
};
use std::sync::mpsc;
use std::time::Duration;

struct Item {
    facts: reaper_core::Facts,
    disposition: Disposition,
    marked: bool,
}

enum Msg {
    Item(Box<Item>),
    ScanDone { dirs: u64, files: u64 },
}

enum Mode {
    Browse,
    Filter(String),
    Confirm(SealedPlan),
    Report(Vec<StepOutcome>),
}

pub fn run(root: Utf8PathBuf, manifest_dir: Utf8PathBuf) -> std::io::Result<()> {
    // Terminal must be restored on ANY exit — panic hook first (§7).
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        default_hook(info);
    }));
    let mut terminal = ratatui::init();

    let (tx, rx) = mpsc::channel::<Msg>();
    let scan_root = root.clone();
    std::thread::spawn(move || {
        let registry = Registry::embedded().expect("embedded ruleset loads");
        let reader = reaper_scan::select_reader();
        let clock = SystemClock;
        let prober = Prober {
            reader: reader.as_ref(),
            clock: &clock,
            root_dev: prober::device_of(&scan_root),
        };
        let live = reaper_scan::select_probe();
        let git = reaper_scan::GixProbe;
        let policy = Policy::default();
        // Discover first (fast), then probe each candidate and stream the
        // classified row up — sizes and verdicts appear as they're computed.
        let found = std::sync::Mutex::new(Vec::new());
        let totals = scan(&scan_root, &registry, reader.as_ref(), &|ev| {
            if let ScanEvent::Discovered(c) = ev {
                found.lock().unwrap().push(c);
            }
        });
        let candidates = found.into_inner().unwrap();
        for facts in gather_facts(&candidates, &prober, live.as_deref(), Some(&git)) {
            let disposition = classify(&facts, &policy);
            if tx
                .send(Msg::Item(Box::new(Item {
                    facts,
                    disposition,
                    marked: false,
                })))
                .is_err()
            {
                return;
            }
        }
        let _ = tx.send(Msg::ScanDone {
            dirs: totals.dirs,
            files: totals.files,
        });
    });

    let mut items: Vec<Item> = Vec::new();
    let mut table = TableState::default();
    let mut mode = Mode::Browse;
    let mut scan_status = String::from("scanning…");
    let policy = Policy::default();

    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                Msg::Item(item) => {
                    items.push(*item);
                    items.sort_by(|a, b| {
                        b.facts
                            .size_bytes
                            .unwrap_or(0)
                            .cmp(&a.facts.size_bytes.unwrap_or(0))
                    });
                    if table.selected().is_none() {
                        table.select(Some(0));
                    }
                }
                Msg::ScanDone { dirs, files } => {
                    scan_status = format!("{dirs} dirs · {files} files scanned");
                }
            }
        }

        let filter = match &mode {
            Mode::Filter(f) => f.clone(),
            _ => String::new(),
        };
        let visible: Vec<usize> = items
            .iter()
            .enumerate()
            .filter(|(_, it)| {
                filter.is_empty() || it.facts.candidate.path.as_str().contains(&filter)
            })
            .map(|(i, _)| i)
            .collect();

        terminal.draw(|f| draw(f, &items, &visible, &mut table, &mode, &scan_status))?;

        if !event::poll(Duration::from_millis(50))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match &mut mode {
            Mode::Filter(f) => match key.code {
                KeyCode::Esc => mode = Mode::Browse,
                KeyCode::Enter => mode = Mode::Browse,
                KeyCode::Backspace => {
                    f.pop();
                }
                KeyCode::Char(c) => f.push(c),
                _ => {}
            },
            Mode::Confirm(sealed) => match key.code {
                // The §8.5 typed confirm: `y` commits, anything else aborts.
                KeyCode::Char('y') => {
                    let manifest = manifest_dir
                        .join("log")
                        .join(format!("{}.jsonl", sealed.digest.replace(':', "-")));
                    let live = reaper_scan::select_probe();
                    let mut deleter =
                        Deleter::new(&manifest, live.as_deref()).expect("manifest opens");
                    let outcomes = deleter.execute(sealed);
                    // Reaped rows leave the model; refusals stay visible.
                    let reaped: Vec<Utf8PathBuf> = outcomes
                        .iter()
                        .filter_map(|o| match o {
                            StepOutcome::Reaped { path, .. } => Some(path.clone()),
                            StepOutcome::Refused { .. } => None,
                        })
                        .collect();
                    items.retain(|it| !reaped.contains(&it.facts.candidate.path));
                    table.select(if items.is_empty() { None } else { Some(0) });
                    mode = Mode::Report(outcomes);
                }
                _ => mode = Mode::Browse,
            },
            Mode::Report(_) => mode = Mode::Browse,
            Mode::Browse => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                KeyCode::Down | KeyCode::Char('j') => bump(&mut table, &visible, 1),
                KeyCode::Up | KeyCode::Char('k') => bump(&mut table, &visible, -1),
                KeyCode::Char('/') => mode = Mode::Filter(String::new()),
                KeyCode::Char(' ') => {
                    if let Some(idx) = table.selected().and_then(|v| visible.get(v)) {
                        let it = &mut items[*idx];
                        // Refused rows can't be marked (§8.2): the safety net
                        // is on screen, not silent.
                        if matches!(it.disposition, Disposition::Reapable) {
                            it.marked = !it.marked;
                        }
                    }
                }
                KeyCode::Char('a') => {
                    for &idx in &visible {
                        if matches!(items[idx].disposition, Disposition::Reapable) {
                            items[idx].marked = true;
                        }
                    }
                }
                KeyCode::Char('x') | KeyCode::Char('d') => {
                    let marked: Vec<_> = items
                        .iter()
                        .filter(|it| it.marked)
                        .filter_map(|it| admit(&it.facts, &policy).ok())
                        .collect();
                    if !marked.is_empty() {
                        let p = plan(&marked);
                        let bindings: Vec<_> = p
                            .steps
                            .iter()
                            .map(|s| prober::identity_of(s.path()))
                            .collect();
                        let sizes: Vec<u64> = p
                            .steps
                            .iter()
                            .map(|s| {
                                marked
                                    .iter()
                                    .find(|a| &a.facts().candidate.path == s.path())
                                    .and_then(|a| a.facts().size_bytes)
                                    .unwrap_or(0)
                            })
                            .collect();
                        mode = Mode::Confirm(seal(&p, &bindings, &sizes));
                    }
                }
                _ => {}
            },
        }
    }

    ratatui::restore();
    Ok(())
}

fn bump(table: &mut TableState, visible: &[usize], delta: i64) {
    if visible.is_empty() {
        return;
    }
    let cur = table.selected().unwrap_or(0) as i64;
    let next = (cur + delta).clamp(0, visible.len() as i64 - 1);
    table.select(Some(next as usize));
}

fn draw(
    f: &mut ratatui::Frame,
    items: &[Item],
    visible: &[usize],
    table: &mut TableState,
    mode: &Mode,
    scan_status: &str,
) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .areas(f.area());

    let marked_bytes: u64 = items
        .iter()
        .filter(|i| i.marked)
        .map(|i| i.facts.size_bytes.unwrap_or(0))
        .sum();
    let marked_count = items.iter().filter(|i| i.marked).count();

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" reaper ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("── {scan_status} · {} candidates ", items.len())),
        ])),
        header,
    );

    let rows: Vec<TRow> = visible
        .iter()
        .map(|&i| {
            let it = &items[i];
            let (mark, style) = match (&it.disposition, it.marked) {
                (Disposition::Reapable, true) => ("✔", Style::default().fg(Color::Green)),
                (Disposition::Reapable, false) => ("·", Style::default().fg(Color::Green)),
                (Disposition::Refused { .. }, _) => (" ", Style::default().fg(Color::DarkGray)),
            };
            let verdict = match &it.disposition {
                Disposition::Reapable => "● reapable".to_string(),
                Disposition::Refused { reasons } => {
                    let brief: Vec<String> = reasons.iter().map(reason_short).collect();
                    format!("⚠ {}", brief.join(" "))
                }
            };
            TRow::new(vec![
                mark.to_string(),
                human_bytes(it.facts.size_bytes.unwrap_or(0)),
                it.facts.candidate.ecosystem.0.clone(),
                it.facts
                    .idle_days
                    .map(|d| format!("{d}d"))
                    .unwrap_or_else(|| "?".into()),
                it.facts.candidate.path.to_string(),
                verdict,
            ])
            .style(style)
        })
        .collect();
    let widths = [
        Constraint::Length(1),
        Constraint::Length(9),
        Constraint::Length(8),
        Constraint::Length(5),
        Constraint::Percentage(50),
        Constraint::Min(20),
    ];
    f.render_stateful_widget(
        Table::new(rows, widths)
            .header(TRow::new(vec![
                "", "SIZE", "ECO", "IDLE", "PATH", "VERDICT",
            ]))
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        body,
        table,
    );

    // §8.4: permanence is loud, always.
    let banner = match mode {
        Mode::Confirm(sealed) => Line::from(Span::styled(
            format!(
                " ⚠ PERMANENT DELETE — {} step(s), {} · type y to commit, any key aborts ",
                sealed.steps.len(),
                human_bytes(sealed.steps.iter().map(|s| s.size_bytes).sum())
            ),
            Style::default().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Mode::Report(outcomes) => {
            let freed: u64 = outcomes
                .iter()
                .map(|o| match o {
                    StepOutcome::Reaped { freed_bytes, .. } => *freed_bytes,
                    StepOutcome::Refused { .. } => 0,
                })
                .sum();
            let refused = outcomes.iter().filter(|o| matches!(o, StepOutcome::Refused { .. })).count();
            Line::from(Span::styled(
                format!(" freed {} · {refused} left in place · any key continues ", human_bytes(freed)),
                Style::default().fg(Color::Black).bg(Color::Green),
            ))
        }
        Mode::Filter(fil) => Line::from(format!(" / {fil}▌  (Enter/Esc done)")),
        Mode::Browse => Line::from(Span::styled(
            format!(
                " SELECTED {} in {marked_count} · ⚠ PERMANENT DELETE · space mark  a all  x reap  / filter  q quit ",
                human_bytes(marked_bytes)
            ),
            Style::default().fg(Color::Red),
        )),
    };
    let help = Paragraph::new(banner).block(Block::default().borders(Borders::TOP));
    f.render_widget(help, footer);
}

fn reason_short(r: &RefusalReason) -> String {
    match r {
        RefusalReason::Dirty { entries } => format!("dirty({entries})"),
        RefusalReason::UnpushedCommits { count } => format!("unpushed({count})"),
        RefusalReason::Locked { .. } => "locked".into(),
        RefusalReason::Detached { .. } => "detached".into(),
        RefusalReason::LiveProcess { pids } => format!("live({})", pids.len()),
        RefusalReason::ActiveBuild { .. } => "building".into(),
        RefusalReason::CrossDevice => "xdev".into(),
        RefusalReason::CloudBacked => "cloud".into(),
        RefusalReason::Protected { .. } => "protected".into(),
        RefusalReason::CachesExcluded => "cache(opt-in)".into(),
        RefusalReason::TooRecent {
            idle_days,
            min_idle_days,
        } => {
            format!("fresh({idle_days}d<{min_idle_days}d)")
        }
        RefusalReason::TooSmall { .. } => "small".into(),
        RefusalReason::Unknown { what } => format!("?{what}"),
    }
}

fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = b as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{b}{}", UNITS[0])
    } else {
        format!("{v:.1}{}", UNITS[unit])
    }
}
