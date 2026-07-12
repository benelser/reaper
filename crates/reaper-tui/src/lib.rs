//! The reaper TUI. Design rules: the user must ALWAYS know what reaper is
//! doing and where; feedback is continuous (spinner, counters, gauge, live
//! sizes); color is ANSI-palette so the user's terminal theme carries the
//! look; red is reserved for permanence alone. One classify()/plan()/seal()/
//! Deleter shared with the CLI — identical verdicts by construction.

use camino::Utf8PathBuf;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Clear, Gauge, Padding, Paragraph, Row as TRow, Table, TableState,
};
use reaper_core::{
    admit, classify, plan, seal, Candidate, Disposition, Policy, RefusalReason, Registry,
    SafetyClass, SealedPlan,
};
use reaper_scan::{prober, scan, Deleter, Prober, ScanEvent, StepOutcome, SystemClock};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub fn run(root: Utf8PathBuf, state_dir: Utf8PathBuf) -> std::io::Result<()> {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        default_hook(info);
    }));
    let mut terminal = ratatui::init();
    let mut app = App::new(root, state_dir);
    let mut rx = spawn_scan(app.root.clone());

    loop {
        while let Ok(msg) = rx.try_recv() {
            app.apply(msg);
        }
        // Reap progress mutates the model too — drain BEFORE the view is
        // computed so no stale index survives into draw (panic regression).
        if let Some(rrx) = &app.reap_rx {
            let msgs: Vec<Msg> = rrx.try_iter().collect();
            for m in msgs {
                app.apply(m);
            }
        }
        let visible = app.visible();
        if app.table.selected().is_none() && !visible.is_empty() {
            app.table.select(Some(0));
        }
        if let Some(sel) = app.table.selected() {
            if sel >= visible.len() && !visible.is_empty() {
                app.table.select(Some(visible.len() - 1));
            }
        }
        terminal.draw(|f| draw(f, &mut app, &visible))?;

        if !event::poll(Duration::from_millis(66))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            break;
        }
        match app.handle_key(key.code, &visible) {
            Action::Quit => break,
            Action::Rescan => {
                app.reset_for_rescan();
                rx = spawn_scan(app.root.clone());
            }
            Action::None => {}
        }
    }
    ratatui::restore();
    Ok(())
}

// ------------------------------------------------------------------ model --

struct Item {
    candidate: Candidate,
    facts: Option<reaper_core::Facts>,
    disposition: Option<Disposition>,
    marked: bool,
}

impl Item {
    fn reapable(&self) -> bool {
        matches!(self.disposition, Some(Disposition::Reapable))
    }
    fn size(&self) -> Option<u64> {
        self.facts.as_ref().and_then(|f| f.size_bytes)
    }
    fn idle(&self) -> Option<u64> {
        self.facts.as_ref().and_then(|f| f.idle_days)
    }
}

enum Msg {
    Discovered(Candidate),
    Walked {
        dirs: u64,
        files: u64,
    },
    WalkDone {
        dirs: u64,
        files: u64,
    },
    Probed {
        path: Utf8PathBuf,
        facts: Box<reaper_core::Facts>,
        disposition: Disposition,
    },
    ReapStep(StepOutcome),
    ReapDone,
}

#[derive(PartialEq)]
enum Overlay {
    None,
    Help,
    Preview,
    Confirm(SealedPlan),
    Reaping(Vec<StepOutcome>, usize), // outcomes so far, total steps
    Report(Vec<StepOutcome>),
}

#[derive(Clone, Copy, PartialEq)]
enum SortKey {
    Size,
    Idle,
    Path,
}

impl SortKey {
    fn next(self) -> Self {
        match self {
            SortKey::Size => SortKey::Idle,
            SortKey::Idle => SortKey::Path,
            SortKey::Path => SortKey::Size,
        }
    }
    fn label(self) -> &'static str {
        match self {
            SortKey::Size => "size ↓",
            SortKey::Idle => "idle ↓",
            SortKey::Path => "path ↑",
        }
    }
}

enum Action {
    None,
    Quit,
    Rescan,
}

struct App {
    root: Utf8PathBuf,
    state_dir: Utf8PathBuf,
    items: Vec<Item>,
    table: TableState,
    overlay: Overlay,
    filter: String,
    filtering: bool,
    facet: Option<String>,
    sort: SortKey,
    walk: (u64, u64),
    walk_done: bool,
    started: Instant,
    freed_total: u64,
    tick: usize,
    reap_rx: Option<mpsc::Receiver<Msg>>,
}

impl App {
    fn new(root: Utf8PathBuf, state_dir: Utf8PathBuf) -> Self {
        Self {
            root,
            state_dir,
            items: Vec::new(),
            table: TableState::default(),
            overlay: Overlay::None,
            filter: String::new(),
            filtering: false,
            facet: None,
            sort: SortKey::Size,
            walk: (0, 0),
            walk_done: false,
            started: Instant::now(),
            freed_total: 0,
            tick: 0,
            reap_rx: None,
        }
    }

    fn reset_for_rescan(&mut self) {
        self.items.clear();
        self.walk = (0, 0);
        self.walk_done = false;
        self.started = Instant::now();
        self.table.select(None);
    }

    fn probed(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.disposition.is_some())
            .count()
    }
    fn reapable_bytes(&self) -> u64 {
        self.items
            .iter()
            .filter(|i| i.reapable())
            .filter_map(|i| i.size())
            .sum()
    }

    fn apply(&mut self, msg: Msg) {
        match msg {
            Msg::Discovered(c) => self.items.push(Item {
                candidate: c,
                facts: None,
                disposition: None,
                marked: false,
            }),
            Msg::Walked { dirs, files } => self.walk = (dirs, files),
            Msg::WalkDone { dirs, files } => {
                self.walk = (dirs, files);
                self.walk_done = true;
            }
            Msg::Probed {
                path,
                facts,
                disposition,
            } => {
                if let Some(it) = self.items.iter_mut().find(|i| i.candidate.path == path) {
                    it.facts = Some(*facts);
                    it.disposition = Some(disposition);
                }
            }
            Msg::ReapStep(o) => {
                if let StepOutcome::Reaped {
                    path, freed_bytes, ..
                } = &o
                {
                    self.freed_total += freed_bytes;
                    self.items.retain(|it| &it.candidate.path != path);
                }
                if let Overlay::Reaping(outcomes, _) = &mut self.overlay {
                    outcomes.push(o);
                }
            }
            Msg::ReapDone => {
                if let Overlay::Reaping(outcomes, _) =
                    std::mem::replace(&mut self.overlay, Overlay::None)
                {
                    self.overlay = Overlay::Report(outcomes);
                }
                self.reap_rx = None;
                for it in self.items.iter_mut() {
                    it.marked = false;
                }
            }
        }
    }

    fn visible(&self) -> Vec<usize> {
        let needle = self.filter.to_lowercase();
        let mut v: Vec<usize> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, it)| {
                (needle.is_empty() || it.candidate.path.as_str().to_lowercase().contains(&needle))
                    && self
                        .facet
                        .as_ref()
                        .is_none_or(|f| &it.candidate.ecosystem.0 == f)
            })
            .map(|(i, _)| i)
            .collect();
        match self.sort {
            SortKey::Size => {
                v.sort_by_key(|&i| std::cmp::Reverse(self.items[i].size().unwrap_or(0)))
            }
            SortKey::Idle => {
                v.sort_by_key(|&i| std::cmp::Reverse(self.items[i].idle().unwrap_or(0)))
            }
            SortKey::Path => v.sort_by(|&a, &b| {
                self.items[a]
                    .candidate
                    .path
                    .cmp(&self.items[b].candidate.path)
            }),
        }
        v
    }

    fn handle_key(&mut self, code: KeyCode, visible: &[usize]) -> Action {
        match &self.overlay {
            Overlay::Confirm(sealed) => {
                if code == KeyCode::Char('y') {
                    let sealed = sealed.clone();
                    let total = sealed.steps.len();
                    self.overlay = Overlay::Reaping(Vec::new(), total);
                    self.reap_rx = Some(spawn_reap(sealed, self.state_dir.clone()));
                } else {
                    self.overlay = Overlay::None;
                }
                return Action::None;
            }
            Overlay::Reaping(..) => return Action::None, // hands off mid-reap
            Overlay::Help | Overlay::Preview | Overlay::Report(_) => {
                self.overlay = Overlay::None;
                return Action::None;
            }
            Overlay::None => {}
        }
        if self.filtering {
            match code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filtering = false;
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            return Action::None;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('g') => return Action::Rescan,
            KeyCode::Down | KeyCode::Char('j') => self.bump(visible, 1),
            KeyCode::Up | KeyCode::Char('k') => self.bump(visible, -1),
            KeyCode::PageDown => self.bump(visible, 12),
            KeyCode::PageUp => self.bump(visible, -12),
            KeyCode::Home => self.table.select(Some(0)),
            KeyCode::Char('/') => self.filtering = true,
            KeyCode::Char('e') => self.cycle_facet(),
            KeyCode::Char('s') => self.sort = self.sort.next(),
            KeyCode::Char('?') => self.overlay = Overlay::Help,
            KeyCode::Enter => {
                if self.selected(visible).is_some() {
                    self.overlay = Overlay::Preview;
                }
            }
            KeyCode::Char(' ') => {
                if let Some(i) = self.selected_idx(visible) {
                    if self.items[i].reapable() {
                        self.items[i].marked = !self.items[i].marked;
                        self.bump(visible, 1); // flow: mark advances
                    }
                }
            }
            KeyCode::Char('a') => {
                let all = visible
                    .iter()
                    .filter(|&&i| self.items[i].reapable())
                    .all(|&i| self.items[i].marked);
                for &i in visible {
                    if self.items[i].reapable() {
                        self.items[i].marked = !all;
                    }
                }
            }
            KeyCode::Char('x') | KeyCode::Char('d') => {
                let policy = Policy::default();
                let marked: Vec<_> = self
                    .items
                    .iter()
                    .filter(|it| it.marked)
                    .filter_map(|it| it.facts.as_ref())
                    .filter_map(|f| admit(f, &policy).ok())
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
                    self.overlay = Overlay::Confirm(seal(&p, &bindings, &sizes));
                }
            }
            _ => {}
        }
        Action::None
    }

    fn cycle_facet(&mut self) {
        let mut ecos: Vec<String> = self
            .items
            .iter()
            .map(|i| i.candidate.ecosystem.0.clone())
            .collect();
        ecos.sort();
        ecos.dedup();
        self.facet = match &self.facet {
            None => ecos.first().cloned(),
            Some(cur) => match ecos.iter().position(|e| e == cur) {
                Some(i) if i + 1 < ecos.len() => Some(ecos[i + 1].clone()),
                _ => None,
            },
        };
    }

    fn selected_idx(&self, visible: &[usize]) -> Option<usize> {
        self.table.selected().and_then(|v| visible.get(v)).copied()
    }
    fn selected<'a>(&'a self, visible: &[usize]) -> Option<&'a Item> {
        self.selected_idx(visible).map(|i| &self.items[i])
    }
    fn bump(&mut self, visible: &[usize], delta: i64) {
        if visible.is_empty() {
            return;
        }
        let cur = self.table.selected().unwrap_or(0) as i64;
        self.table.select(Some(
            (cur + delta).clamp(0, visible.len() as i64 - 1) as usize
        ));
    }
}

// ----------------------------------------------------------------- workers -

fn spawn_scan(root: Utf8PathBuf) -> mpsc::Receiver<Msg> {
    let (tx, rx) = mpsc::channel::<Msg>();
    std::thread::spawn(move || {
        let registry = Registry::embedded().expect("embedded ruleset loads");
        let reader = reaper_scan::select_reader();
        let clock = SystemClock;
        let prober = Prober {
            reader: reader.as_ref(),
            clock: &clock,
            root_dev: prober::device_of(&root),
        };
        let git = reaper_scan::GixProbe;
        let policy = Policy::default();

        let discovered = std::sync::Mutex::new(Vec::new());
        let stream = tx.clone();
        let totals = scan(&root, &registry, reader.as_ref(), &|ev| match ev {
            ScanEvent::Discovered(c) => {
                let _ = stream.send(Msg::Discovered(c.clone()));
                discovered.lock().unwrap().push(c);
            }
            ScanEvent::Progress { dirs, files } => {
                let _ = stream.send(Msg::Walked { dirs, files });
            }
            _ => {}
        });
        let _ = tx.send(Msg::WalkDone {
            dirs: totals.dirs,
            files: totals.files,
        });

        let candidates = discovered.into_inner().unwrap();
        // Sweep FIRST (one fast pass over the process table), then probe each
        // candidate in parallel and STREAM its verdict the moment it lands —
        // sizes trickle in instead of arriving all at once at the end.
        let live = reaper_scan::select_probe();
        let pids: Vec<Option<Vec<u32>>> = match &live {
            Some(probe) => {
                let dirs: Vec<Utf8PathBuf> =
                    candidates.iter().map(|c| c.path.clone()).collect();
                probe.live_pids(&dirs)
            }
            None => vec![None; candidates.len()],
        };
        rayon::scope(|sc| {
            for (c, live_pids) in candidates.iter().zip(pids) {
                let tx = tx.clone();
                let prober = &prober;
                let git = &git;
                let policy = &policy;
                sc.spawn(move |_| {
                    let mut f = prober.probe(c);
                    if matches!(c.safety_class, SafetyClass::GitWorktree) {
                        f.git = reaper_core::GitProbe::facts(git, &c.path);
                    }
                    f.live_pids = live_pids;
                    let disposition = classify(&f, policy);
                    let _ = tx.send(Msg::Probed {
                        path: f.candidate.path.clone(),
                        facts: Box::new(f),
                        disposition,
                    });
                });
            }
        });
    });
    rx
}

fn spawn_reap(sealed: SealedPlan, state_dir: Utf8PathBuf) -> mpsc::Receiver<Msg> {
    let (tx, rx) = mpsc::channel::<Msg>();
    std::thread::spawn(move || {
        let manifest = state_dir
            .join("log")
            .join(format!("{}.jsonl", sealed.digest.replace(':', "-")));
        let live = reaper_scan::select_probe();
        match Deleter::new(&manifest, live.as_deref()) {
            Ok(mut d) => {
                d.execute_with(&sealed, &mut |o| {
                    let _ = tx.send(Msg::ReapStep(o.clone()));
                });
            }
            Err(e) => {
                let _ = tx.send(Msg::ReapStep(StepOutcome::Refused {
                    path: Utf8PathBuf::from("(manifest)"),
                    why: format!("cannot open write-ahead manifest: {e}"),
                }));
            }
        }
        let _ = tx.send(Msg::ReapDone);
    });
    rx
}

// ------------------------------------------------------------------- draw --

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const ACCENT: Color = Color::Green;
const CHROME: Color = Color::DarkGray;

fn draw(f: &mut ratatui::Frame, app: &mut App, visible: &[usize]) {
    app.tick = app.tick.wrapping_add(1);
    let frame = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(CHROME))
        .title(Line::from(vec![
            Span::styled(" 💀 reaper ", Style::new().bold().fg(ACCENT)),
            Span::styled(app.root.to_string(), Style::new().bold()),
            Span::raw(" "),
        ]))
        .title_alignment(Alignment::Left);
    let inner = frame.inner(f.area());
    f.render_widget(frame, f.area());

    let [status, list, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(inner.inner(Margin {
        horizontal: 1,
        vertical: 0,
    }));

    draw_status(f, app, status);
    draw_list(f, app, visible, list);
    draw_footer(f, app, footer);

    match &app.overlay {
        Overlay::None => {}
        Overlay::Help => draw_help(f),
        Overlay::Preview => {
            if let Some(it) = app.selected(visible) {
                draw_preview(f, it);
            }
        }
        Overlay::Confirm(sealed) => draw_confirm(f, sealed),
        Overlay::Reaping(outcomes, total) => draw_reaping(f, app, outcomes, *total),
        Overlay::Report(outcomes) => draw_report(f, outcomes, app.freed_total),
    }
}

/// The always-on answer to "what is reaper doing right now, and where?"
fn draw_status(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let (dirs, files) = app.walk;
    let elapsed = app.started.elapsed().as_secs();
    let spin = SPINNER[app.tick % SPINNER.len()];
    let probed = app.probed();
    let total = app.items.len();

    let phase: Line = if !app.walk_done {
        Line::from(vec![
            Span::styled(format!(" {spin} "), Style::new().fg(ACCENT)),
            Span::styled("scanning", Style::new().bold()),
            Span::raw(format!(
                "  {dirs} dirs · {files} files · {total} candidates · {elapsed}s"
            )),
        ])
    } else if probed < total {
        Line::from(vec![
            Span::styled(format!(" {spin} "), Style::new().fg(ACCENT)),
            Span::styled("sizing", Style::new().bold()),
            Span::raw(format!(
                "  {probed}/{total} candidates · {} reclaimable so far",
                human_bytes(app.reapable_bytes())
            )),
        ])
    } else {
        Line::from(vec![
            Span::styled(" ✓ ", Style::new().fg(ACCENT)),
            Span::raw(format!(
                "{dirs} dirs · {files} files · {total} candidates · "
            )),
            Span::styled(
                format!("{} reclaimable", human_bytes(app.reapable_bytes())),
                Style::new().bold().fg(ACCENT),
            ),
        ])
    };

    let facet = app.facet.as_deref().unwrap_or("all");
    let filter_text = if app.filter.is_empty() && !app.filtering {
        Span::styled("/ filter", Style::new().fg(CHROME))
    } else {
        Span::styled(
            format!("/ {}{}", app.filter, if app.filtering { "▌" } else { "" }),
            Style::new().bold(),
        )
    };
    let controls = Line::from(vec![
        Span::raw("   "),
        filter_text,
        Span::styled("   eco ", Style::new().fg(CHROME)),
        Span::raw(facet.to_string()),
        Span::styled("   sort ", Style::new().fg(CHROME)),
        Span::raw(app.sort.label()),
        Span::styled("   ? help", Style::new().fg(CHROME)),
    ]);
    f.render_widget(Paragraph::new(vec![phase, controls]), area);
}

fn draw_list(f: &mut ratatui::Frame, app: &mut App, visible: &[usize], area: Rect) {
    if visible.is_empty() {
        let msg: Vec<Line> = if !app.walk_done {
            vec![Line::from(vec![
                Span::styled(SPINNER[app.tick % SPINNER.len()], Style::new().fg(ACCENT)),
                Span::raw(format!("  walking {} …", app.root)),
            ])]
        } else if app.items.is_empty() {
            vec![
                Line::styled("Nothing to reap here.", Style::new().bold()),
                Line::raw(""),
                Line::styled(
                    format!(
                        "{} has no build artifacts, caches, or stale worktrees.",
                        app.root
                    ),
                    Style::new().fg(CHROME),
                ),
                Line::styled("Try a bigger sweep:  reaper ~", Style::new().fg(CHROME)),
            ]
        } else {
            vec![Line::styled(
                "Nothing matches the filter — press / to edit or Esc to clear.",
                Style::new().fg(CHROME),
            )]
        };
        f.render_widget(
            Paragraph::new(msg)
                .alignment(Alignment::Center)
                .block(Block::new().padding(Padding::top(area.height / 3))),
            area,
        );
        return;
    }

    let max_size = visible
        .iter()
        .filter_map(|&i| app.items[i].size())
        .max()
        .unwrap_or(1)
        .max(1);
    let rows: Vec<TRow> = visible
        .iter()
        .map(|&i| {
            let it = &app.items[i];
            let mark = match (it.reapable(), it.marked) {
                (true, true) => Span::styled("✔", Style::new().fg(ACCENT).bold()),
                (true, false) => Span::styled("·", Style::new().fg(CHROME)),
                _ => Span::raw(" "),
            };
            let size_txt = match it.size() {
                Some(b) => human_bytes(b),
                None => "…".into(),
            };
            let bar = match it.size() {
                Some(b) => size_bar(b, max_size, 8),
                None => String::new(),
            };
            let bar_style = if it.reapable() {
                Style::new().fg(ACCENT)
            } else {
                Style::new().fg(CHROME)
            };
            let idle = it
                .idle()
                .map(|d| format!("{d}d"))
                .unwrap_or_else(|| "…".into());
            let verdict: Line = match &it.disposition {
                Some(Disposition::Reapable) => {
                    Line::from(Span::styled("reapable", Style::new().fg(ACCENT)))
                }
                Some(Disposition::Refused { reasons }) => {
                    let brief: Vec<String> = reasons.iter().take(2).map(reason_short).collect();
                    Line::from(Span::styled(
                        brief.join(" · "),
                        Style::new().fg(Color::Yellow),
                    ))
                }
                None => Line::from(Span::styled(
                    format!("{} probing", SPINNER[(app.tick + i) % SPINNER.len()]),
                    Style::new().fg(CHROME),
                )),
            };
            let dim_row = matches!(it.disposition, Some(Disposition::Refused { .. }));
            let row = TRow::new(vec![
                Line::from(mark),
                Line::raw(size_txt).right_aligned(),
                Line::from(Span::styled(bar, bar_style)),
                Line::raw(it.candidate.ecosystem.0.clone()),
                Line::raw(idle).right_aligned(),
                path_line(it.candidate.path.as_str(), &app.root),
                verdict,
            ]);
            if dim_row {
                row.style(Style::new().add_modifier(Modifier::DIM))
            } else {
                row
            }
        })
        .collect();
    let widths = [
        Constraint::Length(1),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(5),
        Constraint::Fill(3),
        Constraint::Fill(2),
    ];
    f.render_stateful_widget(
        Table::new(rows, widths)
            .header(
                TRow::new(["", "SIZE", "", "ECO", "IDLE", "PATH", "VERDICT"])
                    .style(Style::new().fg(CHROME).bold()),
            )
            .column_spacing(1)
            .row_highlight_style(Style::new().reversed()),
        area,
        &mut app.table,
    );
}

fn draw_footer(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let marked: Vec<&Item> = app.items.iter().filter(|i| i.marked).collect();
    let marked_bytes: u64 = marked.iter().filter_map(|i| i.size()).sum();
    let mut spans = vec![if marked.is_empty() {
        Span::styled(" nothing marked ", Style::new().fg(CHROME))
    } else {
        Span::styled(
            format!(" {} marked in {} ", human_bytes(marked_bytes), marked.len()),
            Style::new().bold().fg(ACCENT),
        )
    }];
    spans.push(Span::styled(
        "· delete is permanent · ",
        Style::new().fg(Color::Red),
    ));
    for (k, v) in [
        ("space", "mark"),
        ("a", "all"),
        ("⏎", "why"),
        ("x", "reap"),
        ("g", "rescan"),
        ("q", "quit"),
    ] {
        spans.push(Span::styled(k, Style::new().bold()));
        spans.push(Span::styled(format!(" {v}  "), Style::new().fg(CHROME)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn popup(f: &mut ratatui::Frame, width: u16, height: u16, title: &str, danger: bool) -> Rect {
    let area = f.area();
    let rect = Rect {
        x: area.width.saturating_sub(width) / 2,
        y: area.height.saturating_sub(height) / 2,
        width: width.min(area.width),
        height: height.min(area.height),
    };
    f.render_widget(Clear, rect);
    f.render_widget(
        Block::bordered()
            .border_type(BorderType::Rounded)
            .title(format!(" {title} "))
            .title_style(if danger {
                Style::new().bold().fg(Color::Red)
            } else {
                Style::new().bold().fg(ACCENT)
            })
            .border_style(Style::new().fg(if danger { Color::Red } else { CHROME })),
        rect,
    );
    rect.inner(Margin {
        horizontal: 2,
        vertical: 1,
    })
}

fn draw_help(f: &mut ratatui::Frame) {
    let inner = popup(f, 58, 15, "keys", false);
    let rows = [
        ("↑↓ j k", "move"),
        (
            "space",
            "mark (reapable rows only — refusals can't be marked)",
        ),
        ("a", "mark / unmark everything reapable in view"),
        ("⏎", "why? — the full verdict for this row"),
        ("x", "reap the marked set (typed-y confirm)"),
        ("/", "filter paths"),
        ("e", "cycle ecosystem"),
        ("s", "sort: size / idle / path"),
        ("g", "rescan"),
        ("q", "quit — scans never mutate anything"),
    ];
    let lines: Vec<Line> = rows
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!("{k:>8}  "), Style::new().bold().fg(ACCENT)),
                Span::raw(*v),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_preview(f: &mut ratatui::Frame, it: &Item) {
    let reasons = match &it.disposition {
        Some(Disposition::Refused { reasons }) => reasons.len(),
        _ => 0,
    };
    let inner = popup(f, 80, (10 + reasons).min(20) as u16, "why", false);
    let field = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("{k:<10}"), Style::new().fg(CHROME)),
            Span::raw(v),
        ])
    };
    let mut lines = vec![
        field("path", it.candidate.path.to_string()),
        field(
            "detector",
            format!("{} ({})", it.candidate.detector.0, it.candidate.ecosystem.0),
        ),
        field(
            "size",
            it.size()
                .map(human_bytes)
                .unwrap_or_else(|| "still sizing…".into()),
        ),
        field(
            "idle",
            it.idle()
                .map(|d| format!("{d} days"))
                .unwrap_or_else(|| "…".into()),
        ),
        Line::raw(""),
    ];
    match &it.disposition {
        Some(Disposition::Reapable) => {
            lines.push(Line::from(Span::styled(
                "reapable — every safety gate affirmatively clean",
                Style::new().fg(ACCENT).bold(),
            )));
            if let SafetyClass::Regenerable {
                regenerate_hint: Some(h),
            } = &it.candidate.safety_class
            {
                lines.push(field("recovery", h.clone()));
            }
        }
        Some(Disposition::Refused { reasons }) => {
            lines.push(Line::from(Span::styled(
                "refused — reaper will not touch this:",
                Style::new().fg(Color::Yellow).bold(),
            )));
            for r in reasons {
                lines.push(Line::raw(format!("  · {}", reason_long(r))));
            }
        }
        None => lines.push(Line::styled("still probing…", Style::new().fg(CHROME))),
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_confirm(f: &mut ratatui::Frame, sealed: &SealedPlan) {
    let n = sealed.steps.len();
    let shown = n.min(8);
    let inner = popup(f, 86, (shown + 7) as u16, "permanent delete", true);
    let total: u64 = sealed.steps.iter().map(|s| s.size_bytes).sum();
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{} ", human_bytes(total)),
                Style::new().bold().fg(Color::Red),
            ),
            Span::raw(format!(
                "across {n} step(s) — no trash, no undelete. Recovery = rebuild."
            )),
        ]),
        Line::raw(""),
    ];
    for b in sealed.steps.iter().take(shown) {
        let step = b.step();
        let verb = match step {
            reaper_core::ReapStep::RemoveWorktree { .. } => "remove worktree",
            reaper_core::ReapStep::DeleteDir { .. } => "delete",
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {verb:<16}"), Style::new().fg(CHROME)),
            Span::raw(format!("{}  ", step.path())),
            Span::styled(human_bytes(b.size_bytes), Style::new().bold()),
        ]));
    }
    if n > shown {
        lines.push(Line::styled(
            format!("  … and {} more", n - shown),
            Style::new().fg(CHROME),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::raw("press "),
        Span::styled("y", Style::new().bold().fg(Color::Red)),
        Span::raw(" to reap · anything else aborts"),
    ]));
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_reaping(f: &mut ratatui::Frame, app: &App, outcomes: &[StepOutcome], total: usize) {
    let inner = popup(f, 86, 8, "reaping", true);
    let done = outcomes.len();
    let freed: u64 = outcomes
        .iter()
        .map(|o| match o {
            StepOutcome::Reaped { freed_bytes, .. } => *freed_bytes,
            _ => 0,
        })
        .sum();
    let [top, gauge_area, last_line] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(2),
    ])
    .areas(inner);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{} ", SPINNER[app.tick % SPINNER.len()]),
                Style::new().fg(ACCENT),
            ),
            Span::raw(format!(
                "step {done}/{total} · {} freed",
                human_bytes(freed)
            )),
        ])),
        top,
    );
    f.render_widget(
        Gauge::default()
            .ratio(if total == 0 {
                0.0
            } else {
                done as f64 / total as f64
            })
            .gauge_style(Style::new().fg(ACCENT).bg(Color::Black))
            .label(""),
        gauge_area,
    );
    if let Some(last) = outcomes.last() {
        let line = match last {
            StepOutcome::Reaped { path, .. } => Line::from(Span::styled(
                format!("✓ {}", shorten(path.as_str(), 76)),
                Style::new().fg(ACCENT),
            )),
            StepOutcome::Refused { path, why } => Line::from(Span::styled(
                format!("⛔ {} — {}", shorten(path.as_str(), 40), why),
                Style::new().fg(Color::Yellow),
            )),
        };
        f.render_widget(Paragraph::new(line), last_line);
    }
}

fn draw_report(f: &mut ratatui::Frame, outcomes: &[StepOutcome], freed_total: u64) {
    let shown = outcomes.len().min(10);
    let inner = popup(f, 86, (shown + 5) as u16, "reaped", false);
    let freed: u64 = outcomes
        .iter()
        .map(|o| match o {
            StepOutcome::Reaped { freed_bytes, .. } => *freed_bytes,
            _ => 0,
        })
        .sum();
    let mut lines = Vec::new();
    for o in outcomes.iter().take(shown) {
        lines.push(match o {
            StepOutcome::Reaped {
                path, freed_bytes, ..
            } => Line::from(vec![
                Span::styled("✓ ", Style::new().fg(ACCENT)),
                Span::raw(shorten(path.as_str(), 60)),
                Span::styled(
                    format!("  {}", human_bytes(*freed_bytes)),
                    Style::new().bold(),
                ),
            ]),
            StepOutcome::Refused { path, why } => Line::from(Span::styled(
                format!("⛔ {} — {}", shorten(path.as_str(), 36), why),
                Style::new().fg(Color::Yellow),
            )),
        });
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled(
            format!("{} freed", human_bytes(freed)),
            Style::new().bold().fg(ACCENT),
        ),
        Span::styled(
            format!(
                " · {} this session · `reaper undo` prints recovery",
                human_bytes(freed_total)
            ),
            Style::new().fg(CHROME),
        ),
    ]));
    f.render_widget(Paragraph::new(lines), inner);
}

// ----------------------------------------------------------------- text ----

/// Dim the parent, brighten the basename — the eye lands where it matters.
fn path_line(path: &str, root: &Utf8PathBuf) -> Line<'static> {
    let rel = path
        .strip_prefix(root.as_str())
        .unwrap_or(path)
        .trim_start_matches('/');
    let shown = shorten(rel, 56);
    match shown.rfind('/') {
        Some(cut) => Line::from(vec![
            Span::styled(shown[..=cut].to_string(), Style::new().fg(CHROME)),
            Span::styled(shown[cut + 1..].to_string(), Style::new().bold()),
        ]),
        None => Line::from(Span::styled(shown, Style::new().bold())),
    }
}

fn size_bar(size: u64, max: u64, width: usize) -> String {
    let filled = ((size as f64 / max as f64) * width as f64).ceil() as usize;
    let filled = filled.clamp(if size > 0 { 1 } else { 0 }, width);
    format!("{}{}", "▮".repeat(filled), "▯".repeat(width - filled))
}

fn reason_short(r: &RefusalReason) -> String {
    match r {
        RefusalReason::Dirty { entries } => format!("dirty({entries})"),
        RefusalReason::UnpushedCommits { count } => format!("unpushed({count})"),
        RefusalReason::Locked { .. } => "locked".into(),
        RefusalReason::Detached { .. } => "detached".into(),
        RefusalReason::LiveProcess { pids } => format!("in use({})", pids.len()),
        RefusalReason::ActiveBuild { .. } => "building".into(),
        RefusalReason::CrossDevice => "other disk".into(),
        RefusalReason::CloudBacked => "cloud".into(),
        RefusalReason::Protected { .. } => "protected".into(),
        RefusalReason::CachesExcluded => "cache (opt-in)".into(),
        RefusalReason::TooRecent {
            idle_days,
            min_idle_days,
        } => {
            format!("fresh {idle_days}d<{min_idle_days}d")
        }
        RefusalReason::TooSmall { .. } => "small".into(),
        RefusalReason::Unknown { what } => format!("unknown: {what}"),
    }
}

fn reason_long(r: &RefusalReason) -> String {
    match r {
        RefusalReason::Dirty { entries } => {
            format!("{entries} uncommitted/untracked change(s) — commit, stash, or clean first")
        }
        RefusalReason::UnpushedCommits { count } => {
            format!("{count} commit(s) no remote holds — push them first")
        }
        RefusalReason::Locked { note } => match note {
            Some(n) => format!("worktree locked: {n}"),
            None => "worktree locked (git worktree lock)".into(),
        },
        RefusalReason::Detached { unreachable_commits } => format!(
            "detached HEAD with {unreachable_commits} commit(s) nothing else holds — they die with the dir"
        ),
        RefusalReason::LiveProcess { pids } => {
            format!("process(es) {pids:?} have their cwd or open files inside")
        }
        RefusalReason::ActiveBuild { .. } => "a build wrote here moments ago".into(),
        RefusalReason::CrossDevice => "on a different mount than the scan root".into(),
        RefusalReason::CloudBacked => {
            "cloud-sync placeholder — deleting would trigger downloads".into()
        }
        RefusalReason::Protected { pattern } => format!("protected by your exclude glob {pattern}"),
        RefusalReason::CachesExcluded => {
            "shared cache — rerun with --include-caches to opt in".into()
        }
        RefusalReason::TooRecent { idle_days, min_idle_days } => format!(
            "only {idle_days}d idle (floor {min_idle_days}d) — fresh things are probably in use"
        ),
        RefusalReason::TooSmall { size_bytes, min_size_bytes } => format!(
            "{} < the {} floor you set",
            human_bytes(*size_bytes),
            human_bytes(*min_size_bytes)
        ),
        RefusalReason::Unknown { what } => {
            format!("could not establish `{what}` — doubt counts as danger")
        }
    }
}

fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let tail: String = s
        .chars()
        .rev()
        .take(max - 1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
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
