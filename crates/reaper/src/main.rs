//! The agent CLI (§9): `scan` (classify + seal a plan, ZERO mutation),
//! `reap --plan <digest>` (dry-run by default; `--execute` is the ONLY
//! mutation path in the whole product), `undo <digest>` (EMIT recovery —
//! reaper never executes commands, G7).

use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, Subcommand, ValueEnum};
use reaper_core::{
    admit, classify, plan, seal, Candidate, Disposition, Policy, RefusalReason, Registry,
    SealedPlan,
};
use reaper_scan::{
    prober, scan, Deleter, InstanceLock, Prober, ScanEvent, StepOutcome, SystemClock,
};
use serde::Serialize;
use std::sync::Mutex;

mod update;

#[derive(Parser)]
#[command(
    name = "reaper",
    version,
    about = "language-agnostic filesystem-bloat reaper"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Bare `reaper [PATH]` opens the TUI on PATH (default: cwd).
    #[arg(default_value = ".")]
    path: Utf8PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Classify reclaimable bloat under PATH — ZERO mutation, typed report.
    /// Reapable candidates are sealed into a plan bound to this exact tree.
    Scan {
        #[arg(default_value = ".")]
        path: Utf8PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
        /// Override ALL per-class idle floors (worktree 7d / build 3d / cache 30d).
        #[arg(long)]
        min_idle_days: Option<u64>,
        /// Minimum candidate size, e.g. 500M or 1G.
        #[arg(long)]
        min_size: Option<String>,
        /// Only these ecosystems (comma-separated, e.g. rust,node).
        #[arg(long, value_delimiter = ',')]
        ecosystem: Vec<String>,
        /// Glob(s) reaper must NEVER reap — joins the protect list.
        #[arg(long)]
        exclude: Vec<String>,
        /// Opt in shared package caches (higher blast radius).
        #[arg(long)]
        include_caches: bool,
    },
    /// Execute (or rehearse) a plan a prior `scan` sealed. DRY-RUN unless
    /// --execute. Refuses if the tree drifted from the plan.
    Reap {
        /// The plan digest a prior scan printed (sha256:… or unique prefix).
        #[arg(long)]
        plan: String,
        /// The ONLY mutation path. PERMANENT delete — there is no trash.
        #[arg(long)]
        execute: bool,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
    /// EMIT recovery for a past reap: the exact regenerate / worktree
    /// re-add commands. Never executes them (G7); never un-deletes.
    Undo {
        /// The reap's plan digest (or unique prefix).
        digest: String,
    },
    /// Dump the active detector ruleset (audit).
    Rules,
    /// Update reaper in place to the latest release (checksum-verified).
    Update {
        /// Only report whether an update exists; install nothing.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Json,
    /// One candidate per line — for huge scans an agent consumes incrementally.
    Ndjson,
}

const SCAN_SCHEMA: &str = "reaper-scan/v1";
const REAP_SCHEMA: &str = "reaper-reap/v1";

fn main() {
    let cli = Cli::parse();
    let Some(cmd) = cli.cmd else {
        #[cfg(feature = "tui")]
        {
            if let Err(e) = reaper_tui::run(cli.path, state_dir()) {
                eprintln!("tui error: {e}");
                std::process::exit(2);
            }
            return;
        }
        #[cfg(not(feature = "tui"))]
        {
            eprintln!(
                "headless build: use `reaper scan` (this binary was built without the tui feature)"
            );
            std::process::exit(2);
        }
    };
    match cmd {
        Cmd::Scan {
            path,
            format,
            min_idle_days,
            min_size,
            ecosystem,
            exclude,
            include_caches,
        } => {
            let min_size_bytes = match min_size.as_deref().map(parse_size) {
                Some(Ok(b)) => b,
                Some(Err(e)) => {
                    eprintln!("--min-size: {e}");
                    std::process::exit(2);
                }
                None => 0,
            };
            let idle = match min_idle_days {
                Some(d) => reaper_core::IdlePolicy {
                    worktree_days: d,
                    regenerable_days: d,
                    cache_days: d,
                },
                None => reaper_core::IdlePolicy::default(),
            };
            let policy = match Policy::new(idle, min_size_bytes, include_caches, &exclude) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("--exclude: {e}");
                    std::process::exit(2);
                }
            };
            run_scan(&path, format, policy, &ecosystem)
        }
        Cmd::Reap {
            plan,
            execute,
            format,
        } => run_reap(&plan, execute, format),
        Cmd::Undo { digest } => run_undo(&digest),
        Cmd::Update { check } => update::run(check),
        Cmd::Rules => match Registry::embedded() {
            Ok(reg) => println!(
                "{}",
                serde_json::to_string_pretty(reg.detectors()).expect("rules serialize")
            ),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        },
    }
}

// ---------------------------------------------------------------- state ----

/// Per-OS state dir (§13): plans + the write-ahead manifest + the lock.
/// REAPER_STATE_DIR overrides (tests + agents).
fn state_dir() -> Utf8PathBuf {
    let base = std::env::var_os("REAPER_STATE_DIR")
        .map(std::path::PathBuf::from)
        .or_else(platform_state_dir)
        .unwrap_or_else(std::env::temp_dir);
    Utf8PathBuf::from_path_buf(base)
        .expect("utf8 state dir")
        .join("reaper")
}

fn platform_state_dir() -> Option<std::path::PathBuf> {
    // Minimal, dependency-free per-platform resolution (§13).
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join("Library/Application Support"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/state"))
            })
    }
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        None
    }
}

// ----------------------------------------------------------------- scan ----

#[derive(Serialize)]
struct ScanReport<'a> {
    schema_version: &'static str,
    root: &'a Utf8Path,
    candidates: Vec<Row>,
    plan_digest: Option<String>,
    totals: Totals,
}

#[derive(Serialize)]
struct Row {
    #[serde(flatten)]
    candidate: Candidate,
    size_bytes: Option<u64>,
    idle_days: Option<u64>,
    disposition: Disposition,
}

#[derive(Serialize)]
struct Totals {
    dirs: u64,
    files: u64,
    candidates: u64,
    reapable_bytes: u64,
}

fn run_scan(root: &Utf8PathBuf, format: Format, policy: Policy, ecosystems: &[String]) {
    // A missing or non-directory root is a loud error, never a serene
    // 0-candidate success (dogfood catch).
    match root.symlink_metadata() {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            eprintln!("{root} is not a directory");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("cannot scan {root}: {e}");
            std::process::exit(2);
        }
    }
    let registry = match Registry::embedded() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let reader = reaper_scan::select_reader();
    let found: Mutex<Vec<Candidate>> = Mutex::new(Vec::new());
    let totals = scan(root, &registry, reader.as_ref(), &|ev| {
        // ScanEvent is non_exhaustive; unrendered events are skipped.
        if let ScanEvent::Discovered(c) = ev {
            found.lock().unwrap().push(c);
        }
    });

    let clock = SystemClock;
    let prober = Prober {
        reader: reader.as_ref(),
        clock: &clock,
        root_dev: prober::device_of(root),
    };
    let live = reaper_scan::select_probe();
    let mut candidates = found.into_inner().unwrap();
    // Selection predicate (§9): --ecosystem narrows what enters the report
    // AND the plan; it is a filter, never a classification change.
    if !ecosystems.is_empty() {
        candidates.retain(|c| ecosystems.iter().any(|e| e == &c.ecosystem.0));
    }
    let all_facts = reaper_scan::gather_facts(
        &candidates,
        &prober,
        live.as_deref(),
        Some(&reaper_scan::GixProbe),
    );

    // Seal the reapable set into the §9 plan artifact and persist it.
    let admitted: Vec<_> = all_facts
        .iter()
        .filter_map(|f| admit(f, &policy).ok())
        .collect();
    let reapable_bytes: u64 = admitted
        .iter()
        .map(|a| a.facts().size_bytes.unwrap_or(0))
        .sum();
    let plan_digest = (!admitted.is_empty())
        .then(|| {
            let p = plan(&admitted);
            let bindings: Vec<Option<reaper_core::Identity>> = p
                .steps
                .iter()
                .map(|s| prober::identity_of(s.path()))
                .collect();
            let sizes: Vec<u64> = p
                .steps
                .iter()
                .map(|s| {
                    admitted
                        .iter()
                        .find(|a| &a.facts().candidate.path == s.path())
                        .and_then(|a| a.facts().size_bytes)
                        .unwrap_or(0)
                })
                .collect();
            let sealed = seal(&p, &bindings, &sizes);
            let plans = state_dir().join("plans");
            let persisted = std::fs::create_dir_all(&plans).and_then(|()| {
                std::fs::write(
                    plans.join(format!("{}.json", sealed.digest.replace(':', "-"))),
                    serde_json::to_string_pretty(&sealed).expect("plan serializes"),
                )
            });
            match persisted {
                Ok(()) => Some(sealed.digest),
                Err(e) => {
                    // Never advertise a digest that doesn't exist on disk.
                    eprintln!("warning: plan not persisted ({e}) — reap unavailable for this scan");
                    None
                }
            }
        })
        .flatten();

    let mut rows: Vec<Row> = all_facts
        .into_iter()
        .map(|facts| {
            let disposition = classify(&facts, &policy);
            Row {
                size_bytes: facts.size_bytes,
                idle_days: facts.idle_days,
                candidate: facts.candidate,
                disposition,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.candidate.path.cmp(&b.candidate.path)); // deterministic

    let report = ScanReport {
        schema_version: SCAN_SCHEMA,
        root,
        candidates: rows,
        plan_digest,
        totals: Totals {
            dirs: totals.dirs,
            files: totals.files,
            candidates: totals.candidates,
            reapable_bytes,
        },
    };

    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("serialize")
            )
        }
        Format::Ndjson => {
            for row in &report.candidates {
                println!("{}", serde_json::to_string(row).expect("serialize"));
            }
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "schema_version": SCAN_SCHEMA,
                    "totals": report.totals,
                    "plan_digest": report.plan_digest,
                }))
                .expect("serialize")
            );
        }
        Format::Table => {
            for row in &report.candidates {
                let verdict = match &row.disposition {
                    Disposition::Reapable => "reapable".to_string(),
                    Disposition::Refused { reasons } => {
                        let brief: Vec<String> = reasons.iter().map(reason_brief).collect();
                        format!("refused: {}", brief.join(" · "))
                    }
                };
                let size = row
                    .size_bytes
                    .map(human_bytes)
                    .unwrap_or_else(|| "?".into());
                let idle = row
                    .idle_days
                    .map(|d| format!("idle {d}d"))
                    .unwrap_or_else(|| "idle ?".into());
                println!(
                    "{:>9} {:<8} {:<9} {:<40} {}",
                    size, row.candidate.ecosystem.0, idle, row.candidate.path, verdict
                );
            }
            println!(
                "{} candidate(s) · {} dirs · {} files scanned · {} reapable",
                report.totals.candidates,
                report.totals.dirs,
                report.totals.files,
                human_bytes(report.totals.reapable_bytes)
            );
            if let Some(d) = &report.plan_digest {
                println!("plan sealed: reaper reap --plan {d} [--execute]   (PERMANENT delete)");
            } else if !report.candidates.is_empty() {
                // The empty state teaches, never shrugs (§8.9): say WHY and
                // hand over the lever.
                let mut tally: std::collections::BTreeMap<String, usize> = Default::default();
                for row in &report.candidates {
                    if let Disposition::Refused { reasons } = &row.disposition {
                        for r in reasons {
                            *tally
                                .entry(reason_brief(r).split('(').next().unwrap_or("?").to_string())
                                .or_default() += 1;
                        }
                    }
                }
                let mut top: Vec<_> = tally.into_iter().collect();
                top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
                let brief: Vec<String> = top
                    .iter()
                    .take(3)
                    .map(|(r, n)| format!("{r}×{n}"))
                    .collect();
                println!(
                    "0 reapable — all {} candidate(s) refused ({}). Fresh builds age out: try --min-idle-days 1, or check the refusals above.",
                    report.candidates.len(),
                    brief.join(" · ")
                );
            }
        }
    }
}

/// "500M"/"1G"/"1024" → bytes.
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M' | 'm') => (&s[..s.len() - 1], 1 << 20),
        Some('G' | 'g') => (&s[..s.len() - 1], 1 << 30),
        Some('T' | 't') => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("unparseable size {s:?}"))
}

// ----------------------------------------------------------------- reap ----

#[derive(Serialize)]
struct ReapReport {
    schema_version: &'static str,
    plan_digest: String,
    executed: bool,
    outcomes: Vec<StepOutcome>,
    freed_bytes: u64,
}

fn load_plan(digest_arg: &str) -> SealedPlan {
    let plans = state_dir().join("plans");
    let mut matches = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&plans) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let digest = name.trim_end_matches(".json").replace("sha256-", "sha256:");
            if digest.starts_with(digest_arg)
                || digest.trim_start_matches("sha256:").starts_with(digest_arg)
            {
                matches.push(e.path());
            }
        }
    }
    match matches.len() {
        1 => serde_json::from_str(&std::fs::read_to_string(&matches[0]).expect("read plan"))
            .expect("plan parses"),
        0 => {
            eprintln!("no sealed plan matches {digest_arg} — run `reaper scan` first");
            std::process::exit(2);
        }
        n => {
            eprintln!("{n} plans match {digest_arg} — give more digits");
            std::process::exit(2);
        }
    }
}

fn run_reap(digest_arg: &str, execute: bool, format: Format) {
    let sealed = load_plan(digest_arg);
    let manifest = state_dir()
        .join("log")
        .join(format!("{}.jsonl", sealed.digest.replace(':', "-")));

    if !execute {
        // Dry-run: print the EXACT primitives (§8.5) and touch nothing.
        for bound in &sealed.steps {
            println!(
                "would reap: {}  ({}, recover: {})",
                bound.step().path(),
                human_bytes(bound.size_bytes),
                bound.recover.as_deref().unwrap_or("—")
            );
        }
        println!(
            "dry-run: {} step(s), {} — add --execute to reap (PERMANENT)",
            sealed.steps.len(),
            human_bytes(sealed.steps.iter().map(|s| s.size_bytes).sum())
        );
        return; // exit 0: a dry-run is always clean (§9)
    }

    let lock = match InstanceLock::acquire(&state_dir().join("execute.lock")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    // Finish any tomb a crashed/interrupted run left behind — across ALL
    // prior plans, not just this digest (§7 crash-resumable).
    for t in Deleter::drain_pending_all(&state_dir().join("log")) {
        eprintln!("resumed and drained leftover tomb {t}");
    }

    let live = reaper_scan::select_probe();
    let mut deleter = match Deleter::new(&manifest, live.as_deref()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "cannot open the write-ahead manifest ({manifest}): {e} — refusing to execute"
            );
            std::process::exit(2);
        }
    };
    let outcomes = deleter.execute(&sealed);
    let freed: u64 = outcomes
        .iter()
        .map(|o| match o {
            StepOutcome::Reaped { freed_bytes, .. } => *freed_bytes,
            StepOutcome::Refused { .. } => 0,
        })
        .sum();
    let any_failed = outcomes
        .iter()
        .any(|o| matches!(o, StepOutcome::Refused { .. }));

    match format {
        Format::Json | Format::Ndjson => println!(
            "{}",
            serde_json::to_string_pretty(&ReapReport {
                schema_version: REAP_SCHEMA,
                plan_digest: sealed.digest.clone(),
                executed: true,
                outcomes,
                freed_bytes: freed,
            })
            .expect("serialize")
        ),
        Format::Table => {
            for o in &outcomes {
                match o {
                    StepOutcome::Reaped {
                        path, freed_bytes, ..
                    } => {
                        println!("✓ reaped {path} ({} freed)", human_bytes(*freed_bytes))
                    }
                    StepOutcome::Refused { path, why } => {
                        println!("⛔ left in place {path}: {why}")
                    }
                }
            }
            println!(
                "freed {} · recovery: reaper undo {}",
                human_bytes(freed),
                sealed.digest
            );
        }
    }
    // std::process::exit skips destructors — release the lock EXPLICITLY
    // before exiting, or a refused step strands it (dogfood catch).
    drop(lock);
    // Exit codes (§9): non-zero ONLY when an --execute step failed.
    if any_failed {
        std::process::exit(1);
    }
}

// ----------------------------------------------------------------- undo ----

fn run_undo(digest_arg: &str) {
    let log_dir = state_dir().join("log");
    let Ok(rd) = std::fs::read_dir(&log_dir) else {
        eprintln!("no reap log yet");
        std::process::exit(2);
    };
    let mut printed = false;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let digest = name
            .trim_end_matches(".jsonl")
            .replace("sha256-", "sha256:");
        if !(digest.starts_with(digest_arg)
            || digest.trim_start_matches("sha256:").starts_with(digest_arg))
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(e.path()) else {
            continue;
        };
        println!("# recovery for {digest} — reaper EMITS these; run what you need (G7):");
        for line in content.lines() {
            if let Ok(reaper_scan::ManifestEvent::Tombed { path, recover, .. }) =
                serde_json::from_str(line)
            {
                match recover {
                    Some(cmd) => println!("{cmd}   # restores {path}"),
                    None => println!("# {path}: no regenerate hint recorded"),
                }
                printed = true;
            }
        }
    }
    if !printed {
        eprintln!("nothing recoverable recorded for {digest_arg}");
        std::process::exit(2);
    }
}

// ------------------------------------------------------------- rendering ---

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

/// One-line rendering per refusal. Deliberately EXHAUSTIVE (§10 fitness):
/// a new `RefusalReason` variant fails compilation here until it renders.
fn reason_brief(reason: &RefusalReason) -> String {
    match reason {
        RefusalReason::Dirty { entries } => format!("dirty({entries})"),
        RefusalReason::UnpushedCommits { count } => format!("unpushed({count})"),
        RefusalReason::Locked { note } => match note {
            Some(n) => format!("locked({n})"),
            None => "locked".into(),
        },
        RefusalReason::Detached {
            unreachable_commits,
        } => {
            format!("detached({unreachable_commits} unreachable)")
        }
        RefusalReason::LiveProcess { pids } => format!("live-process({pids:?})"),
        RefusalReason::ActiveBuild { .. } => "active-build".into(),
        RefusalReason::CrossDevice => "cross-device".into(),
        RefusalReason::CloudBacked => "cloud-backed".into(),
        RefusalReason::Protected { pattern } => format!("protected({pattern})"),
        RefusalReason::CachesExcluded => "caches-excluded".into(),
        RefusalReason::TooRecent {
            idle_days,
            min_idle_days,
        } => {
            format!("too-recent({idle_days}d < {min_idle_days}d)")
        }
        RefusalReason::TooSmall {
            size_bytes,
            min_size_bytes,
        } => {
            format!("too-small({size_bytes} < {min_size_bytes})")
        }
        RefusalReason::Unknown { what } => format!("unknown({what})"),
    }
}
