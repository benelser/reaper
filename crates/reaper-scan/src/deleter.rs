//! The deleter (§7): permanent, engineered for safety THEN speed.
//! Per step: (dev,ino) re-bind → live-process re-sweep → write-ahead
//! manifest (fsync BEFORE any mutation) → tomb-rename (O(1); on Windows the
//! rename doubles as the authoritative lock probe — R7) → drain the tomb
//! with std::fs::remove_dir_all (the post-CVE-2022-21658, fd-relative,
//! symlink-race-safe primitive). Refusals leave the tree IN PLACE.

use crate::sweep::LiveProbe;
use camino::{Utf8Path, Utf8PathBuf};
use reaper_core::{ReapStep, SealedPlan};
use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum StepOutcome {
    Reaped {
        path: Utf8PathBuf,
        freed_bytes: u64,
        recover: Option<String>,
    },
    /// Left in place — the reason is honest and typed.
    Refused { path: Utf8PathBuf, why: String },
}

/// One write-ahead manifest line (JSONL). `Tombed` is fsync'd BEFORE the
/// rename; `Drained` after the drain — a crash between them leaves a
/// resumable record (§7 crash-resumable tombs).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event")]
pub enum ManifestEvent {
    Planned {
        digest: String,
    },
    Tombed {
        path: Utf8PathBuf,
        tomb: Utf8PathBuf,
        recover: Option<String>,
        size_bytes: u64,
    },
    Drained {
        tomb: Utf8PathBuf,
        freed_bytes: u64,
    },
    Refused {
        path: Utf8PathBuf,
        why: String,
    },
}

pub struct Deleter<'a> {
    manifest: std::fs::File,
    pub live: Option<&'a dyn LiveProbe>,
}

impl<'a> Deleter<'a> {
    pub fn new(manifest_path: &Utf8Path, live: Option<&'a dyn LiveProbe>) -> std::io::Result<Self> {
        if let Some(parent) = manifest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let manifest = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(manifest_path)?;
        Ok(Self { manifest, live })
    }

    /// Append + fsync: the record exists before the mutation does.
    fn log(&mut self, ev: &ManifestEvent) -> std::io::Result<()> {
        let mut line = serde_json::to_string(ev).expect("manifest event serializes");
        line.push('\n');
        self.manifest.write_all(line.as_bytes())?;
        self.manifest.sync_data()
    }

    /// Execute a sealed plan. Every step re-verifies its world before
    /// touching it; any doubt leaves the step's tree in place.
    pub fn execute(&mut self, plan: &SealedPlan) -> Vec<StepOutcome> {
        let mut outcomes = Vec::new();
        self.execute_with(plan, &mut |o| outcomes.push(o.clone()));
        outcomes
    }

    /// Streaming variant: each step's outcome is delivered the moment it
    /// lands, so a UI can show reap progress live.
    pub fn execute_with(&mut self, plan: &SealedPlan, on: &mut dyn FnMut(&StepOutcome)) {
        let _ = self.log(&ManifestEvent::Planned {
            digest: plan.digest.clone(),
        });
        for (i, bound) in plan.steps.iter().enumerate() {
            let step = bound.step();
            let path = step.path().clone();

            // TOCTOU re-bind: the dir must still be the EXACT dir we planned
            // (dev+ino+mtime — inode reuse alone cannot fake all three).
            if let Some(planned) = bound.identity {
                match crate::prober::identity_of(&path) {
                    Some(now) if now == planned => {}
                    Some(_) => {
                        on(&self.refuse(
                            path,
                            "identity drifted since planning (dev/ino/mtime mismatch) — re-scan",
                        ));
                        continue;
                    }
                    None => {
                        on(&self.refuse(path, "gone or unreadable at execution time"));
                        continue;
                    }
                }
            }

            // Live re-sweep over THIS step (O(selected), §7 phase 2).
            if let Some(live) = self.live {
                match live.live_pids(std::slice::from_ref(&path)).remove(0) {
                    Some(pids) if pids.is_empty() => {}
                    Some(pids) => {
                        on(&self.refuse(path, &format!("live process(es) {pids:?}")));
                        continue;
                    }
                    None => {
                        on(&self.refuse(path, "live-process fact unestablishable at execution"));
                        continue;
                    }
                }
            }

            // Worktree admin dir located BEFORE the tomb rename hides `.git`.
            let admin = match &step {
                ReapStep::RemoveWorktree { .. } => crate::gitprobe::admin_dir_of(&path),
                ReapStep::DeleteDir { .. } => None,
            };

            let tomb = match path.parent() {
                Some(parent) => parent.join(format!(".reaper-tomb-{}-{i}", std::process::id())),
                None => {
                    on(&self.refuse(path, "refusing to reap a filesystem root"));
                    continue;
                }
            };
            // WRITE-AHEAD is load-bearing: if the record cannot be made
            // durable, the mutation MUST NOT happen (no greenwashed step).
            if let Err(e) = self.log(&ManifestEvent::Tombed {
                path: path.clone(),
                tomb: tomb.clone(),
                recover: bound.recover.clone(),
                size_bytes: bound.size_bytes,
            }) {
                on(&self.refuse(path, &format!("write-ahead manifest unwritable: {e}")));
                continue;
            }
            if let Err(e) = std::fs::rename(&path, &tomb) {
                // R7: Windows os 5/32 = open handles — the rename IS the
                // authoritative lock probe; the tree is untouched.
                let why = match e.raw_os_error() {
                    Some(5) | Some(32) => {
                        "live process holds files (rename lock probe)".to_string()
                    }
                    _ => format!("tomb rename failed: {e}"),
                };
                on(&self.refuse(path, &why));
                continue;
            }

            // The path is gone (perceived O(1) reclaim). Drain the tomb —
            // with retries: a writer that raced the sweep (started in the
            // sweep→rename window; its handles moved WITH the tomb) makes
            // remove_dir_all return ENOTEMPTY, and it converges once the
            // writer notices its world vanished (dogfood catch, step 142).
            match drain_with_retries(&tomb) {
                Ok(()) => {
                    let _ = self.log(&ManifestEvent::Drained {
                        tomb: tomb.clone(),
                        freed_bytes: bound.size_bytes,
                    });
                    // A worktree also sheds its admin dir; the branch survives.
                    // A failure here is REPORTED (git would still list the
                    // worktree as prunable), not silently dropped.
                    if let Some(admin) = admin {
                        if let Err(e) = std::fs::remove_dir_all(&admin) {
                            eprintln!("note: {path}: worktree admin dir not removed ({e}); `git worktree prune` will finish it");
                        }
                    }
                    on(&StepOutcome::Reaped {
                        path,
                        freed_bytes: bound.size_bytes,
                        recover: bound.recover.clone(),
                    });
                }
                Err(e) => {
                    // Tomb persists on disk AND in the manifest — resumable.
                    on(&self.refuse(tomb, &format!("drain interrupted: {e} (resumes next run)")));
                }
            }
        }
    }

    fn refuse(&mut self, path: Utf8PathBuf, why: &str) -> StepOutcome {
        let _ = self.log(&ManifestEvent::Refused {
            path: path.clone(),
            why: why.to_string(),
        });
        StepOutcome::Refused {
            path,
            why: why.to_string(),
        }
    }

    /// Crash/interruption recovery (§7): any `Tombed` without a matching
    /// `Drained` is finished now, ACROSS ALL manifests — a tomb from any
    /// prior run must never linger just because its digest isn't re-run
    /// (dogfood catch). Completed drains are recorded back into their
    /// manifest so recovery is idempotent.
    pub fn drain_pending_all(log_dir: &Utf8Path) -> Vec<Utf8PathBuf> {
        let Ok(rd) = std::fs::read_dir(log_dir) else {
            return Vec::new();
        };
        let mut drained = Vec::new();
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let Some(p) = camino::Utf8Path::from_path(&path) else {
                continue;
            };
            drained.extend(Self::drain_pending(p));
        }
        drained
    }

    /// Single-manifest recovery; prefer `drain_pending_all`.
    pub fn drain_pending(manifest_path: &Utf8Path) -> Vec<Utf8PathBuf> {
        let Ok(content) = std::fs::read_to_string(manifest_path) else {
            return Vec::new();
        };
        let mut pending: Vec<(Utf8PathBuf, u64)> = Vec::new();
        for line in content.lines() {
            match serde_json::from_str::<ManifestEvent>(line) {
                Ok(ManifestEvent::Tombed {
                    tomb, size_bytes, ..
                }) => pending.push((tomb, size_bytes)),
                Ok(ManifestEvent::Drained { tomb, .. }) => pending.retain(|(t, _)| t != &tomb),
                _ => {}
            }
        }
        let mut drained = Vec::new();
        for (tomb, size_bytes) in pending {
            if tomb.symlink_metadata().is_ok() && drain_with_retries(&tomb).is_ok() {
                // Close the ledger so recovery is idempotent.
                if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(manifest_path) {
                    let ev = ManifestEvent::Drained {
                        tomb: tomb.clone(),
                        freed_bytes: size_bytes,
                    };
                    let mut line = serde_json::to_string(&ev).expect("event serializes");
                    line.push('\n');
                    let _ = f.write_all(line.as_bytes());
                    let _ = f.sync_data();
                }
                drained.push(tomb);
            }
        }
        drained
    }
}

/// remove_dir_all with convergence retries for racing writers. The rename
/// already cut off every path-based open; only pre-existing handles can
/// still write, and those wind down.
fn drain_with_retries(tomb: &Utf8Path) -> std::io::Result<()> {
    let mut last = None;
    for attempt in 0..4 {
        match std::fs::remove_dir_all(tomb) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
                if attempt < 3 {
                    std::thread::sleep(std::time::Duration::from_millis(250 * (attempt + 1)));
                }
            }
        }
    }
    Err(last.unwrap())
}

/// The single-instance lock (§7): exclusive-create with the owner pid.
/// Boring and portable; price: a SIGKILL'd reaper leaves a stale lock whose
/// removal is manual (the error message says exactly what to do).
pub struct InstanceLock {
    path: Utf8PathBuf,
}

impl InstanceLock {
    pub fn acquire(path: &Utf8Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", std::process::id());
                Ok(Self { path: path.to_owned() })
            }
            Err(_) => Err(format!(
                "another reaper --execute appears active (lock: {path}). If it crashed, remove the lock file and retry."
            )),
        }
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
