//! The fact-gathering pipeline for one candidate: eager subtree sizing
//! (§6.3 — reclaim roots are sized in parallel while the walk continues),
//! the depth≤2 freshness sample (R12: the load-bearing idle signal), device
//! identity, and cloud-placeholder detection. Every un-establishable fact
//! stays `None` — the classifier refuses it; the prober never guesses.
//!
//! live_pids arrives with the process sweep (slice 4): `None` until then.

use crate::dirread::{DirReader, Entry, FileKind};
use camino::{Utf8Path, Utf8PathBuf};
use reaper_core::{Candidate, Facts};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Injected time — no `SystemTime::now()` in anything a test touches (§11.2).
pub trait Clock: Sync {
    fn now(&self) -> SystemTime;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// How fresh the newest depth≤2 sample mtime may be before the candidate is
/// treated as an ACTIVE build (§14 open question — tune against real builds).
const ACTIVE_BUILD_WINDOW: Duration = Duration::from_secs(120);
/// The freshness sample depth (R12: 3 movers visible in ~12 stats at ≤2).
const SAMPLE_DEPTH: u32 = 2;

pub struct Prober<'a> {
    pub reader: &'a dyn DirReader,
    pub clock: &'a dyn Clock,
    /// The scan root's device id — `None` when the platform can't say, which
    /// fails closed via `same_device: None`.
    pub root_dev: Option<u64>,
}

impl Prober<'_> {
    /// Gather what is establishable for `candidate`. Pure over its inputs
    /// except for the filesystem it reads; never mutates anything.
    pub fn probe(&self, candidate: &Candidate) -> Facts {
        let mut facts = Facts::unprobed(candidate.clone());
        let path = &candidate.path;

        facts.same_device = match (self.root_dev, device_of(path)) {
            (Some(root), Some(dev)) => Some(root == dev),
            _ => None,
        };

        let sum = self.sum_subtree(path);
        facts.size_bytes = Some(sum.bytes);
        facts.cloud_backed = if sum.cloud_established {
            Some(sum.cloud_any)
        } else {
            None
        };

        if let Some(newest) = sum.newest_sampled_mtime {
            let age = self
                .clock
                .now()
                .duration_since(newest)
                .unwrap_or(Duration::ZERO);
            facts.idle_days = Some(age.as_secs() / 86_400);
            facts.active_build = Some(age < ACTIVE_BUILD_WINDOW);
        }

        facts
    }

    /// Parallel subtree sum: logical bytes, any-cloud-flag, and the newest
    /// mtime within SAMPLE_DEPTH. Symlinks never followed; unreadable
    /// subtrees leave their bytes uncounted (an undercount is safe — it can
    /// only make a candidate LESS attractive, and size is not a safety gate).
    fn sum_subtree(&self, root: &Utf8Path) -> SubtreeSum {
        let acc = Acc {
            bytes: AtomicU64::new(0),
            cloud_any: AtomicBool::new(false),
            cloud_missing: AtomicBool::new(false),
            newest_nanos: AtomicU64::new(0),
        };
        rayon::scope(|s| self.visit(root.to_owned(), 0, s, &acc));
        SubtreeSum {
            bytes: acc.bytes.load(Ordering::Relaxed),
            cloud_any: acc.cloud_any.load(Ordering::Relaxed),
            cloud_established: !acc.cloud_missing.load(Ordering::Relaxed),
            newest_sampled_mtime: match acc.newest_nanos.load(Ordering::Relaxed) {
                0 => None,
                n => Some(SystemTime::UNIX_EPOCH + Duration::from_nanos(n)),
            },
        }
    }

    fn visit<'s>(&'s self, dir: Utf8PathBuf, depth: u32, s: &rayon::Scope<'s>, acc: &'s Acc) {
        let Ok(entries) = self.reader.read_dir(&dir) else {
            return;
        };
        for e in entries {
            let full = || dir.join(&e.name);
            match e.kind {
                FileKind::Dir => {
                    if depth < SAMPLE_DEPTH {
                        acc.observe_mtime(&e, &full());
                    }
                    let child = full();
                    let d = depth + 1;
                    s.spawn(move |s| self.visit(child, d, s, acc));
                }
                FileKind::Other => {
                    // DT_UNKNOWN (real on XFS ftype=0 mounts): one fill
                    // stat classifies — a dir descends, a file counts,
                    // a symlink is skipped.
                    let p = full();
                    match p.symlink_metadata() {
                        Ok(m) if m.is_dir() => {
                            let d = depth + 1;
                            s.spawn(move |s| self.visit(p, d, s, acc));
                        }
                        Ok(m) if m.is_file() => {
                            acc.bytes.fetch_add(m.len(), Ordering::Relaxed);
                            if depth < SAMPLE_DEPTH {
                                acc.observe_mtime(&e, &p);
                            }
                        }
                        _ => {}
                    }
                }
                FileKind::File => {
                    let len = match e.len {
                        Some(len) => len,
                        None => fill_len(&full()).unwrap_or(0),
                    };
                    acc.bytes.fetch_add(len, Ordering::Relaxed);
                    match e.cloud {
                        Some(true) => acc.cloud_any.store(true, Ordering::Relaxed),
                        Some(false) => {}
                        None => acc.cloud_missing.store(true, Ordering::Relaxed),
                    }
                    if depth < SAMPLE_DEPTH {
                        acc.observe_mtime(&e, &full());
                    }
                }
                FileKind::Symlink => {} // counted nowhere, followed never
            }
        }
    }
}

struct SubtreeSum {
    bytes: u64,
    cloud_any: bool,
    cloud_established: bool,
    newest_sampled_mtime: Option<SystemTime>,
}

struct Acc {
    bytes: AtomicU64,
    cloud_any: AtomicBool,
    cloud_missing: AtomicBool,
    /// Newest sampled mtime as nanos-since-epoch (0 = none seen).
    newest_nanos: AtomicU64,
}

impl Acc {
    fn observe_mtime(&self, e: &Entry, full: &Utf8Path) {
        let mtime = e.mtime.or_else(|| fill_mtime(full));
        if let Some(t) = mtime {
            if let Ok(d) = t.duration_since(SystemTime::UNIX_EPOCH) {
                self.newest_nanos
                    .fetch_max(d.as_nanos() as u64, Ordering::Relaxed);
            }
        }
    }
}

/// The fill pass, one field at a time — issued only where `Caps` said the
/// bulk read couldn't supply it (§6.1).
fn fill_len(path: &Utf8Path) -> Option<u64> {
    path.symlink_metadata().ok().map(|m| m.len())
}

fn fill_mtime(path: &Utf8Path) -> Option<SystemTime> {
    path.symlink_metadata().ok().and_then(|m| m.modified().ok())
}

/// The full fact pipeline for a scan's candidates: per-candidate probes,
/// git facts for worktree candidates (O(worktrees)), then ONE live-process
/// sweep across all of them (O(procs), §7).
pub fn gather_facts(
    candidates: &[Candidate],
    prober: &Prober<'_>,
    live: Option<&dyn crate::sweep::LiveProbe>,
    git: Option<&dyn reaper_core::GitProbe>,
) -> Vec<Facts> {
    let mut facts: Vec<Facts> = candidates.iter().map(|c| prober.probe(c)).collect();
    if let Some(git) = git {
        for f in facts.iter_mut() {
            if matches!(
                f.candidate.safety_class,
                reaper_core::SafetyClass::GitWorktree
            ) {
                f.git = git.facts(&f.candidate.path);
            }
        }
    }
    if let Some(probe) = live {
        let dirs: Vec<Utf8PathBuf> = candidates.iter().map(|c| c.path.clone()).collect();
        for (f, pids) in facts.iter_mut().zip(probe.live_pids(&dirs)) {
            f.live_pids = pids;
        }
    }
    facts
}

/// Full identity of a path — the plan binding (§7/§9). Three components:
/// ext4 reuses inode numbers, so mtime completes the proof of sameness.
#[cfg(unix)]
pub fn identity_of(path: &Utf8Path) -> Option<reaper_core::Identity> {
    use std::os::unix::fs::MetadataExt;
    let m = path.symlink_metadata().ok()?;
    Some(reaper_core::Identity {
        dev: m.dev(),
        ino: m.ino(),
        mtime_ns: (m.mtime() as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(m.mtime_nsec() as u64),
    })
}

/// Windows: real identity via GetFileInformationByHandle (volume serial +
/// file index + last-write) — the placeholder (0,0) let the drift e2e reap
/// a swapped tree, which is exactly the criterion-1 hole this closes.
#[cfg(windows)]
pub fn identity_of(path: &Utf8Path) -> Option<reaper_core::Identity> {
    crate::dirread::windows::file_identity(path)
}

/// Device identity of a path, for the stay-on-device gate (§13).
#[cfg(unix)]
pub fn device_of(path: &Utf8Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    path.symlink_metadata().ok().map(|m| m.dev())
}

/// Windows: volume serial via handle metadata (stable Rust lacks it on
/// `Metadata`); v1 approximates by drive prefix — same drive letter ⇒ same
/// volume for the overwhelming case, and mount-point subtleties refuse via
/// `None` (fail closed) rather than guessing.
#[cfg(windows)]
pub fn device_of(path: &Utf8Path) -> Option<u64> {
    let s = path.as_str().as_bytes();
    if s.len() >= 2 && s[1] == b':' {
        Some(s[0].to_ascii_uppercase() as u64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dirread::StdDirReader;
    use camino::Utf8PathBuf;
    use reaper_core::{Candidate, DetectorId, EcosystemId, SafetyClass};

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    #[test]
    fn probe_establishes_size_idle_and_device() {
        let td = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(td.path().to_path_buf()).unwrap();
        let target = root.join("target");
        std::fs::create_dir_all(target.join("debug/deps")).unwrap();
        std::fs::write(target.join("debug/a.o"), vec![0u8; 1000]).unwrap();
        std::fs::write(target.join("debug/deps/b.o"), vec![0u8; 2345]).unwrap();

        let candidate = Candidate {
            path: target.clone(),
            ecosystem: EcosystemId("rust".into()),
            detector: DetectorId("rust-target".into()),
            safety_class: SafetyClass::Regenerable {
                regenerate_hint: None,
            },
        };
        // "Now" = 10 days after the files were written.
        let clock = FixedClock(SystemTime::now() + std::time::Duration::from_secs(10 * 86_400));
        let prober = Prober {
            reader: &StdDirReader,
            clock: &clock,
            root_dev: device_of(&root),
        };
        let facts = prober.probe(&candidate);

        assert_eq!(facts.size_bytes, Some(3345));
        assert_eq!(facts.idle_days, Some(10));
        assert_eq!(facts.active_build, Some(false));
        assert_eq!(facts.same_device, Some(true));
        // live_pids stays None until the slice-4 sweep — and the classifier
        // keeps refusing on exactly that.
        assert_eq!(facts.live_pids, None);
    }

    #[test]
    fn fresh_writes_flag_active_build() {
        let td = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(td.path().to_path_buf()).unwrap();
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("hot.o"), b"x").unwrap();

        let candidate = Candidate {
            path: target,
            ecosystem: EcosystemId("rust".into()),
            detector: DetectorId("rust-target".into()),
            safety_class: SafetyClass::Regenerable {
                regenerate_hint: None,
            },
        };
        let clock = FixedClock(SystemTime::now());
        let prober = Prober {
            reader: &StdDirReader,
            clock: &clock,
            root_dev: device_of(&root),
        };
        let facts = prober.probe(&candidate);
        assert_eq!(facts.active_build, Some(true));
        assert_eq!(facts.idle_days, Some(0));
    }
}
