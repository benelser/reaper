//! The classifier — pure, total, fail-closed. `Reapable` requires EVERY gate
//! affirmatively clean; ANY load-bearing `None` refuses `Unknown`. Refusals
//! accumulate ALL reasons (§7). `Admitted` is the parse-don't-validate proof:
//! only this module can construct it, so `plan()` cannot receive a refused
//! candidate by construction — "refused is never mutated" is a compiler fact.

use crate::model::{Disposition, Facts, HeadState, LockState, RefusalReason, SafetyClass};
use crate::policy::Policy;

/// Proof that `facts` passed every gate under some policy. No public
/// constructor: `admit()` is the only way in.
#[derive(Debug, Clone)]
pub struct Admitted {
    facts: Facts,
}

impl Admitted {
    pub fn facts(&self) -> &Facts {
        &self.facts
    }
}

/// The single verdict function both surfaces share.
pub fn classify(facts: &Facts, policy: &Policy) -> Disposition {
    match admit(facts, policy) {
        Ok(_) => Disposition::Reapable,
        Err(reasons) => Disposition::Refused { reasons },
    }
}

/// Run the full gate battery; return the proof or every reason it failed.
pub fn admit(facts: &Facts, policy: &Policy) -> Result<Admitted, Vec<RefusalReason>> {
    let mut reasons = Vec::new();
    let class = &facts.candidate.safety_class;

    // The protect list wins over everything — pure data, always refuses (§7).
    if let Some(pattern) = policy.protected_by(&facts.candidate.path) {
        reasons.push(RefusalReason::Protected {
            pattern: pattern.to_string(),
        });
    }

    // Shared caches are opt-in: higher blast radius (§14).
    if matches!(class, SafetyClass::PackageCache) && !policy.include_caches {
        reasons.push(RefusalReason::CachesExcluded);
    }

    match facts.live_pids.as_deref() {
        Some([]) => {}
        Some(pids) => reasons.push(RefusalReason::LiveProcess {
            pids: pids.to_vec(),
        }),
        None => reasons.push(unknown("live_pids")),
    }

    match facts.active_build {
        Some(false) => {}
        Some(true) => reasons.push(RefusalReason::ActiveBuild {
            pids: facts.live_pids.clone().unwrap_or_default(),
        }),
        None => reasons.push(unknown("active_build")),
    }

    match facts.same_device {
        Some(true) => {}
        Some(false) => reasons.push(RefusalReason::CrossDevice),
        None => reasons.push(unknown("same_device")),
    }

    match facts.cloud_backed {
        Some(false) => {}
        Some(true) => reasons.push(RefusalReason::CloudBacked),
        None => reasons.push(unknown("cloud_backed")),
    }

    let min_idle_days = policy.min_idle.floor_days(class);
    match facts.idle_days {
        Some(idle_days) if idle_days >= min_idle_days => {}
        Some(idle_days) => reasons.push(RefusalReason::TooRecent {
            idle_days,
            min_idle_days,
        }),
        None => reasons.push(unknown("idle_days")),
    }

    match facts.size_bytes {
        Some(size_bytes) if size_bytes >= policy.min_size_bytes => {}
        Some(size_bytes) => reasons.push(RefusalReason::TooSmall {
            size_bytes,
            min_size_bytes: policy.min_size_bytes,
        }),
        None => reasons.push(unknown("size_bytes")),
    }

    // Git facts are load-bearing ONLY for worktrees; a target/ dir with no
    // git story is fine.
    if matches!(class, SafetyClass::GitWorktree) {
        match &facts.git {
            None => reasons.push(unknown("git")),
            Some(git) => {
                match git.dirty_entries {
                    Some(0) => {}
                    Some(entries) => reasons.push(RefusalReason::Dirty { entries }),
                    None => reasons.push(unknown("git.dirty_entries")),
                }
                match git.unpushed_commits {
                    Some(0) => {}
                    Some(count) => reasons.push(RefusalReason::UnpushedCommits { count }),
                    None => reasons.push(unknown("git.unpushed_commits")),
                }
                match &git.lock {
                    Some(LockState::Unlocked) => {}
                    Some(LockState::Locked { note }) => {
                        reasons.push(RefusalReason::Locked { note: note.clone() })
                    }
                    None => reasons.push(unknown("git.lock")),
                }
                match &git.head {
                    Some(HeadState::Attached { .. }) => {}
                    Some(HeadState::Detached {
                        unreachable_commits,
                    }) => {
                        // Detached commits die with the worktree (R9 W3):
                        // refuse even at zero — a detached worktree's intent
                        // is unknowable and the branch-survival guarantee is gone.
                        reasons.push(RefusalReason::Detached {
                            unreachable_commits: *unreachable_commits,
                        })
                    }
                    None => reasons.push(unknown("git.head")),
                }
            }
        }
    }

    if reasons.is_empty() {
        Ok(Admitted {
            facts: facts.clone(),
        })
    } else {
        Err(reasons)
    }
}

fn unknown(what: &str) -> RefusalReason {
    RefusalReason::Unknown {
        what: what.to_string(),
    }
}
