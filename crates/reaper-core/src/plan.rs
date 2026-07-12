//! plan() — pure: admitted candidates → an ordered, typed execution plan.
//! Takes `&[Admitted]`, the proof type: a refused candidate cannot reach a
//! plan by construction. No `ReapMode` parameter (ruled at slice 2): the §9
//! plan-digest design requires the plan be IDENTICAL under dry-run and
//! execute — a parameter that cannot change the output is a cost with no buy.

use crate::classify::Admitted;
use crate::model::SafetyClass;
use camino::Utf8PathBuf;
use serde::Serialize;

/// One typed step. The Deleter port (slice 4) executes these; both surfaces
/// render them verbatim in the confirm view (§8.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "step")]
pub enum ReapStep {
    /// Native worktree removal (G7): worktree dir + `.git/worktrees/<name>`.
    RemoveWorktree {
        path: Utf8PathBuf,
        branch: Option<String>,
    },
    /// Tomb-rename then parallel drain (§7).
    DeleteDir {
        path: Utf8PathBuf,
        regenerate_hint: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReapPlan {
    pub steps: Vec<ReapStep>,
}

/// Deterministic: steps are ordered by path, independent of input order —
/// the same selection always digests to the same plan (§9).
pub fn plan(selected: &[Admitted]) -> ReapPlan {
    let mut steps: Vec<ReapStep> = selected
        .iter()
        .map(|a| {
            let facts = a.facts();
            let path = facts.candidate.path.clone();
            match &facts.candidate.safety_class {
                SafetyClass::GitWorktree => ReapStep::RemoveWorktree {
                    path,
                    branch: facts.git.as_ref().and_then(|g| g.head.as_ref()).and_then(
                        |h| match h {
                            crate::model::HeadState::Attached { branch } => Some(branch.clone()),
                            crate::model::HeadState::Detached { .. } => None,
                        },
                    ),
                },
                SafetyClass::Regenerable { regenerate_hint } => ReapStep::DeleteDir {
                    path,
                    regenerate_hint: regenerate_hint.clone(),
                },
                // SEALED set, matched exhaustively in-crate: a new class does
                // not compile until it states its reap primitive here.
                SafetyClass::PackageCache => ReapStep::DeleteDir {
                    path,
                    regenerate_hint: None,
                },
            }
        })
        .collect();
    steps.sort_by(|a, b| step_path(a).cmp(step_path(b)));
    ReapPlan { steps }
}

fn step_path(step: &ReapStep) -> &Utf8PathBuf {
    match step {
        ReapStep::RemoveWorktree { path, .. } | ReapStep::DeleteDir { path, .. } => path,
    }
}

impl ReapStep {
    pub fn path(&self) -> &Utf8PathBuf {
        step_path(self)
    }
}

/// The identity a step is bound to. THREE components, not two: ext4 reuses
/// inode numbers promptly (the drift e2e caught (dev,ino) alone missing a
/// swap on Linux), and a swapped dir necessarily carries a new mtime. A
/// LEGITIMATE top-level mtime change also refuses — fail closed, re-scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Identity {
    pub dev: u64,
    pub ino: u64,
    pub mtime_ns: u64,
}

/// A step bound to the identity of the dir it was planned against: a path
/// swapped after planning fails the identity match and refuses (§7/§9).
/// `None` binding = identity not establishable on this platform; the deleter
/// then re-verifies by other means or refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct BoundStep {
    pub step_json: String, // canonical bytes of the ReapStep (digest input)
    pub identity: Option<Identity>,
    pub size_bytes: u64,
    pub recover: Option<String>,
}

/// The §9 artifact: blast-radius guard and TOCTOU binding in ONE value —
/// `--execute` binds to this digest, and reap verifies O(plan), never O(tree).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct SealedPlan {
    pub digest: String,
    pub steps: Vec<BoundStep>,
}

/// Seal a plan with per-step identity bindings (supplied by the IO shell —
/// this function stays pure). Deterministic: same steps + bindings ⇒ same
/// digest, independent of everything else.
pub fn seal(plan: &ReapPlan, bindings: &[Option<Identity>], sizes: &[u64]) -> SealedPlan {
    use sha2::{Digest, Sha256};
    let steps: Vec<BoundStep> = plan
        .steps
        .iter()
        .zip(bindings.iter().zip(sizes))
        .map(|(step, (identity, size))| BoundStep {
            step_json: serde_json::to_string(step).expect("ReapStep serializes"),
            identity: *identity,
            size_bytes: *size,
            recover: match step {
                ReapStep::DeleteDir {
                    regenerate_hint, ..
                } => regenerate_hint.clone(),
                ReapStep::RemoveWorktree { path, branch } => branch
                    .as_ref()
                    .map(|b| format!("git worktree add {path} {b}")),
            },
        })
        .collect();
    let mut hasher = Sha256::new();
    for s in &steps {
        hasher.update(s.step_json.as_bytes());
        hasher.update(format!("{:?}", s.identity).as_bytes());
    }
    SealedPlan {
        digest: format!("sha256:{:x}", hasher.finalize()),
        steps,
    }
}

impl BoundStep {
    pub fn step(&self) -> ReapStep {
        serde_json::from_str(&self.step_json).expect("sealed step_json round-trips")
    }
}
