//! Domain vocabulary. Illegal states are unrepresentable; verdicts are
//! values, never errors; `None` always means "the probe could not establish
//! this fact" and the classifier fails closed on it.

use camino::Utf8PathBuf;
use serde::Serialize;

/// A DATA label for an ecosystem ("rust", "node", …) — never branch logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct EcosystemId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct DetectorId(pub String);

/// How a candidate's safety is established. SEALED — a variant exists only
/// where COMPUTED facts are genuinely needed; everything else is ruleset data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SafetyClass {
    /// Regenerable build output (target/, node_modules/, .venv/, …).
    Regenerable { regenerate_hint: Option<String> },
    /// A git linked worktree — gated on dirty/unpushed/locked/detached facts.
    GitWorktree,
    /// A shared package-manager cache — higher blast radius, off by default.
    PackageCache,
}

/// One matched reclaim candidate — a directory a detector claimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub path: Utf8PathBuf,
    pub ecosystem: EcosystemId,
    pub detector: DetectorId,
    pub safety_class: SafetyClass,
}

/// Worktree lock state, as read natively from `.git/worktrees/<n>/locked`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    Unlocked,
    Locked { note: Option<String> },
}

/// Where HEAD points. Detached carries the count of commits reachable from
/// HEAD but from no ref — those die with the worktree (R9 finding W3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeadState {
    Attached { branch: String },
    Detached { unreachable_commits: u64 },
}

/// Git facts for a worktree candidate, all natively read (G7).
/// `unpushed_commits` semantics (ruled at slice 2, backed by R9/R11 data):
/// when remotes exist, commits reachable from HEAD but from no remote ref;
/// when NO remote exists, 0 for an attached branch — worktree removal never
/// touches refs, so the branch preserves every commit. Detached risk is
/// carried by `head`, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitFacts {
    pub dirty_entries: Option<usize>,
    pub unpushed_commits: Option<u64>,
    pub lock: Option<LockState>,
    pub head: Option<HeadState>,
}

/// The gathered FACTS for one candidate — the classifier's ENTIRE input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub candidate: Candidate,
    pub size_bytes: Option<u64>,
    pub idle_days: Option<u64>,
    /// Processes with cwd OR an open fd inside the candidate (widened sweep, §7).
    pub live_pids: Option<Vec<u32>>,
    /// Freshness probes / shallow sample say a build is writing (§7, R12).
    pub active_build: Option<bool>,
    /// false ⇒ crossed a mount (§13): refuse.
    pub same_device: Option<bool>,
    /// Dataless/offline placeholder present (§13): refuse, never materialize.
    pub cloud_backed: Option<bool>,
    /// Load-bearing ONLY for `SafetyClass::GitWorktree`.
    pub git: Option<GitFacts>,
}

impl Facts {
    /// A candidate with nothing established yet — the fail-closed starting
    /// point every probe pipeline begins from (and the skeleton bin emits).
    pub fn unprobed(candidate: Candidate) -> Self {
        Self {
            candidate,
            size_bytes: None,
            idle_days: None,
            live_pids: None,
            active_build: None,
            same_device: None,
            cloud_backed: None,
            git: None,
        }
    }
}

/// The verdict — a domain VALUE, never an error. Refused carries ALL reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum Disposition {
    Reapable,
    Refused { reasons: Vec<RefusalReason> },
}

/// Deliberately NOT `#[non_exhaustive]`: the §10 fitness demands that adding
/// a refusal variant is a compile error until every renderer handles it.
/// (Workspace-internal enum; semver cost accepted and priced.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "code")]
pub enum RefusalReason {
    Dirty {
        entries: usize,
    },
    UnpushedCommits {
        count: u64,
    },
    Locked {
        note: Option<String>,
    },
    Detached {
        unreachable_commits: u64,
    },
    LiveProcess {
        pids: Vec<u32>,
    },
    ActiveBuild {
        pids: Vec<u32>,
    },
    CrossDevice,
    CloudBacked,
    Protected {
        pattern: String,
    },
    CachesExcluded,
    TooRecent {
        idle_days: u64,
        min_idle_days: u64,
    },
    TooSmall {
        size_bytes: u64,
        min_size_bytes: u64,
    },
    /// FAIL-CLOSED catch-all: the named fact could not be established.
    Unknown {
        what: String,
    },
}
