//! Ports the pure core DEFINES and the IO shell implements (§3/§4). The
//! core never sees an implementation — tests inject fakes; production
//! injects the native readers.

use crate::model::GitFacts;
use camino::Utf8Path;

/// Establishes git facts for a linked-worktree candidate — natively (G7:
/// the shipped impl reads `.git` state in-process; real git exists only as
/// the tests' differential oracle). `None` = could not establish; the
/// classifier refuses `Unknown(git)`.
pub trait GitProbe: Sync {
    fn facts(&self, worktree: &Utf8Path) -> Option<GitFacts>;
}
