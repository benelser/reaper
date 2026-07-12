//! Policy — the user's dials, parsed (not validated) at construction so the
//! classifier never sees an invalid glob.

use crate::model::SafetyClass;
use globset::{Glob, GlobSet, GlobSetBuilder};

/// Per-safety-class idle floors (§7): a worktree deserves a long fuse; a
/// build dir is one rebuild away; a shared cache is colder still.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdlePolicy {
    pub worktree_days: u64,
    pub regenerable_days: u64,
    pub cache_days: u64,
}

impl Default for IdlePolicy {
    fn default() -> Self {
        Self {
            worktree_days: 7,
            regenerable_days: 3,
            cache_days: 30,
        }
    }
}

impl IdlePolicy {
    pub fn floor_days(&self, class: &SafetyClass) -> u64 {
        // SEALED set, matched exhaustively in-crate: a new class does not
        // compile until it picks its idle floor here.
        match class {
            SafetyClass::Regenerable { .. } => self.regenerable_days,
            SafetyClass::GitWorktree => self.worktree_days,
            SafetyClass::PackageCache => self.cache_days,
        }
    }
}

#[derive(Debug)]
pub struct Policy {
    pub min_idle: IdlePolicy,
    pub min_size_bytes: u64,
    pub include_caches: bool,
    protect_patterns: Vec<String>,
    protect: GlobSet,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new(IdlePolicy::default(), 0, false, &[]).expect("empty protect list always parses")
    }
}

impl Policy {
    /// Parse, don't validate: a bad glob is a construction error, never a
    /// silently-skipped protection.
    pub fn new(
        min_idle: IdlePolicy,
        min_size_bytes: u64,
        include_caches: bool,
        protect: &[String],
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for pattern in protect {
            builder.add(Glob::new(pattern)?);
        }
        Ok(Self {
            min_idle,
            min_size_bytes,
            include_caches,
            protect_patterns: protect.to_vec(),
            protect: builder.build()?,
        })
    }

    /// The protect list wins over everything: first matching pattern, if any.
    pub fn protected_by(&self, path: &camino::Utf8Path) -> Option<&str> {
        self.protect
            .matches(path.as_std_path())
            .first()
            .map(|&i| self.protect_patterns[i].as_str())
    }
}
