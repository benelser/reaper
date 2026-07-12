//! The portable orchestrator (SPEC §6.2/§6.3): rayon work-stealing across
//! directories, prune-on-classify at reclaim roots, zero `cfg`. Proven
//! against jwalk (0.74–0.86× measured on all three OSes) and held by
//! tests/bench_gate.rs.

use crate::dirread::{DirReader, FileKind};
use camino::Utf8PathBuf;
use reaper_core::{Candidate, Registry};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// The event seam both surfaces consume. Grows (Sized, Progress, …) without
/// breaking consumers.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScanEvent {
    Discovered(Candidate),
    /// Heartbeat while walking (every ~128 dirs) — live feedback is a
    /// product requirement, not a nicety.
    Progress {
        dirs: u64,
        files: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanTotals {
    pub dirs: u64,
    pub files: u64,
    pub candidates: u64,
}

struct Ctx<'a> {
    reader: &'a dyn DirReader,
    registry: &'a Registry,
    emit: &'a (dyn Fn(ScanEvent) + Sync),
    dirs: AtomicU64,
    files: AtomicU64,
    candidates: AtomicU64,
}

/// Walk `root`, stream `ScanEvent`s to `emit`, return totals. Reclaim roots
/// are recorded and NEVER descended — the §6.3 algorithmic win. Symlinks are
/// never followed, so cycles cannot occur. Unreadable directories are
/// skipped: a dir we cannot read is a dir we never claim (fail closed).
pub fn scan(
    root: &Utf8PathBuf,
    registry: &Registry,
    reader: &dyn DirReader,
    emit: &(dyn Fn(ScanEvent) + Sync),
) -> ScanTotals {
    let ctx = Ctx {
        reader,
        registry,
        emit,
        dirs: AtomicU64::new(0),
        files: AtomicU64::new(0),
        candidates: AtomicU64::new(0),
    };
    rayon::scope(|s| visit(root.clone(), s, &ctx));
    ScanTotals {
        dirs: ctx.dirs.load(Ordering::Relaxed),
        files: ctx.files.load(Ordering::Relaxed),
        candidates: ctx.candidates.load(Ordering::Relaxed),
    }
}

fn visit<'s>(dir: Utf8PathBuf, s: &rayon::Scope<'s>, ctx: &'s Ctx<'_>) {
    let d = ctx.dirs.fetch_add(1, Ordering::Relaxed) + 1;
    if d.is_multiple_of(128) {
        (ctx.emit)(ScanEvent::Progress {
            dirs: d,
            files: ctx.files.load(Ordering::Relaxed),
        });
    }
    let Ok(entries) = ctx.reader.read_dir(&dir) else {
        return;
    };

    let files: Vec<&str> = entries
        .iter()
        .filter(|e| e.kind == FileKind::File)
        .map(|e| e.name.as_str())
        .collect();
    let subdirs: Vec<&str> = entries
        .iter()
        .filter(|e| e.kind == FileKind::Dir)
        .map(|e| e.name.as_str())
        .collect();
    let matched = ctx.registry.match_listing(&dir, &files, &subdirs);
    // Only PRUNING matches stop the descent (§6.3); a worktree candidate
    // keeps walking so its inner bloat stays independently reapable. A
    // pruning SELF-match (CACHEDIR.TAG) stops this whole dir.
    let mut stop_here = false;
    let pruned: HashSet<&str> = matched
        .iter()
        .filter(|m| m.prune)
        .filter_map(|m| {
            if m.candidate.path == dir {
                stop_here = true;
                None
            } else {
                m.candidate.path.file_name()
            }
        })
        .collect();
    for m in &matched {
        ctx.candidates.fetch_add(1, Ordering::Relaxed);
        (ctx.emit)(ScanEvent::Discovered(m.candidate.clone()));
    }
    if stop_here {
        return; // self-declared cache: one candidate, zero descents
    }

    for e in entries {
        match e.kind {
            FileKind::Dir => {
                if pruned.contains(e.name.as_str()) {
                    continue; // a claimed reclaim root: one candidate, zero descents
                }
                let child = dir.join(&e.name);
                s.spawn(move |s| visit(child, s, ctx));
            }
            FileKind::File => {
                ctx.files.fetch_add(1, Ordering::Relaxed);
            }
            FileKind::Symlink | FileKind::Other => {} // counted nowhere, followed never
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dirread::StdDirReader;
    use std::sync::Mutex;

    fn fixture() -> (tempfile::TempDir, Utf8PathBuf) {
        let td = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(td.path().to_path_buf()).unwrap();
        let proj = root.join("proj");
        std::fs::create_dir_all(proj.join("src")).unwrap();
        std::fs::write(proj.join("Cargo.toml"), "[package]").unwrap();
        std::fs::write(proj.join("src/main.rs"), "fn main(){}").unwrap();
        let deep = proj.join("target/debug/deps");
        std::fs::create_dir_all(&deep).unwrap();
        for i in 0..50 {
            std::fs::write(deep.join(format!("o{i}")), "x").unwrap();
        }
        (td, root)
    }

    #[test]
    fn discovers_the_reclaim_root_and_never_descends_it() {
        let (_td, root) = fixture();
        let seen = Mutex::new(Vec::new());
        let totals = scan(
            &root,
            &Registry::embedded().unwrap(),
            &StdDirReader,
            &|ev| {
                if let ScanEvent::Discovered(c) = ev {
                    seen.lock().unwrap().push(c);
                }
            },
        );

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].path.ends_with("proj/target"));
        assert_eq!(totals.candidates, 1);
        // Prune proof: the 50 files inside target/ were never enumerated.
        assert_eq!(
            totals.files, 2,
            "expected only Cargo.toml + src/main.rs, got {totals:?}"
        );
    }

    #[test]
    fn empty_registry_walks_everything() {
        let (_td, root) = fixture();
        let totals = scan(&root, &Registry::empty(), &StdDirReader, &|_| {});
        assert_eq!(totals.candidates, 0);
        assert_eq!(totals.files, 52); // 2 sources + 50 artifacts: nothing pruned
    }
}
