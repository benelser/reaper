//! The native GitProbe — gix in-process, zero exec (G7). Semantics pinned by
//! the R9 fixtures and the R11 differential: dirty INCLUDES untracked (the
//! `is_dirty()` footgun is designed out — untracked work is precious);
//! unpushed = commits reachable from HEAD but from no remote tip, and 0 for
//! an attached branch when NO remote exists (worktree removal never touches
//! refs — the branch preserves every commit); lock and head come from raw
//! `.git/worktrees/<name>` file reads.

use camino::{Utf8Path, Utf8PathBuf};
use reaper_core::{GitFacts, GitProbe, HeadState, LockState};

pub struct GixProbe;

impl GitProbe for GixProbe {
    fn facts(&self, worktree: &Utf8Path) -> Option<GitFacts> {
        // Every sub-fact is independently establishable; a failure in one
        // leaves the others — the classifier refuses per missing fact.
        let admin = admin_dir_of(worktree);
        let mut facts = GitFacts {
            dirty_entries: None,
            unpushed_commits: None,
            lock: None,
            head: None,
        };

        if let Some(admin) = &admin {
            facts.lock = Some(match std::fs::read_to_string(admin.join("locked")) {
                Ok(note) => {
                    let note = note.trim();
                    LockState::Locked {
                        note: (!note.is_empty()).then(|| note.to_string()),
                    }
                }
                Err(_) => LockState::Unlocked,
            });
        }

        let repo = gix::open(worktree.as_std_path()).ok()?;

        facts.head = head_state(&repo);
        facts.dirty_entries = dirty_entries(&repo);
        facts.unpushed_commits = unpushed(&repo);
        Some(facts)
    }
}

/// `.git` FILE content: `gitdir: <path>/.git/worktrees/<name>` → the admin
/// dir whose `locked`/`HEAD` files carry worktree state. Raw file reads —
/// the R9 no-exec section proved these are the on-disk artifacts.
pub fn admin_dir_of(worktree: &Utf8Path) -> Option<Utf8PathBuf> {
    let content = std::fs::read_to_string(worktree.join(".git")).ok()?;
    let gitdir = content.strip_prefix("gitdir:")?.trim();
    let p = Utf8PathBuf::from(gitdir);
    let abs = if p.is_relative() { worktree.join(p) } else { p };
    abs.parent()?.file_name()?; // sanity: …/.git/worktrees/<name>
    Some(abs)
}

fn head_state(repo: &gix::Repository) -> Option<HeadState> {
    let head = repo.head().ok()?;
    if head.is_detached() {
        // Commits reachable from HEAD but from NO ref die with the worktree.
        let head_id = repo.head_id().ok()?;
        let all_tips: Vec<gix::ObjectId> = repo
            .references()
            .ok()?
            .all()
            .ok()?
            .filter_map(|r| r.ok())
            .filter_map(|r| r.try_id().map(|id| id.detach()))
            .collect();
        let unreachable_commits = repo
            .rev_walk([head_id.detach()])
            .with_hidden(all_tips)
            .all()
            .ok()?
            .filter_map(|c| c.ok())
            .count() as u64;
        Some(HeadState::Detached {
            unreachable_commits,
        })
    } else {
        let branch = head.referent_name()?.shorten().to_string();
        Some(HeadState::Attached { branch })
    }
}

/// Dirty = ANY index/worktree divergence, untracked included — the R11
/// finding: `is_dirty()` ignores untracked files, which are precious here.
fn dirty_entries(repo: &gix::Repository) -> Option<usize> {
    let iter = repo
        .status(gix::progress::Discard)
        .ok()?
        .into_index_worktree_iter(Vec::new())
        .ok()?;
    Some(iter.filter_map(Result::ok).count())
}

fn unpushed(repo: &gix::Repository) -> Option<u64> {
    let head_id = repo.head_id().ok()?;
    let remote_tips: Vec<gix::ObjectId> = repo
        .references()
        .ok()?
        .prefixed("refs/remotes/")
        .ok()?
        .filter_map(|r| r.ok())
        .filter_map(|r| r.try_id().map(|id| id.detach()))
        .collect();
    if remote_tips.is_empty() {
        // No remote exists: an attached branch preserves every commit across
        // worktree removal (slice-2 ruling, R9 data). Detached risk is
        // carried by HeadState, not here.
        return Some(0);
    }
    Some(
        repo.rev_walk([head_id.detach()])
            .with_hidden(remote_tips)
            .all()
            .ok()?
            .filter_map(|c| c.ok())
            .count() as u64,
    )
}
