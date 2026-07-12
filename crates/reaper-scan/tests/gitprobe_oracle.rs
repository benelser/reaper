//! The GitFacts differential gate (§10): the native gix probe vs real git as
//! the oracle, over the R9 fixture shapes. Real git runs ONLY here, in
//! tests — the shipped probe never execs (G7).

use camino::{Utf8Path, Utf8PathBuf};
use reaper_core::{GitProbe, HeadState, LockState};
use reaper_scan::GixProbe;
use std::process::Command;

fn git(dir: &Utf8Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir.as_str())
        .args(args)
        .env("GIT_AUTHOR_NAME", "oracle")
        .env("GIT_AUTHOR_EMAIL", "o@x")
        .env("GIT_COMMITTER_NAME", "oracle")
        .env("GIT_COMMITTER_EMAIL", "o@x")
        .output()
        .expect("git oracle");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// One repo with a remote, one worktree per scenario.
#[test]
fn gix_probe_matches_the_git_oracle_across_worktree_states() {
    let td = tempfile::tempdir().unwrap();
    // NOT canonicalized: Windows canonicalize yields \\?\-prefixed paths
    // that git -C rejects; nothing here compares paths.
    let root = Utf8PathBuf::from_path_buf(td.path().to_path_buf()).unwrap();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("f"), "base").unwrap();
    git(&repo, &["add", "f"]);
    git(&repo, &["commit", "-qm", "base"]);
    git(
        &repo,
        &["init", "-q", "--bare", root.join("origin.git").as_str()],
    );
    git(
        &repo,
        &["remote", "add", "origin", root.join("origin.git").as_str()],
    );
    git(&repo, &["push", "-qu", "origin", "main"]);

    let probe = GixProbe;

    // clean + pushed: everything affirmatively clean
    let wt = root.join("wt-clean");
    git(
        &repo,
        &["worktree", "add", "-q", "-b", "clean", wt.as_str()],
    );
    git(&wt, &["push", "-qu", "origin", "clean"]);
    let facts = probe.facts(&wt).expect("facts");
    assert_eq!(facts.dirty_entries, Some(0));
    assert_eq!(facts.unpushed_commits, Some(0));
    assert_eq!(facts.lock, Some(LockState::Unlocked));
    assert_eq!(
        facts.head,
        Some(HeadState::Attached {
            branch: "clean".into()
        })
    );

    // dirty (untracked-only — the is_dirty() footgun case)
    let wt = root.join("wt-dirty");
    git(
        &repo,
        &["worktree", "add", "-q", "-b", "dirty", wt.as_str()],
    );
    std::fs::write(wt.join("untracked.txt"), "x").unwrap();
    let facts = probe.facts(&wt).expect("facts");
    let oracle_dirty = !git(&wt, &["status", "--porcelain"]).is_empty();
    assert_eq!(facts.dirty_entries.map(|n| n > 0), Some(oracle_dirty));
    assert_eq!(facts.dirty_entries, Some(1));

    // ahead of upstream by 2
    let wt = root.join("wt-ahead");
    git(
        &repo,
        &["worktree", "add", "-q", "-b", "ahead", wt.as_str()],
    );
    git(&wt, &["push", "-qu", "origin", "ahead"]);
    git(&wt, &["commit", "-qm", "a1", "--allow-empty"]);
    git(&wt, &["commit", "-qm", "a2", "--allow-empty"]);
    let facts = probe.facts(&wt).expect("facts");
    let oracle: u64 = git(&wt, &["rev-list", "--count", "HEAD", "--not", "--remotes"])
        .parse()
        .unwrap();
    assert_eq!(facts.unpushed_commits, Some(oracle));
    assert_eq!(facts.unpushed_commits, Some(2));

    // locked, with a reason
    let wt = root.join("wt-locked");
    git(
        &repo,
        &["worktree", "add", "-q", "-b", "locked", wt.as_str()],
    );
    git(
        &repo,
        &["worktree", "lock", "--reason", "keep me", wt.as_str()],
    );
    let facts = probe.facts(&wt).expect("facts");
    assert_eq!(
        facts.lock,
        Some(LockState::Locked {
            note: Some("keep me".into())
        })
    );

    // detached with an unreachable commit
    let wt = root.join("wt-detached");
    git(
        &repo,
        &["worktree", "add", "-q", "--detach", wt.as_str(), "main"],
    );
    git(&wt, &["commit", "-qm", "orphan", "--allow-empty"]);
    let facts = probe.facts(&wt).expect("facts");
    assert_eq!(
        facts.head,
        Some(HeadState::Detached {
            unreachable_commits: 1
        })
    );
}

#[test]
fn remote_less_repo_worktree_is_not_unpushed_when_attached() {
    let td = tempfile::tempdir().unwrap();
    // NOT canonicalized: Windows canonicalize yields \\?\-prefixed paths
    // that git -C rejects; nothing here compares paths.
    let root = Utf8PathBuf::from_path_buf(td.path().to_path_buf()).unwrap();
    let repo = root.join("lonely");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("f"), "x").unwrap();
    git(&repo, &["add", "f"]);
    git(&repo, &["commit", "-qm", "base"]);
    let wt = root.join("wt");
    git(&repo, &["worktree", "add", "-q", "-b", "feat", wt.as_str()]);
    git(&wt, &["commit", "-qm", "local-only", "--allow-empty"]);

    let facts = GixProbe.facts(&wt).expect("facts");
    // Slice-2 ruling, R9 data: the branch preserves every commit across
    // worktree removal — no remote does NOT mean unpushed.
    assert_eq!(facts.unpushed_commits, Some(0));
    assert_eq!(
        facts.head,
        Some(HeadState::Attached {
            branch: "feat".into()
        })
    );
    assert_eq!(facts.dirty_entries, Some(0));
}
