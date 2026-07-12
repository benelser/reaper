//! The §11 e2e layer: scan → seal → reap --execute → undo, on a real tree,
//! through the real binary. Also the drift gate: a tree swapped after
//! planning refuses on the (dev,ino) mismatch and is left in place.
//! filetime ages the fixture (no wall-clock games).

use std::process::Command;

fn reaper(state: &std::path::Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .env("REAPER_STATE_DIR", state)
        .args(args)
        .output()
        .expect("spawn reaper");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// An aged rust project: target/ is 10 days idle — fully reapable.
fn aged_fixture(root: &std::path::Path) {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(proj.join("Cargo.toml"), "[package]").unwrap();
    std::fs::write(proj.join("src/main.rs"), "fn main(){}").unwrap();
    let deep = proj.join("target/debug/deps");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("artifact.o"), vec![0u8; 4096]).unwrap();
    let old = filetime::FileTime::from_unix_time(
        filetime::FileTime::now().unix_seconds() - 10 * 86_400,
        0,
    );
    for p in [
        proj.join("target"),
        proj.join("target/debug"),
        deep.clone(),
        deep.join("artifact.o"),
    ] {
        filetime::set_file_mtime(&p, old).unwrap();
    }
}

#[test]
fn scan_reap_undo_round_trip() {
    let td = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    aged_fixture(td.path());
    let target = td.path().join("proj/target");

    // 1. scan: the aged target is reapable and a plan is sealed.
    let (ok, out) = reaper(
        state.path(),
        &["scan", td.path().to_str().unwrap(), "--format", "json"],
    );
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v["candidates"][0]["disposition"]["status"], "reapable",
        "{out}"
    );
    let digest = v["plan_digest"].as_str().expect("plan sealed").to_string();
    assert_eq!(v["totals"]["reapable_bytes"], 4096);

    // 2. dry-run reap: exit 0, NOTHING mutated.
    let (ok, out) = reaper(state.path(), &["reap", "--plan", &digest]);
    assert!(ok, "dry-run must exit 0");
    assert!(out.contains("would reap"), "{out}");
    assert!(target.exists(), "dry-run mutated the tree!");

    // 3. execute: the target is PERMANENTLY gone; the tomb is drained.
    let (ok, out) = reaper(
        state.path(),
        &["reap", "--plan", &digest, "--execute", "--format", "json"],
    );
    assert!(ok, "execute failed: {out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["outcomes"][0]["outcome"], "reaped");
    assert_eq!(v["freed_bytes"], 4096);
    assert!(!target.exists(), "target survived --execute");
    assert!(
        !td.path().join("proj").read_dir().unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".reaper-tomb")),
        "tomb left behind"
    );

    // 4. undo EMITS the regenerate command (never runs it — G7).
    let (ok, out) = reaper(state.path(), &["undo", &digest]);
    assert!(ok);
    assert!(out.contains("cargo build"), "recovery hint missing: {out}");
    assert!(!target.exists(), "undo must not resurrect");
}

#[test]
fn drifted_tree_refuses_and_is_left_in_place() {
    let td = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    aged_fixture(td.path());
    let target = td.path().join("proj/target");

    let (ok, out) = reaper(
        state.path(),
        &["scan", td.path().to_str().unwrap(), "--format", "json"],
    );
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let digest = v["plan_digest"].as_str().expect("plan sealed").to_string();

    // Swap the planned dir for a NEW dir at the same path: new (dev, ino).
    std::fs::remove_dir_all(&target).unwrap();
    std::fs::create_dir_all(target.join("precious")).unwrap();
    std::fs::write(target.join("precious/data.txt"), "irreplaceable").unwrap();

    let (ok, out) = reaper(
        state.path(),
        &["reap", "--plan", &digest, "--execute", "--format", "json"],
    );
    assert!(!ok, "drifted execute must exit non-zero");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["outcomes"][0]["outcome"], "refused", "{out}");
    assert!(
        target.join("precious/data.txt").exists(),
        "drift refusal must leave the new tree untouched"
    );
}

/// Exit-code honesty (§9) — asserted, not assumed:
/// scan = 0; dry-run = 0; undo-with-nothing = non-zero; and an execute that
/// CANNOT write its write-ahead manifest refuses and leaves the tree alive.
#[test]
fn exit_codes_are_honest_and_write_ahead_is_load_bearing() {
    let td = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    aged_fixture(td.path());

    let (ok, out) = reaper(
        state.path(),
        &["scan", td.path().to_str().unwrap(), "--format", "json"],
    );
    assert!(ok, "scan must exit 0");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let digest = v["plan_digest"].as_str().expect("plan sealed").to_string();

    // undo with no reap log yet: non-zero, honest.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_reaper"))
        .env("REAPER_STATE_DIR", state.path())
        .args(["undo", &digest])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "undo with nothing recoverable must be non-zero"
    );

    // Make the log dir unwritable: the write-ahead manifest cannot exist, so
    // --execute must REFUSE (non-zero) and the target must SURVIVE.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let target = td.path().join("proj/target");
        let log_dir = state.path().join("reaper/log");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let out = std::process::Command::new(env!("CARGO_BIN_EXE_reaper"))
            .env("REAPER_STATE_DIR", state.path())
            .args(["reap", "--plan", &digest, "--execute"])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "unwritable manifest must fail the execute, not greenwash it"
        );
        assert!(
            target.exists(),
            "write-ahead failure must leave the tree alive"
        );
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn a_refused_execute_releases_the_instance_lock() {
    let td = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    aged_fixture(td.path());
    let (ok, out) = reaper(
        state.path(),
        &["scan", td.path().to_str().unwrap(), "--format", "json"],
    );
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let digest = v["plan_digest"].as_str().unwrap().to_string();

    // Make the plan unexecutable: remove the target so the step refuses.
    std::fs::remove_dir_all(td.path().join("proj/target")).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_reaper"))
        .env("REAPER_STATE_DIR", state.path())
        .args(["reap", "--plan", &digest, "--execute"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "refused execute is non-zero");

    // The lock must NOT be stranded (exit-without-drop regression).
    assert!(
        !state.path().join("reaper/execute.lock").exists(),
        "refused execute stranded the instance lock"
    );
}

/// A tomb from plan A must drain on ANY later execute (plan B) — resume is
/// cross-digest (dogfood catch: interrupted drains lingered forever).
#[test]
fn interrupted_tombs_resume_across_digests() {
    let td = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    aged_fixture(td.path());

    // Forge an interrupted run: a manifest with Tombed and no Drained, plus
    // the tomb itself on disk.
    let tomb = td.path().join("proj/.reaper-tomb-legacy");
    std::fs::create_dir_all(tomb.join("deep")).unwrap();
    std::fs::write(tomb.join("deep/left.o"), vec![0u8; 128]).unwrap();
    let log = state.path().join("reaper/log");
    std::fs::create_dir_all(&log).unwrap();
    std::fs::write(
        log.join("sha256-legacy.jsonl"),
        format!(
            "{}\n",
            serde_json::json!({"event":"tombed","path": td.path().join("proj/old").to_str().unwrap(),
                "tomb": tomb.to_str().unwrap(), "recover": null, "size_bytes": 128})
        ),
    )
    .unwrap();

    // Execute a DIFFERENT plan; the legacy tomb must be drained first.
    let (ok, out) = reaper(
        state.path(),
        &["scan", td.path().to_str().unwrap(), "--format", "json"],
    );
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let digest = v["plan_digest"].as_str().unwrap().to_string();
    let (ok, _) = reaper(state.path(), &["reap", "--plan", &digest, "--execute"]);
    assert!(ok);
    assert!(
        !tomb.exists(),
        "cross-digest resume must drain the legacy tomb"
    );

    // And it is idempotent: the manifest now carries the Drained record.
    let closed = std::fs::read_to_string(log.join("sha256-legacy.jsonl")).unwrap();
    assert!(
        closed.contains("drained"),
        "recovery must close the ledger: {closed}"
    );
}
