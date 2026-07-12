//! The self-update swap machinery, end-to-end through the real binary:
//! a copy of reaper replaces ITSELF in place (artifact mode — no network),
//! stays executable afterwards, and leaves no staging debris.

use std::process::Command;

#[test]
fn update_swaps_the_running_binary_in_place_and_it_still_runs() {
    let td = tempfile::tempdir().unwrap();
    let installed = td.path().join(if cfg!(windows) {
        "reaper.exe"
    } else {
        "reaper"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_reaper"), &installed).unwrap();

    let before = std::fs::metadata(&installed).unwrap().modified().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100)); // mtime granularity

    // The binary updates ITSELF while running (the hard part on Windows).
    let out = Command::new(&installed)
        .env("REAPER_UPDATE_ARTIFACT", env!("CARGO_BIN_EXE_reaper"))
        .arg("update")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "update failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = std::fs::metadata(&installed).unwrap().modified().unwrap();
    assert!(after > before, "binary was not replaced");

    // The swapped binary must be immediately runnable.
    let out = Command::new(&installed).arg("--version").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("reaper"));

    // No staging debris left beside it.
    let debris: Vec<_> = std::fs::read_dir(td.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("staging"))
        .collect();
    assert!(debris.is_empty(), "staging debris: {debris:?}");

    // --check in artifact mode reports and mutates nothing.
    let before = std::fs::metadata(&installed).unwrap().modified().unwrap();
    let out = Command::new(&installed)
        .env("REAPER_UPDATE_ARTIFACT", env!("CARGO_BIN_EXE_reaper"))
        .args(["update", "--check"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        std::fs::metadata(&installed).unwrap().modified().unwrap(),
        before
    );
}
