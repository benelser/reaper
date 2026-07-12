//! Self-detection gate for the live-process sweep (§10 "active-build gate"):
//! a real child process holding a real resource inside a candidate dir MUST
//! be reported, and after it exits it must NOT be. (Test-side spawning is
//! fine — G7 binds the shipped binary.)

use camino::Utf8PathBuf;
use reaper_scan::select_probe;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn child_holding_a_file_is_detected_then_released() {
    let probe = match select_probe() {
        Some(p) => p,
        None => return, // platform without a sweep: classifier refuses Unknown
    };
    let td = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(td.path().canonicalize().unwrap()).unwrap();
    std::fs::write(dir.join("held.txt"), b"held").unwrap();

    // A child that opens the file, reports READY, and parks on stdin.
    #[cfg(unix)]
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd '{dir}' && exec 9<held.txt && echo READY && read line"
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    #[cfg(windows)]
    let mut child = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$f=[IO.File]::Open('{}\\held.txt','Open','Read','None'); Write-Output READY; [Console]::In.ReadLine() | Out-Null; $f.Close()",
                dir
            ),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for READY so the hold is established before sweeping.
    {
        use std::io::{BufRead, BufReader};
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "READY");
    }

    let dirs = vec![dir.clone()];
    let pids = probe
        .live_pids(&dirs)
        .remove(0)
        .expect("sweep must establish the fact here");
    assert!(
        pids.contains(&child.id()),
        "child {} holding a file in {dir} not detected: {pids:?}",
        child.id()
    );

    // Release and verify no stale positive.
    child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    drop(child.stdin.take());
    child.wait().unwrap();
    let pids = probe
        .live_pids(&dirs)
        .remove(0)
        .expect("sweep must establish the fact here");
    assert!(
        !pids.contains(&child.id()),
        "exited child still reported: {pids:?}"
    );
}
