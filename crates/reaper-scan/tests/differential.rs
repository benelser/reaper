//! The load-bearing cross-platform gate (§10/§11): the selected fast leaf
//! must agree with `StdDirReader` on every field its `Caps` claim — on the
//! REAL OS, over a real fixture. A fast backend that silently disagrees with
//! the floor fails here, on the machine where it lies. Plus the
//! syscall-economy check: bulk calls must scale sub-linearly (measured shape:
//! `calls ≤ entries/50 + 2` — the +2 is the data+terminator floor).

use camino::Utf8PathBuf;
use reaper_scan::{select_reader, DirReader, Entry, FileKind, StdDirReader};
use std::collections::BTreeMap;
use std::time::Duration;

const FILES: usize = 1500;
const MTIME_TOLERANCE: Duration = Duration::from_secs(2); // NTFS enumeration mtimes can lag briefly (measured)

fn fixture() -> (tempfile::TempDir, Utf8PathBuf) {
    let td = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(td.path().to_path_buf()).unwrap();
    for i in 0..FILES {
        let size = (i * 7919) % 40960;
        std::fs::write(root.join(format!("f{i:05}.dat")), vec![0xAB; size]).unwrap();
    }
    for i in 0..5 {
        std::fs::create_dir(root.join(format!("sub{i}"))).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink("f00000.dat", root.join("link")).unwrap();
    (td, root)
}

fn by_name(entries: Vec<Entry>) -> BTreeMap<String, Entry> {
    entries.into_iter().map(|e| (e.name.clone(), e)).collect()
}

#[test]
fn fast_leaf_agrees_with_std_floor_on_everything_caps_claim() {
    let (_td, root) = fixture();
    let fast = select_reader();
    let caps = fast.caps();

    let got = by_name(fast.read_dir(&root).unwrap());
    let want = by_name(StdDirReader.read_dir(&root).unwrap());

    // Name-set equality, both directions.
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        want.keys().collect::<Vec<_>>(),
        "listing disagreement between fast leaf and std floor"
    );

    for (name, w) in &want {
        let g = &got[name];
        // Types must agree wherever the fast leaf claims one (DT_UNKNOWN
        // filesystems legally degrade to Other — the fill classifies).
        if g.kind != FileKind::Other {
            assert_eq!(g.kind, w.kind, "{name}: type disagreement");
        }
        let std_meta = root.join(name).symlink_metadata().unwrap();
        if caps.size && g.kind == FileKind::File {
            assert_eq!(g.len, Some(std_meta.len()), "{name}: size disagreement");
        }
        if caps.mtime {
            let got_mtime = g.mtime.expect("caps.mtime promised");
            let want_mtime = std_meta.modified().unwrap();
            let drift = got_mtime
                .duration_since(want_mtime)
                .or_else(|_| want_mtime.duration_since(got_mtime))
                .unwrap();
            assert!(drift <= MTIME_TOLERANCE, "{name}: mtime drift {drift:?}");
        }
        if caps.cloud {
            assert_eq!(
                g.cloud,
                Some(false),
                "{name}: fixture wrongly flagged cloud"
            );
        }
    }
}

// The syscall-economy fitness (§10): only meaningful on the concrete leaf,
// per OS — asserted where the leaf exists.

#[cfg(target_os = "macos")]
#[test]
fn macos_bulk_syscall_economy() {
    let (_td, root) = fixture();
    let reader = reaper_scan::dirread::macos::MacDirReader::probe().expect("leaf available");
    let n = reader.read_dir(&root).unwrap().len() as u64;
    let calls = reader.bulk_calls();
    assert!(
        calls <= n / 50 + 2,
        "economy violated: {calls} calls for {n} entries"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_bulk_syscall_economy() {
    let (_td, root) = fixture();
    let reader = reaper_scan::dirread::linux::LinuxDirReader::probe().expect("leaf available");
    let n = reader.read_dir(&root).unwrap().len() as u64;
    let calls = reader.bulk_calls();
    assert!(
        calls <= n / 50 + 2,
        "economy violated: {calls} calls for {n} entries"
    );
}

#[cfg(windows)]
#[test]
fn windows_bulk_syscall_economy() {
    let (_td, root) = fixture();
    let reader = reaper_scan::dirread::windows::WinDirReader::probe().expect("leaf available");
    let n = reader.read_dir(&root).unwrap().len() as u64;
    let calls = reader.bulk_calls();
    assert!(
        calls <= n / 50 + 2,
        "economy violated: {calls} calls for {n} entries"
    );
}
