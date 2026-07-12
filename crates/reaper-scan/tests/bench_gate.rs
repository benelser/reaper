//! The traversal-speed fitness gate, shaped by two measured findings:
//!   R3:  the orchestrator beat jwalk on all three OSes (0.74–0.86×) — hold it.
//!   hosted runners spread 2.2× across machines and spike within runs —
//!        so this gate is a SAME-RUN MEDIAN RATIO, never an absolute time.
//!
//! `#[ignore]`d in the normal suite; the CI bench-gate job runs it with
//! `--release -- --ignored`.

use camino::Utf8PathBuf;
use reaper_core::Registry;
use reaper_scan::{scan, StdDirReader};
use std::time::Instant;

const REPOS: usize = 60;
const SRC_FILES: usize = 20;
const TARGET_SUBDIRS: usize = 16;
const TARGET_FILES_PER_SUBDIR: usize = 50;
const REPS: usize = 9;

#[test]
#[ignore = "perf gate — run explicitly in --release (CI bench-gate job)"]
fn orchestrator_holds_parity_and_prune_wins() {
    let td = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(td.path().to_path_buf()).unwrap();
    build_fixture(&root);

    let (mut jw, mut full, mut pruned) = (vec![], vec![], vec![]);
    for _ in 0..REPS {
        // Interleaved so machine drift hits all contenders equally (R10).
        jw.push(time(|| jwalk_files(&root)));
        full.push(time(|| scan_files(&root, Registry::empty())));
        pruned.push(time(|| scan_files(&root, Registry::embedded().unwrap())));
    }
    let (jw, full, pruned) = (median(&mut jw), median(&mut full), median(&mut pruned));
    let parity = full / jw;
    let prune_win = jw / pruned;
    println!("bench-gate medians_ms: jwalk={jw:.2} ours_full={full:.2} ours_pruned={pruned:.2}");
    println!("bench-gate parity_ratio={parity:.3} prune_win={prune_win:.1}x");

    assert!(
        parity <= 1.15,
        "orchestrator lost parity vs jwalk: ratio {parity:.3} > 1.15"
    );
    assert!(
        prune_win >= 3.0,
        "prune-on-classify win collapsed: {prune_win:.1}x < 3x"
    );
}

fn build_fixture(root: &Utf8PathBuf) {
    for r in 0..REPOS {
        let repo = root.join(format!("repo{r:03}"));
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("Cargo.toml"), "[package]").unwrap();
        for f in 0..SRC_FILES {
            std::fs::write(repo.join("src").join(format!("s{f}.rs")), "x").unwrap();
        }
        for d in 0..TARGET_SUBDIRS {
            let sub = repo.join("target").join(format!("t{d:02}"));
            std::fs::create_dir_all(&sub).unwrap();
            for f in 0..TARGET_FILES_PER_SUBDIR {
                std::fs::write(sub.join(format!("o{f}")), "x").unwrap();
            }
        }
    }
}

fn time(f: impl Fn() -> u64) -> f64 {
    let t = Instant::now();
    std::hint::black_box(f());
    t.elapsed().as_secs_f64() * 1e3
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn jwalk_files(root: &Utf8PathBuf) -> u64 {
    jwalk::WalkDir::new(root)
        .skip_hidden(false)
        .sort(false)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .count() as u64
}

fn scan_files(root: &Utf8PathBuf, registry: Registry) -> u64 {
    scan(root, &registry, &StdDirReader, &|_| {}).files
}
