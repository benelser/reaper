//! Golden shape of `reaper scan --format json` (SPEC §10 "schema stability").
//! Spawning the real binary is the point: this is the exact surface an agent
//! sees. (Test-side process spawning is fine — G7 binds the SHIPPED binary.)

use std::process::Command;

#[test]
fn scan_json_reports_candidate_fail_closed_and_pruned_totals() {
    let td = tempfile::tempdir().unwrap();
    let proj = td.path().join("proj");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(proj.join("Cargo.toml"), "[package]").unwrap();
    std::fs::write(proj.join("src/main.rs"), "fn main(){}").unwrap();
    let deep = proj.join("target/debug/incremental");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("artifact.o"), "x").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["scan", td.path().to_str().unwrap(), "--format", "json"])
        .output()
        .expect("spawn reaper");
    assert!(
        out.status.success(),
        "scan exited nonzero: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json");
    assert_eq!(v["schema_version"], "reaper-scan/v1");

    let candidates = v["candidates"].as_array().expect("candidates array");
    assert_eq!(candidates.len(), 1);
    let c = &candidates[0];
    assert!(c["path"].as_str().unwrap().ends_with("target"));
    assert_eq!(c["ecosystem"], "rust");
    assert_eq!(c["detector"], "rust-target");
    // A freshly-written fixture ALWAYS refuses: it is 0 days idle against a
    // 3-day floor (and typically flags active-build too). The refusal being
    // `too_recent` — not `unknown` — proves the probes established real facts.
    assert_eq!(c["disposition"]["status"], "refused");
    let codes: Vec<&str> = c["disposition"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["code"].as_str().unwrap())
        .collect();
    assert!(
        codes.contains(&"too_recent"),
        "expected too_recent in {codes:?}"
    );
    assert_eq!(c["size_bytes"], 1); // the 1-byte artifact, summed through the prune

    // Prune proof at the surface: the artifact inside target/ was never walked.
    assert_eq!(v["totals"]["files"], 2);
    assert_eq!(v["totals"]["candidates"], 1);
}

#[test]
fn scanning_a_missing_path_or_file_is_a_loud_error() {
    for bad in ["/definitely/not/a/path", file!()] {
        let out = Command::new(env!("CARGO_BIN_EXE_reaper"))
            .args(["scan", bad])
            .output()
            .unwrap();
        assert!(!out.status.success(), "scan {bad} must fail loudly");
    }
}
