//! The purity fitness gate (SPEC §10): reaper-core links serde + camino and
//! NOTHING else. A new runtime dependency here must be argued into this list,
//! not slipped past it.

const ALLOWLIST: &[&str] = &["camino", "globset", "serde", "serde_json", "sha2", "toml"];

#[test]
fn core_runtime_dependencies_are_allowlisted() {
    let manifest = include_str!("../Cargo.toml");
    let mut in_deps = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_deps = line == "[dependencies]";
            continue;
        }
        if !in_deps || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = line.split(['=', '.', ' ']).next().unwrap_or_default();
        assert!(
            ALLOWLIST.contains(&name),
            "reaper-core grew a runtime dependency not on the allowlist: {name}"
        );
    }
}
