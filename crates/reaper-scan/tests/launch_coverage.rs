//! The launch-coverage bar (§5/§10): a fixture "dev home" containing every
//! shipped ecosystem — ALL detected in one scan, plus the CACHEDIR.TAG
//! catch-all (zero extra syscalls: the tag is in the listing already).
//! "reaper found nothing" on a real dev machine is a bug, not a shrug.

use camino::Utf8PathBuf;
use reaper_core::Registry;
use reaper_scan::{scan, ScanEvent, StdDirReader};
use std::collections::BTreeSet;
use std::sync::Mutex;

fn touch(root: &Utf8PathBuf, rel: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, "x").unwrap();
}

fn mkdir(root: &Utf8PathBuf, rel: &str) {
    std::fs::create_dir_all(root.join(rel)).unwrap();
}

#[test]
fn dev_home_fixture_detects_every_shipped_ecosystem() {
    let td = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(td.path().to_path_buf()).unwrap();

    // ecosystem roots: (marker file(s), reclaim dir)
    touch(&root, "rs/Cargo.toml");
    mkdir(&root, "rs/target");
    touch(&root, "mvn/pom.xml");
    mkdir(&root, "mvn/target");
    touch(&root, "js/package.json");
    mkdir(&root, "js/node_modules");
    touch(&root, "js/.next/keep"); // .next needs to exist as a dir
    touch(&root, "py/pyproject.toml");
    mkdir(&root, "py/.venv");
    mkdir(&root, "py/__pycache__");
    touch(&root, "py/tox.ini");
    mkdir(&root, "py/.tox");
    mkdir(&root, "py/.mypy_cache");
    mkdir(&root, "py/.pytest_cache");
    touch(&root, "jvm/build.gradle");
    mkdir(&root, "jvm/build");
    mkdir(&root, "jvm/.gradle");
    touch(&root, "cs/App.csproj");
    mkdir(&root, "cs/bin");
    mkdir(&root, "cs/obj");
    touch(&root, "go/go.mod");
    mkdir(&root, "go/bin");
    touch(&root, "ios/Podfile");
    mkdir(&root, "ios/Pods");
    mkdir(&root, "ios/App.xcodeproj");
    mkdir(&root, "ios/DerivedData");
    touch(&root, "zig/build.zig");
    mkdir(&root, "zig/.zig-cache");
    mkdir(&root, "zig/zig-out");
    touch(&root, "dart/pubspec.yaml");
    mkdir(&root, "dart/.dart_tool");
    touch(&root, "ex/mix.exs");
    mkdir(&root, "ex/_build");
    touch(&root, "php/composer.json");
    mkdir(&root, "php/vendor");
    // the catch-all: a tool nobody wrote a row for
    touch(&root, "somebuild/cache/CACHEDIR.TAG");

    let seen = Mutex::new(BTreeSet::new());
    let registry = Registry::embedded().unwrap();
    scan(&root, &registry, &StdDirReader, &|ev| {
        if let ScanEvent::Discovered(c) = ev {
            seen.lock().unwrap().insert(c.detector.0.clone());
        }
    });
    let seen = seen.lock().unwrap();

    for expected in [
        "rust-target",
        "maven-target",
        "node-modules",
        "nextjs",
        "python-venv",
        "python-pycache",
        "python-tox",
        "python-mypy-cache",
        "python-pytest-cache",
        "gradle-build",
        "gradle-dot",
        "dotnet-bin",
        "dotnet-obj",
        "go-bin",
        "cocoapods",
        "xcode-deriveddata",
        "zig-cache",
        "zig-out",
        "dart-tool",
        "elixir-build",
        "php-vendor",
        "cachedir-tag",
    ] {
        assert!(
            seen.contains(expected),
            "launch bar: {expected} not detected; saw {seen:?}"
        );
    }
}
