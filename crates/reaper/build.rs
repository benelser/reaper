fn main() {
    // The updater needs the target triple at runtime to pick its release asset.
    println!(
        "cargo:rustc-env=REAPER_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
}
