//! `reaper update` — self-update in place, the way first-class Rust binaries
//! do it: resolve the latest tag from the GitHub release redirect (no API,
//! no rate limits), download this platform's asset, verify its sha256
//! sidecar, then atomically swap the running executable (`self-replace`
//! handles the Windows running-exe dance). In-process HTTP only.
//!
//! `REAPER_UPDATE_ARTIFACT=<path to raw binary>` bypasses the network and
//! version check so CI can exercise the swap machinery on every OS.

use sha2::{Digest, Sha256};
use std::io::Read;

const REPO: &str = "benelser/reaper";
const TARGET: &str = env!("REAPER_TARGET");
const CURRENT: &str = env!("CARGO_PKG_VERSION");

pub fn run(check_only: bool) {
    // CI/test escape hatch: swap in a local artifact, no network.
    if let Some(artifact) = std::env::var_os("REAPER_UPDATE_ARTIFACT") {
        if check_only {
            println!("artifact mode: {artifact:?} would be installed");
            return;
        }
        let bytes =
            std::fs::read(&artifact).unwrap_or_else(|e| fail(&format!("read artifact: {e}")));
        install(&bytes);
        println!("reaper updated in place (artifact mode)");
        return;
    }

    let latest_tag = latest_tag().unwrap_or_else(|e| fail(&e));
    let latest = latest_tag.trim_start_matches('v');
    if !newer(latest, CURRENT) {
        println!("reaper {CURRENT} is up to date (latest release: {latest_tag})");
        return;
    }
    println!("update available: {CURRENT} → {latest}");
    if check_only {
        println!("run `reaper update` to install it");
        return;
    }

    let ext = if cfg!(windows) { ".exe" } else { "" };
    let base =
        format!("https://github.com/{REPO}/releases/download/{latest_tag}/reaper-{TARGET}{ext}");
    println!("downloading reaper-{TARGET}{ext} …");
    let bytes = fetch(&base).unwrap_or_else(|e| fail(&e));
    let sidecar = fetch(&format!("{base}.sha256")).unwrap_or_else(|e| fail(&e));

    if let Err(e) = verify_sha256(&bytes, &sidecar) {
        fail(&e);
    }

    install(&bytes);
    println!("reaper {CURRENT} → {latest} — updated in place");
}

/// Integrity gate: the sidecar's hex digest must match the downloaded bytes.
fn verify_sha256(bytes: &[u8], sidecar: &[u8]) -> Result<(), String> {
    let want = String::from_utf8_lossy(sidecar);
    let want = want
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let got = format!("{:x}", Sha256::digest(bytes));
    if want.len() != 64 {
        return Err(format!(
            "malformed checksum sidecar {want:?} — refusing to install"
        ));
    }
    if want != got {
        return Err(format!(
            "checksum mismatch: expected {want}, downloaded {got} — refusing to install"
        ));
    }
    Ok(())
}

/// Write next to the current exe (same filesystem), then atomically swap.
fn install(bytes: &[u8]) {
    let exe = std::env::current_exe().unwrap_or_else(|e| fail(&format!("current_exe: {e}")));
    let staging = exe.with_extension("update-staging");
    std::fs::write(&staging, bytes).unwrap_or_else(|e| fail(&format!("stage update: {e}")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755));
    }
    if let Err(e) = self_replace::self_replace(&staging) {
        let _ = std::fs::remove_file(&staging);
        fail(&format!("swap failed (binary unchanged): {e}"));
    }
    let _ = std::fs::remove_file(&staging);
}

/// The latest release tag, from the redirect target of /releases/latest —
/// no API token, no rate limit, one round trip.
fn latest_tag() -> Result<String, String> {
    let agent = ureq::builder().redirects(0).build();
    let resp = match agent
        .get(&format!("https://github.com/{REPO}/releases/latest"))
        .call()
    {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) if (300..400).contains(&code) => r,
        Err(e) => return Err(format!("release lookup failed: {e}")),
    };
    let location = resp
        .header("location")
        .ok_or("release lookup: no redirect — no releases published yet?")?;
    location
        .rsplit('/')
        .next()
        .filter(|t| t.starts_with('v'))
        .map(str::to_string)
        .ok_or_else(|| format!("unexpected release redirect: {location}"))
}

fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("download {url}: {e}"))?;
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(256 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("download {url}: {e}"))?;
    Ok(bytes)
}

/// Strict semver-ish comparison over dotted numerics ("0.2.1" > "0.2.0").
fn newer(candidate: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split(['.', '-'])
            .map_while(|p| p.parse::<u64>().ok())
            .collect()
    };
    parse(candidate) > parse(current)
}

fn fail(msg: &str) -> ! {
    eprintln!("update error: {msg}");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::{newer, verify_sha256};

    #[test]
    fn version_ordering_is_numeric_not_lexicographic() {
        assert!(newer("0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "0.99.0"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.1.0", "0.2.0"));
    }

    #[test]
    fn checksum_gate_refuses_mismatch_and_garbage() {
        use sha2::{Digest, Sha256};
        let bytes = b"the binary";
        let good = format!("{:x}  reaper-x", Sha256::digest(bytes));
        assert!(verify_sha256(bytes, good.as_bytes()).is_ok());
        // one flipped nibble
        let mut bad = good.clone();
        bad.replace_range(0..1, if &good[0..1] == "a" { "b" } else { "a" });
        assert!(verify_sha256(bytes, bad.as_bytes()).is_err());
        // malformed sidecars never pass
        assert!(verify_sha256(bytes, b"").is_err());
        assert!(verify_sha256(bytes, b"<html>404</html>").is_err());
    }
}
