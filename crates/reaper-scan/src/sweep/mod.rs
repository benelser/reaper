//! The live-process sweep (§7): which processes have their cwd or an open
//! fd inside a candidate directory? ONE pass over the process table answers
//! for ALL candidates (O(procs), not O(procs × candidates) syscalls); reaper
//! itself is excluded (its own scan fds would self-refuse every candidate).
//!
//! Feasibility and cost were proven unprivileged on all three OSes by the R6
//! measured (/proc 1.4 ms · libproc ~13 ms · Restart Manager ~35 ms/candidate).
//! Windows nuance (ruled at slice 4): RM registers FILES, so the scan-time
//! sweep covers a bounded per-candidate file set; deep cwd-only holders are
//! caught at reap by the tomb-rename gate itself (R7: fails on ANY open
//! handle), whose os errors 5/32 map to LiveProcess refusals.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use camino::Utf8PathBuf;

/// The port: given candidate roots, return per-candidate live pids —
/// `None` where the platform could not establish the fact (fail closed).
pub trait LiveProbe: Sync {
    fn live_pids(&self, dirs: &[Utf8PathBuf]) -> Vec<Option<Vec<u32>>>;
}

/// The platform sweep, or `None` where no implementation exists (the
/// classifier then refuses `Unknown(live_pids)` — never guesses).
pub fn select_probe() -> Option<Box<dyn LiveProbe>> {
    #[cfg(target_os = "linux")]
    {
        Some(Box::new(linux::ProcSweep))
    }
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(macos::LibprocSweep))
    }
    #[cfg(windows)]
    {
        Some(Box::new(windows::RestartManagerSweep))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

/// Shared helper: does `path` sit inside any of `dirs`? Returns the indexes
/// it hits (a process can pin several candidates). Unused on Windows (the
/// RM sweep is per-candidate), hence the cfg.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn hits(dirs: &[Utf8PathBuf], path: &str) -> Vec<usize> {
    dirs.iter()
        .enumerate()
        .filter(|(_, d)| {
            let d = d.as_str();
            path.starts_with(d)
                && (path.len() == d.len() || path.as_bytes().get(d.len()) == Some(&b'/'))
        })
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_matching_is_boundary_aware() {
        let dirs = vec![Utf8PathBuf::from("/w/proj/target")];
        assert_eq!(hits(&dirs, "/w/proj/target"), vec![0]);
        assert_eq!(hits(&dirs, "/w/proj/target/debug/x.o"), vec![0]);
        // NOT a hit: sibling with the same prefix
        assert!(hits(&dirs, "/w/proj/target2/x").is_empty());
    }
}
