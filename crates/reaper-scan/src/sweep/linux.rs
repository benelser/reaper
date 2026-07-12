//! Linux sweep — /proc readlinks, no unsafe, no privileges (R6: own-user
//! processes fully visible; other users' EACCES entries are simply not ours
//! to see and not ours to claim — but they also can't be building into our
//! user's build dirs in any common setup).

use super::{hits, LiveProbe};
use camino::Utf8PathBuf;
use std::collections::BTreeSet;

pub struct ProcSweep;

impl LiveProbe for ProcSweep {
    fn live_pids(&self, dirs: &[Utf8PathBuf]) -> Vec<Option<Vec<u32>>> {
        let me = std::process::id();
        let mut per_dir: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); dirs.len()];
        let Ok(proc_entries) = std::fs::read_dir("/proc") else {
            return vec![None; dirs.len()];
        };
        for e in proc_entries.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if pid == me {
                continue;
            }
            if let Ok(cwd) = std::fs::read_link(format!("/proc/{pid}/cwd")) {
                for i in hits(dirs, &cwd.to_string_lossy()) {
                    per_dir[i].insert(pid);
                }
            }
            if let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
                for fd in fds.flatten() {
                    if let Ok(p) = std::fs::read_link(fd.path()) {
                        for i in hits(dirs, &p.to_string_lossy()) {
                            per_dir[i].insert(pid);
                        }
                    }
                }
            }
        }
        per_dir
            .into_iter()
            .map(|s| Some(s.into_iter().collect()))
            .collect()
    }
}
