//! macOS sweep — libproc cwd + per-vnode-fd paths (R6: unprivileged, ~13 ms
//! for a full process table; buffer offsets validated empirically by the
//! against real processes and re-validated by this module's self-detection test).

#![allow(unsafe_code)]

use super::{hits, LiveProbe};
use camino::Utf8PathBuf;
use libc::{c_int, c_void};
use std::collections::BTreeSet;

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDVNODEPATHINFO: c_int = 9;
const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDFDVNODEPATHINFO: c_int = 2;
const PROX_FDTYPE_VNODE: u32 = 1;
// sys/proc_info.h layout arithmetic (empirically validated): vinfo_stat = 136,
// vnode_info = 152, MAXPATHLEN = 1024, vnode_info_path = 1176,
// proc_fileinfo = 24.
const VNODEPATHINFO_LEN: usize = 2 * 1176;
const CDIR_PATH_OFF: usize = 152;
const FDINFOWITHPATH_LEN: usize = 24 + 1176;
const FD_PATH_OFF: usize = 24 + 152;

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

extern "C" {
    fn proc_listpids(t: u32, ti: u32, buf: *mut c_void, size: c_int) -> c_int;
    fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buf: *mut c_void, size: c_int) -> c_int;
    fn proc_pidfdinfo(pid: c_int, fd: c_int, flavor: c_int, buf: *mut c_void, size: c_int)
        -> c_int;
}

fn cstr_at(buf: &[u8], off: usize) -> Option<&str> {
    let end = buf[off..].iter().position(|&b| b == 0)? + off;
    std::str::from_utf8(&buf[off..end]).ok()
}

pub struct LibprocSweep;

impl LiveProbe for LibprocSweep {
    fn live_pids(&self, dirs: &[Utf8PathBuf]) -> Vec<Option<Vec<u32>>> {
        let me = std::process::id() as i32;
        let mut per_dir: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); dirs.len()];

        // SAFETY: sized-query then fill, per libproc convention.
        let n = unsafe { proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
        if n <= 0 {
            return vec![None; dirs.len()];
        }
        let mut pids = vec![0i32; n as usize / 4 + 64];
        // SAFETY: pids is writable for the byte length passed.
        let n = unsafe {
            proc_listpids(
                PROC_ALL_PIDS,
                0,
                pids.as_mut_ptr().cast(),
                (pids.len() * 4) as i32,
            )
        };
        pids.truncate((n.max(0) as usize) / 4);

        for &pid in &pids {
            if pid <= 0 || pid == me {
                continue;
            }
            let mut buf = vec![0u8; VNODEPATHINFO_LEN];
            // SAFETY: buf writable for its declared length.
            let r = unsafe {
                proc_pidinfo(
                    pid,
                    PROC_PIDVNODEPATHINFO,
                    0,
                    buf.as_mut_ptr().cast(),
                    buf.len() as i32,
                )
            };
            if r <= 0 {
                continue; // other user / zombie: not visible, not claimable
            }
            if let Some(cwd) = cstr_at(&buf, CDIR_PATH_OFF) {
                for i in hits(dirs, cwd) {
                    per_dir[i].insert(pid as u32);
                }
            }
            // SAFETY: sized-query for the fd list.
            let sz = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
            if sz <= 0 {
                continue;
            }
            let cnt = sz as usize / std::mem::size_of::<ProcFdInfo>();
            let mut fds = vec![
                ProcFdInfo {
                    proc_fd: 0,
                    proc_fdtype: 0
                };
                cnt + 32
            ];
            // SAFETY: fds writable for the byte length passed.
            let got = unsafe {
                proc_pidinfo(
                    pid,
                    PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr().cast(),
                    (fds.len() * std::mem::size_of::<ProcFdInfo>()) as i32,
                )
            };
            fds.truncate((got.max(0) as usize) / std::mem::size_of::<ProcFdInfo>());
            for fd in &fds {
                if fd.proc_fdtype != PROX_FDTYPE_VNODE {
                    continue;
                }
                let mut fb = vec![0u8; FDINFOWITHPATH_LEN];
                // SAFETY: fb writable for its declared length.
                let r = unsafe {
                    proc_pidfdinfo(
                        pid,
                        fd.proc_fd,
                        PROC_PIDFDVNODEPATHINFO,
                        fb.as_mut_ptr().cast(),
                        fb.len() as i32,
                    )
                };
                if r <= 0 {
                    continue;
                }
                if let Some(p) = cstr_at(&fb, FD_PATH_OFF) {
                    for i in hits(dirs, p) {
                        per_dir[i].insert(pid as u32);
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
