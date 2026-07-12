//! Windows sweep — Restart Manager over a BOUNDED per-candidate file set
//! (R6: unprivileged, ~35 ms per session). RM registers files, so deep
//! cwd-only holders can evade the scan-time sweep — the reap-time
//! tomb-rename is the authoritative gate there (R7: fails on ANY open
//! handle, share-delete included; os 5/32 map to LiveProcess refusals).

#![allow(unsafe_code)]

use super::LiveProbe;
use camino::Utf8PathBuf;
use std::collections::BTreeSet;

/// How many top-level files per candidate to register (bounded, §7).
const SAMPLE_FILES: usize = 24;

#[repr(C)]
#[derive(Clone, Copy)]
struct RmUniqueProcess {
    pid: u32,
    start_time: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmProcessInfo {
    process: RmUniqueProcess,
    app_name: [u16; 256],
    svc_name: [u16; 64],
    app_type: i32,
    app_status: u32,
    ts_session: u32,
    restartable: i32,
}

#[link(name = "rstrtmgr", kind = "raw-dylib")]
extern "system" {
    fn RmStartSession(session: *mut u32, flags: u32, key: *mut u16) -> u32;
    fn RmRegisterResources(
        session: u32,
        n_files: u32,
        files: *const *const u16,
        n_apps: u32,
        apps: *const core::ffi::c_void,
        n_svcs: u32,
        svcs: *const *const u16,
    ) -> u32;
    fn RmGetList(
        session: u32,
        needed: *mut u32,
        n: *mut u32,
        list: *mut RmProcessInfo,
        reboot: *mut u32,
    ) -> u32;
    fn RmEndSession(session: u32) -> u32;
}

pub struct RestartManagerSweep;

impl LiveProbe for RestartManagerSweep {
    fn live_pids(&self, dirs: &[Utf8PathBuf]) -> Vec<Option<Vec<u32>>> {
        let me = std::process::id();
        dirs.iter().map(|d| probe_one(d, me)).collect()
    }
}

fn probe_one(dir: &Utf8PathBuf, me: u32) -> Option<Vec<u32>> {
    // Bounded sample of top-level FILES only — RM rejects directory paths
    // as resources (CI caught the dir-registration attempt failing).
    let mut paths: Vec<Vec<u16>> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten().take(SAMPLE_FILES) {
            if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                paths.push(wide(&e.path().to_string_lossy()));
            }
        }
    }
    if paths.is_empty() {
        // Nothing registrable: no evidence either way at scan time; the
        // reap-time rename gate remains authoritative. Report no holders.
        return Some(Vec::new());
    }
    let ptrs: Vec<*const u16> = paths.iter().map(|p| p.as_ptr()).collect();

    let mut session = 0u32;
    let mut key = [0u16; 65]; // CCH_RM_SESSION_KEY + 1
    let mut pids = BTreeSet::new();
    // SAFETY: out-params live across the calls; `paths`/`ptrs` outlive
    // RmRegisterResources; the session is always ended.
    unsafe {
        if RmStartSession(&mut session, 0, key.as_mut_ptr()) != 0 {
            return None;
        }
        let ok = RmRegisterResources(
            session,
            ptrs.len() as u32,
            ptrs.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
        ) == 0;
        if ok {
            let mut needed = 0u32;
            let mut n = 32u32;
            let mut list = [std::mem::zeroed::<RmProcessInfo>(); 32];
            let mut reboot = 0u32;
            if RmGetList(session, &mut needed, &mut n, list.as_mut_ptr(), &mut reboot) == 0 {
                for info in &list[..(n as usize).min(list.len())] {
                    if info.process.pid != me {
                        pids.insert(info.process.pid);
                    }
                }
            } else {
                RmEndSession(session);
                return None;
            }
        }
        RmEndSession(session);
        if !ok {
            return None;
        }
    }
    Some(pids.into_iter().collect())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
