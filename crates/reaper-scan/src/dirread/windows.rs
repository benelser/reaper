//! Windows leaf — NtQueryDirectoryFile(FileIdBothDirectoryInformation):
//! size + timestamps + attributes inline, batched (~380 entries/call measured).
//! Reparse points (junctions/symlinks) and cloud-recall flags are decidable
//! from the listing alone (verified on real junctions) — never descended, never opened.

#![allow(unsafe_code)]

use super::parse;
use super::{Caps, DirReader, Entry, FileKind};
use camino::Utf8Path;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// Cloud placeholders (§13): OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS.
const CLOUD_ATTRS: u32 = 0x1000 | 0x0004_0000 | 0x0040_0000;
const FILE_ID_BOTH_DIRECTORY_INFORMATION: i32 = 37;
const STATUS_SUCCESS: i32 = 0;
const STATUS_NO_MORE_FILES: i32 = 0x8000_0006_u32 as i32;
/// FILETIME epoch (1601-01-01) → Unix epoch, in 100 ns ticks.
const EPOCH_DELTA_100NS: i64 = 116_444_736_000_000_000;

#[repr(C)]
struct IoStatusBlock {
    status: i32,
    information: usize,
}

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtQueryDirectoryFile(
        file_handle: isize,
        event: isize,
        apc_routine: *mut core::ffi::c_void,
        apc_context: *mut core::ffi::c_void,
        io_status_block: *mut IoStatusBlock,
        file_information: *mut core::ffi::c_void,
        length: u32,
        file_information_class: i32,
        return_single_entry: u8,
        file_name: *mut core::ffi::c_void,
        restart_scan: u8,
    ) -> i32;
}

#[repr(C)]
struct ByHandleFileInformation {
    attributes: u32,
    creation: [u32; 2],
    last_access: [u32; 2],
    last_write: [u32; 2],
    volume_serial: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    fn GetFileInformationByHandle(handle: isize, info: *mut ByHandleFileInformation) -> i32;
}

/// Real file identity — (volume serial, file index). Criterion-1
/// load-bearing: the (dev,ino) plan binding detects a tree swapped after
/// planning; a placeholder here let the drift e2e reap a swapped tree.
pub fn file_identity(path: &Utf8Path) -> Option<reaper_core::Identity> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .ok()?;
    // SAFETY: live handle owned by `f`; info is a plain-data out-param.
    unsafe {
        let mut info = std::mem::zeroed::<ByHandleFileInformation>();
        if GetFileInformationByHandle(f.as_raw_handle() as isize, &mut info) == 0 {
            return None;
        }
        Some(reaper_core::Identity {
            dev: info.volume_serial as u64,
            ino: ((info.index_high as u64) << 32) | info.index_low as u64,
            // FILETIME ticks; only equality matters and both sides use this fn.
            mtime_ns: ((info.last_write[1] as u64) << 32) | info.last_write[0] as u64,
        })
    }
}

pub struct WinDirReader {
    bulk_calls: AtomicU64,
}

impl WinDirReader {
    /// Runtime capability probe (§13): one real call decides the ladder rung.
    pub fn probe() -> Option<Self> {
        let reader = Self {
            bulk_calls: AtomicU64::new(0),
        };
        let tmp = std::env::temp_dir();
        let dir = Utf8Path::from_path(&tmp)?;
        reader.read_dir(dir).ok()?;
        reader.bulk_calls.store(0, Ordering::Relaxed);
        Some(reader)
    }

    /// Syscall-economy counter (the §10 fitness test reads this).
    pub fn bulk_calls(&self) -> u64 {
        self.bulk_calls.load(Ordering::Relaxed)
    }
}

fn filetime_to_systemtime(t: i64) -> std::time::SystemTime {
    let unix_100ns = t - EPOCH_DELTA_100NS;
    if unix_100ns < 0 {
        return UNIX_EPOCH;
    }
    UNIX_EPOCH
        + Duration::new(
            (unix_100ns / 10_000_000) as u64,
            ((unix_100ns % 10_000_000) * 100) as u32,
        )
}

impl DirReader for WinDirReader {
    fn caps(&self) -> Caps {
        // ino=false honestly: FileId is inline but the volume id is not; the
        // (dev,ino) plan binding stats its specific candidate at reap time.
        Caps {
            size: true,
            mtime: true,
            ino: false,
            cloud: true,
        }
    }

    fn read_dir(&self, dir: &Utf8Path) -> io::Result<Vec<Entry>> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)?;
        let handle = f.as_raw_handle() as isize;

        let mut buf = vec![0u8; 512 * 1024];
        let mut entries = Vec::new();
        let mut restart: u8 = 1;
        loop {
            let mut iosb = IoStatusBlock {
                status: 0,
                information: 0,
            };
            // SAFETY: handle is a live directory handle owned by `f` (backup
            // semantics); buf is writable for its full length; the call is
            // synchronous (no event/APC), so iosb and buf outlive completion.
            let status = unsafe {
                NtQueryDirectoryFile(
                    handle,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut iosb,
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    FILE_ID_BOTH_DIRECTORY_INFORMATION,
                    0,
                    std::ptr::null_mut(),
                    restart,
                )
            };
            restart = 0;
            self.bulk_calls.fetch_add(1, Ordering::Relaxed);
            if status == STATUS_NO_MORE_FILES {
                break;
            }
            if status != STATUS_SUCCESS {
                return Err(io::Error::other(format!(
                    "NtQueryDirectoryFile NTSTATUS {status:#x}"
                )));
            }
            // information = bytes written; the chain is 0-terminated, so an
            // unset information degrades to walking the full buffer safely.
            let filled = if iosb.information == 0 {
                buf.len()
            } else {
                iosb.information.min(buf.len())
            };
            for raw in parse::win_id_both(&buf[..filled]) {
                let kind = if raw.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    FileKind::Symlink // reparse class: junction/symlink — never descend
                } else if raw.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    FileKind::Dir
                } else {
                    FileKind::File
                };
                entries.push(Entry {
                    name: raw.name,
                    kind,
                    len: Some(raw.end_of_file as u64),
                    mtime: Some(filetime_to_systemtime(raw.last_write_time)),
                    ino: None,
                    cloud: Some(raw.attributes & CLOUD_ATTRS != 0),
                });
            }
        }
        Ok(entries)
    }
}
