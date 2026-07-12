//! macOS leaf — getattrlistbulk(2): name+type+size+mtime+flags+fileid for
//! MANY entries per syscall (~750/call measured, zero per-entry stats).
//! All buffer interpretation lives in `parse` (Miri-covered); this module is
//! only the syscall and the fd.

#![allow(unsafe_code)]

use super::parse::{
    self, ATTR_CMN_FILEID, ATTR_CMN_FLAGS, ATTR_CMN_MODTIME, ATTR_CMN_NAME, ATTR_CMN_OBJTYPE,
    ATTR_CMN_RETURNED_ATTRS, ATTR_FILE_DATALENGTH,
};
use super::{Caps, DirReader, Entry, FileKind};
use camino::Utf8Path;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

// vnode types (fsobj_type_t)
const VREG: u32 = 1;
const VDIR: u32 = 2;
const VLNK: u32 = 5;
/// SF_DATALESS — a dataless (cloud-evicted) placeholder; NEVER materialize.
const SF_DATALESS: u32 = 0x4000_0000;

#[repr(C)]
struct AttrList {
    bitmapcount: u16,
    reserved: u16,
    commonattr: u32,
    volattr: u32,
    dirattr: u32,
    fileattr: u32,
    forkattr: u32,
}

extern "C" {
    // Writes at most `bufsize` bytes into `attrbuf`; returns the number of
    // packed records, 0 at end-of-dir, -1 on error.
    fn getattrlistbulk(
        dirfd: libc::c_int,
        alist: *mut AttrList,
        attrbuf: *mut libc::c_void,
        bufsize: usize,
        options: u64,
    ) -> libc::c_int;
}

pub struct MacDirReader {
    bulk_calls: AtomicU64,
}

impl MacDirReader {
    /// Runtime capability probe (§13): one real call decides the ladder rung.
    pub fn probe() -> Option<Self> {
        let reader = Self {
            bulk_calls: AtomicU64::new(0),
        };
        let probe_dir = std::env::temp_dir();
        let dir = Utf8Path::from_path(&probe_dir)?;
        reader.read_dir(dir).ok()?;
        reader.bulk_calls.store(0, Ordering::Relaxed);
        Some(reader)
    }

    /// Syscall-economy counter (the §10 fitness test reads this).
    pub fn bulk_calls(&self) -> u64 {
        self.bulk_calls.load(Ordering::Relaxed)
    }
}

impl DirReader for MacDirReader {
    fn caps(&self) -> Caps {
        Caps {
            size: true,
            mtime: true,
            ino: true,
            cloud: true,
        }
    }

    fn read_dir(&self, dir: &Utf8Path) -> io::Result<Vec<Entry>> {
        let f = std::fs::File::open(dir)?;
        let fd = f.as_raw_fd();
        // One fstat per DIRECTORY (not per entry) for the device id.
        let dev = f
            .metadata()
            .map(|m| std::os::unix::fs::MetadataExt::dev(&m))
            .unwrap_or(0);

        let mut alist = AttrList {
            bitmapcount: 5, // ATTR_BIT_MAP_COUNT
            reserved: 0,
            commonattr: ATTR_CMN_RETURNED_ATTRS
                | ATTR_CMN_NAME
                | ATTR_CMN_OBJTYPE
                | ATTR_CMN_MODTIME
                | ATTR_CMN_FLAGS
                | ATTR_CMN_FILEID,
            volattr: 0,
            dirattr: 0,
            fileattr: ATTR_FILE_DATALENGTH,
            forkattr: 0,
        };
        let mut buf = vec![0u8; 512 * 1024];
        let mut entries = Vec::new();
        loop {
            // SAFETY: fd is a live directory fd owned by `f`; buf is writable
            // for its full length; alist outlives the call.
            let n =
                unsafe { getattrlistbulk(fd, &mut alist, buf.as_mut_ptr().cast(), buf.len(), 0) };
            self.bulk_calls.fetch_add(1, Ordering::Relaxed);
            match n {
                -1 => return Err(io::Error::last_os_error()),
                0 => break,
                n => {
                    for raw in parse::mac_attrbulk(&buf, n as usize) {
                        let kind = match raw.objtype {
                            VREG => FileKind::File,
                            VDIR => FileKind::Dir,
                            VLNK => FileKind::Symlink,
                            _ => FileKind::Other,
                        };
                        entries.push(Entry {
                            name: raw.name,
                            kind,
                            len: raw.data_length.map(|l| l as u64),
                            mtime: Some(
                                UNIX_EPOCH
                                    + Duration::new(raw.mtime_sec as u64, raw.mtime_nsec as u32),
                            ),
                            ino: Some((dev, raw.file_id)),
                            cloud: Some(raw.flags & SF_DATALESS != 0),
                        });
                    }
                }
            }
        }
        Ok(entries)
    }
}
