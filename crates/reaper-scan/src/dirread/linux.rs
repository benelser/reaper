//! Linux leaf — getdents64(2): names + d_type batched (~750 entries/call, measured);
//! size/mtime are honestly ABSENT from `Caps` — the fill pass pays per-entry
//! where a consumer needs them (io_uring pipelining is the priced upgrade,
//! judged by the bench when it lands). DT_UNKNOWN filesystems (XFS ftype=0,
//! reproduced on a real XFS ftype=0 mount) surface as `FileKind::Other` for the fill
//! to classify.

#![allow(unsafe_code)]

use super::parse;
use super::{Caps, DirReader, Entry, FileKind};
use camino::Utf8Path;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct LinuxDirReader {
    bulk_calls: AtomicU64,
}

impl LinuxDirReader {
    /// Runtime capability probe (§13): getdents64 is ancient, but the ladder
    /// never assumes — one real call decides.
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

impl DirReader for LinuxDirReader {
    fn caps(&self) -> Caps {
        // Honest: the bulk read gives type+ino only. No cloud placeholders
        // exist on Linux, so `cloud` is establishable as a constant false.
        Caps {
            size: false,
            mtime: false,
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

        let mut buf = vec![0u8; 512 * 1024];
        let mut entries = Vec::new();
        loop {
            // SAFETY: fd is a live directory fd owned by `f`; buf is writable
            // for its full length.
            let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
            self.bulk_calls.fetch_add(1, Ordering::Relaxed);
            match n {
                -1 => return Err(io::Error::last_os_error()),
                0 => break,
                n => {
                    for raw in parse::linux_dirents(&buf[..n as usize]) {
                        let kind = match raw.d_type {
                            libc::DT_REG => FileKind::File,
                            libc::DT_DIR => FileKind::Dir,
                            libc::DT_LNK => FileKind::Symlink,
                            // DT_UNKNOWN and exotic types: the fill classifies.
                            _ => FileKind::Other,
                        };
                        entries.push(Entry {
                            name: raw.name,
                            kind,
                            len: None,
                            mtime: None,
                            ino: Some((dev, raw.ino)),
                            cloud: Some(false),
                        });
                    }
                }
            }
        }
        Ok(entries)
    }
}
