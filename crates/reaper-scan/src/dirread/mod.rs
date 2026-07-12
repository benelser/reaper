//! The platform seam — exactly ONE directory read wide (SPEC §6). A backend
//! declares `Caps` once; entries carry attrs as negotiated `Option`s; the
//! orchestrator never sees a platform. Fast leaves are additive behind this
//! port; `StdDirReader` is the floor that never goes away.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod parse;
#[cfg(windows)]
pub mod windows;

use camino::Utf8Path;
use std::io;
use std::time::SystemTime;

/// What THIS backend hands back cheaply, declared once (data, not guesswork).
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub size: bool,
    pub mtime: bool,
    pub ino: bool,
    /// Backend reports cloud-placeholder (dataless/offline) status inline —
    /// §13: count it, refuse it, NEVER materialize it.
    pub cloud: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Dir,
    /// Symlinks and reparse points are counted, NEVER descended (§13).
    Symlink,
    Other,
}

/// One directory entry. A field is `Some` iff `Caps` says the backend gave
/// it for free — the fill pass completes only what's missing.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub kind: FileKind,
    /// Logical size. (Allocated-size refinement is a priced v2 item.)
    pub len: Option<u64>,
    pub mtime: Option<SystemTime>,
    pub ino: Option<(u64, u64)>,
    pub cloud: Option<bool>,
}

pub trait DirReader: Sync {
    fn caps(&self) -> Caps;
    fn read_dir(&self, dir: &Utf8Path) -> io::Result<Vec<Entry>>;
}

/// Pick the best backend for this machine, falling down the ladder to the
/// std floor if the fast primitive is unavailable (§13 runtime capability).
pub fn select_reader() -> Box<dyn DirReader> {
    #[cfg(target_os = "macos")]
    if let Some(r) = macos::MacDirReader::probe() {
        return Box::new(r);
    }
    #[cfg(target_os = "linux")]
    if let Some(r) = linux::LinuxDirReader::probe() {
        return Box::new(r);
    }
    #[cfg(windows)]
    if let Some(r) = windows::WinDirReader::probe() {
        return Box::new(r);
    }
    Box::new(StdDirReader)
}

/// The day-1 baseline, correct on all three OSes. Reports only what the
/// dirent gives free (type); everything else is the fill pass's job —
/// declared honestly via `Caps`.
pub struct StdDirReader;

impl DirReader for StdDirReader {
    fn caps(&self) -> Caps {
        Caps {
            size: false,
            mtime: false,
            ino: false,
            cloud: false,
        }
    }

    fn read_dir(&self, dir: &Utf8Path) -> io::Result<Vec<Entry>> {
        let rd = std::fs::read_dir(dir)?;
        Ok(rd
            .filter_map(Result::ok)
            .map(|e| {
                let kind = match e.file_type() {
                    Ok(t) if t.is_symlink() => FileKind::Symlink,
                    Ok(t) if t.is_dir() => FileKind::Dir,
                    Ok(t) if t.is_file() => FileKind::File,
                    _ => FileKind::Other,
                };
                Entry {
                    name: e.file_name().to_string_lossy().into_owned(),
                    kind,
                    len: None,
                    mtime: None,
                    ino: None,
                    cloud: None,
                }
            })
            .collect())
    }
}
