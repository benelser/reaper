//! reaper-scan — the IO shell: the `DirReader` port's backends and the
//! portable rayon orchestrator (zero `cfg` above the port; the per-OS fast
//! leaves are additive impls behind it). All `unsafe` lives in the
//! `dirread::{macos,linux,windows}` leaves — denied everywhere else.

#![deny(unsafe_code)]

pub mod deleter;
pub mod dirread;
pub mod gitprobe;
pub mod orchestrator;
pub mod prober;
pub mod sweep;

pub use deleter::{Deleter, InstanceLock, ManifestEvent, StepOutcome};
pub use dirread::{select_reader, Caps, DirReader, Entry, FileKind, StdDirReader};
pub use gitprobe::GixProbe;
pub use orchestrator::{scan, ScanEvent, ScanTotals};
pub use prober::{gather_facts, Clock, Prober, SystemClock};
pub use sweep::{select_probe, LiveProbe};
