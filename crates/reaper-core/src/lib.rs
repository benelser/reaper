//! reaper-core — the pure domain. No fs, no git, no tui, no unsafe, ~no deps.
//! Everything here is a total function over values; the IO shell
//! (`reaper-scan`) implements the ports this crate defines.

#![forbid(unsafe_code)]

pub mod classify;
pub mod model;
pub mod plan;
pub mod policy;
pub mod ports;
pub mod registry;

pub use classify::{admit, classify, Admitted};
pub use model::{
    Candidate, DetectorId, Disposition, EcosystemId, Facts, GitFacts, HeadState, LockState,
    RefusalReason, SafetyClass,
};
pub use plan::{plan, seal, BoundStep, Identity, ReapPlan, ReapStep, SealedPlan};
pub use policy::{IdlePolicy, Policy};
pub use ports::GitProbe;
pub use registry::{Detector, DetectorKind, Marker, Match, Registry, RulesetError};
