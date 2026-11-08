//! Kernel-side collection and recording orchestration.

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unused,
    dead_code,
    unsafe_code
)]
pub mod bpf {
    use libbpf_rs::libbpf_sys;

    include!(concat!(env!("OUT_DIR"), "/syscall.skel.rs"));
}

pub mod collector;
pub mod environment;
pub mod event_decoder;
pub mod privilege;
pub mod procfs;
pub mod scope;
pub mod signal;
pub mod writer;

pub use collector::{
    record, CollectorError, RecordReport, RecordRequest, RejectionBreakdown, TargetOutcome,
};
pub use environment::EnvironmentReport;
pub use privilege::PrivilegeStatus;
pub use scope::ScopeTracker;
