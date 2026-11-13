//! SQLite persistence layer.
//!
//! The storage crate knows nothing about eBPF. It accepts validated domain
//! events from [`syscall_core`] and persists them in versioned, indexed tables.

pub mod db;
pub mod error;
pub mod investigation;
pub mod lock;
pub mod migrations;
pub mod verify;

pub use db::{
    EventQuery, NewSession, ProcessSummary, SessionFinish, SessionStatus, SessionSummary, Storage,
};
pub use error::{Result, StorageError};

pub use lock::SessionLock;

pub use verify::{verify_session, verify_session_at_path};

pub use investigation::{
    ActivityFilter, ConnectionActivity, FileActivity, ProcessInstanceEvidence, SessionStats,
    TimelineFilter,
};
