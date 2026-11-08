//! SQLite persistence layer.
//!
//! The storage crate knows nothing about eBPF. It accepts validated domain
//! events from [`syscall_core`] and persists them in versioned, indexed tables.

pub mod db;
pub mod error;
pub mod migrations;

pub use db::{
    EventQuery, NewSession, ProcessSummary, SessionFinish, SessionStatus, SessionSummary, Storage,
};
pub use error::{Result, StorageError};
