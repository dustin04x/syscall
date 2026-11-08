//! Shared domain model for SYSCALL.
//!
//! This crate deliberately has no dependency on eBPF, SQLite, or the CLI. It
//! defines the versioned event schema, process identity rules, clock helpers,
//! and the recording-scope vocabulary used by every other crate.

pub mod clock;
pub mod error;
pub mod event;
pub mod ids;
pub mod paths;
pub mod scope;
pub mod timefmt;

pub use error::{CoreError, Result};
pub use event::{
    Event, EventPayload, EventType, ProcessMetadata, COMM_LEN, MAX_FILENAME_LEN, SCHEMA_VERSION,
};
pub use scope::RecordingScope;
