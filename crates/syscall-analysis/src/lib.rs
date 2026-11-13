//! Explainable behavioral analysis over persisted SYSCALL evidence.
//!
//! This crate never records, executes recorded commands, or mutates a database.
//! It consumes bounded, deterministic read-only queries and emits findings whose
//! supporting events are referenced by persisted row ID.

mod engine;
mod evidence;
mod rules;

pub mod config;

pub use config::{
    AnalysisConfig, ALL_RULE_IDS, DEFAULT_SENSITIVE_PATHS, DEFAULT_TEMPORARY_DIRECTORIES,
    RULE_FS_NET_CORRELATION, RULE_REPEATED_CONNECT, RULE_SENSITIVE_OPEN, RULE_SHELL_CHAIN,
    RULE_SHORT_LIVED_NET, RULE_TEMP_EXEC,
};
pub use engine::{analyze, AnalysisOptions};

use syscall_storage::StorageError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AnalysisError>;

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("unknown rule {0:?}; expected one of: {1}")]
    UnknownRule(String, String),
    #[error("invalid analysis configuration: {0}")]
    InvalidConfig(String),
    #[error("analysis evidence could not be read safely: {0}")]
    Evidence(String),
}
