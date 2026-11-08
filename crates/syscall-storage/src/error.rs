use syscall_core::CoreError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("event validation failed: {0}")]
    InvalidEvent(#[from] CoreError),

    #[error("database schema version {found} is newer than supported version {supported}")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },

    #[error("database is missing the SYSCALL schema; run `syscall record` to initialize it")]
    MissingSchema,

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("corrupt or unsupported database value: {0}")]
    Data(String),

    #[error("invalid database path: {0}")]
    InvalidPath(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;
