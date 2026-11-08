use thiserror::Error;

/// Errors produced by the core event model and shared helpers.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("unsupported schema version {found}; this build supports version {supported}")]
    UnsupportedSchemaVersion { found: u16, supported: u16 },

    #[error("unknown event type: {0}")]
    UnknownEventType(String),

    #[error("unknown event type id: {0}")]
    UnknownEventTypeId(u16),

    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("unknown recording scope: {0}")]
    UnknownRecordingScope(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
