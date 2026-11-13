use std::path::PathBuf;

use serde::Serialize;
use syscall_analysis::AnalysisError;
use syscall_storage::{Storage, StorageError};

#[derive(Debug, thiserror::Error)]
pub enum DesktopError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("database does not exist: {}", .0.display())]
    DatabaseNotFound(PathBuf),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("analysis error: {0}")]
    Analysis(#[from] AnalysisError),
    #[error("export error: {0}")]
    Export(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl DesktopError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::DatabaseNotFound(_) => "DATABASE_NOT_FOUND",
            Self::SessionNotFound(_) => "SESSION_NOT_FOUND",
            Self::Storage(_) => "STORAGE_ERROR",
            Self::Analysis(_) => "ANALYSIS_ERROR",
            Self::Export(_) => "EXPORT_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
}

impl From<DesktopError> for CommandError {
    fn from(value: DesktopError) -> Self {
        Self {
            code: value.code(),
            message: value.to_string(),
        }
    }
}

pub fn open_read_only(path: &PathBuf) -> Result<Storage, DesktopError> {
    if !path.exists() {
        return Err(DesktopError::DatabaseNotFound(path.clone()));
    }
    Ok(Storage::open_read_only(path)?)
}
