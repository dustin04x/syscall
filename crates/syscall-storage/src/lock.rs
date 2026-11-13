//! Per-session advisory locking for active-recorder ownership.
//!
//! Recovery must never reclaim a session owned by a demonstrably active
//! collector. We use an exclusive `flock(2)` on a per-session lock file:
//! - the recording collector holds the lock for the session lifetime
//! - `flock` is released by the kernel on process exit/crash, so abandoned
//!   sessions become recoverable without trusting PID liveness alone
//! - recovery attempts a non-blocking exclusive lock; if it cannot acquire,
//!   the session is treated as actively owned and is not recovered
//!
//! This is conservative: when liveness/ownership cannot be disproven (lock held)
//! we do not recover. A stale lock file without a holder is recoverable.
//! Lock files live in a private `<db>.locks/` directory next to the database.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::{Result, StorageError};

#[derive(Debug)]
pub struct SessionLock {
    _file: File,
    path: PathBuf,
}

impl SessionLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn lock_dir(db_path: &Path) -> PathBuf {
    let mut name = db_path.as_os_str().to_os_string();
    name.push(".locks");
    PathBuf::from(name)
}

pub fn lock_path(db_path: &Path, session_id: &str) -> PathBuf {
    // Session IDs are already validated tokens; keep filename safe/simple.
    let safe: String = session_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    lock_dir(db_path).join(format!("{safe}.lock"))
}

fn ensure_lock_dir(db_path: &Path) -> Result<PathBuf> {
    let dir = lock_dir(db_path);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    // Best-effort private permissions (same posture as DB directory).
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    Ok(dir)
}

fn open_lock_file(db_path: &Path, session_id: &str) -> Result<(File, PathBuf)> {
    ensure_lock_dir(db_path)?;
    let path = lock_path(db_path, session_id);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    Ok((file, path))
}

/// Acquire an exclusive session lock, blocking until available.
/// Used by the active collector for the lifetime of a recording session.
pub fn acquire_exclusive(db_path: &Path, session_id: &str) -> Result<SessionLock> {
    let (file, path) = open_lock_file(db_path, session_id)?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(StorageError::Io(io::Error::last_os_error()));
    }
    Ok(SessionLock { _file: file, path })
}

/// Try to acquire an exclusive session lock without blocking.
/// Returns `Ok(None)` if an active holder exists.
pub fn try_acquire_exclusive(db_path: &Path, session_id: &str) -> Result<Option<SessionLock>> {
    let (file, path) = open_lock_file(db_path, session_id)?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(Some(SessionLock { _file: file, path }));
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == libc::EWOULDBLOCK => Ok(None),
        _ => Err(StorageError::Io(err)),
    }
}

/// Returns true if the session appears actively owned by a live lock holder.
pub fn is_actively_owned(db_path: &Path, session_id: &str) -> Result<bool> {
    Ok(try_acquire_exclusive(db_path, session_id)?.is_none())
}
