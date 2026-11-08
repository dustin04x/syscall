//! Default storage locations.
//!
//! When `syscall record` is started through `sudo`, the process initially runs
//! as root so it can load BPF. The default database must still live in the
//! invoking user's home, not `/root`, because the collector drops privileges
//! before writing the database and later `syscall inspect` runs as the user.

use std::ffi::{CStr, CString};
use std::path::PathBuf;

/// Return the invoking user's home when the process is root via `sudo`.
fn sudo_user_home() -> Option<PathBuf> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let user = std::env::var("SUDO_USER").ok()?;
    if user.is_empty() || user == "root" {
        return None;
    }
    home_for_user(&user)
}

fn home_for_user(user: &str) -> Option<PathBuf> {
    let user = CString::new(user).ok()?;
    let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];

    // SAFETY: all pointers are valid for the duration of the call. On success
    // `result` points at `passwd`, whose strings point into `buffer`.
    let rc = unsafe {
        libc::getpwnam_r(
            user.as_ptr(),
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: `result` is non-null and initialized on success.
    let passwd = unsafe { passwd.assume_init() };
    if passwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir is a NUL-terminated string owned by the passwd record.
    let home = unsafe { CStr::from_ptr(passwd.pw_dir) };
    let home = home.to_str().ok()?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home))
}

/// Home directory that should own recorded sessions.
pub fn invoking_home() -> Option<PathBuf> {
    if let Some(home) = sudo_user_home() {
        return Some(home);
    }
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Default SYSCALL data directory.
pub fn default_data_dir() -> PathBuf {
    if sudo_user_home().is_some() {
        // Do not trust root's XDG_DATA_HOME when running through sudo.
        return invoking_home()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local/share/syscall");
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("syscall");
    }
    invoking_home()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/share/syscall")
}

/// Default SQLite database path.
pub fn default_db_path() -> PathBuf {
    default_data_dir().join("syscall.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_db_path_ends_with_expected_name() {
        assert_eq!(
            default_db_path().file_name().unwrap().to_str().unwrap(),
            "syscall.db"
        );
    }

    #[test]
    fn default_data_dir_ends_with_syscall() {
        assert_eq!(
            default_data_dir().file_name().unwrap().to_str().unwrap(),
            "syscall"
        );
    }
}
