//! Minimal async-signal-safe shutdown handling.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

/// 0 = no request; otherwise the signal number (SIGINT/SIGTERM).
static SHUTDOWN_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn handle_signal(signal: libc::c_int) {
    // Only an atomic store: safe from a signal handler.
    // Keep the first signal to preserve stable exit-code semantics.
    let _ = SHUTDOWN_SIGNAL.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
}

/// Install SIGINT/SIGTERM handlers. Safe to call more than once.
pub fn install() -> io::Result<()> {
    SHUTDOWN_SIGNAL.store(0, Ordering::SeqCst);
    let handler = handle_signal as *const () as libc::sighandler_t;
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: `handler` has the correct C signature and only touches an
        // atomic. `signal` is process-wide and idempotent for our use.
        let previous = unsafe { libc::signal(signal, handler) };
        if previous == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn reset() {
    SHUTDOWN_SIGNAL.store(0, Ordering::SeqCst);
}

pub fn requested() -> bool {
    SHUTDOWN_SIGNAL.load(Ordering::SeqCst) != 0
}

/// The signal that requested shutdown, if any.
pub fn requested_signal() -> Option<i32> {
    match SHUTDOWN_SIGNAL.load(Ordering::SeqCst) {
        0 => None,
        signal => Some(signal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_clears_flag() {
        reset();
        assert!(!requested());
        assert_eq!(requested_signal(), None);
    }

    #[test]
    fn handler_records_first_signal() {
        reset();
        handle_signal(libc::SIGINT);
        assert!(requested());
        assert_eq!(requested_signal(), Some(libc::SIGINT));
        // First signal wins for stable exit semantics.
        handle_signal(libc::SIGTERM);
        assert_eq!(requested_signal(), Some(libc::SIGINT));
        reset();
    }
}
