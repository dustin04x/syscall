//! Identifiers and PID-instance identity.

use std::fs::File;
use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::clock;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Read the Linux boot id, which changes on every boot.
pub fn read_boot_id() -> io::Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "boot id is empty",
        ));
    }
    Ok(value.to_owned())
}

/// Generate a sortable, collision-resistant session id.
///
/// Format: `s-<unix-milliseconds>-<16 hex digits>`.
pub fn new_session_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let counter = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let random = random_u64().unwrap_or_else(|| {
        let fallback = clock::monotonic_now_ns().unwrap_or(0);
        fallback ^ (std::process::id() as u64).rotate_left(32) ^ counter
    });
    format!("s-{millis}-{random:016x}")
}

fn random_u64() -> Option<u64> {
    let mut file = File::open("/dev/urandom").ok()?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).ok()?;
    Some(u64::from_ne_bytes(buf))
}

/// Build the process-instance identity used to survive PID reuse.
///
/// The preferred form is `boot_id:pid:start_time_ticks`, where
/// `start_time_ticks` is field 22 of `/proc/<pid>/stat` (clock ticks since
/// boot). If `/proc` disappeared before it could be read, a monotonic fallback
/// is used and marked with `unknown-`.
pub fn process_instance_id(
    boot_id: &str,
    pid: i32,
    start_time_ticks: Option<u64>,
    fallback_monotonic_ns: u64,
) -> String {
    match start_time_ticks {
        Some(ticks) => format!("{boot_id}:{pid}:{ticks}"),
        None => format!("{boot_id}:{pid}:unknown-{fallback_monotonic_ns}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_unique_and_prefixed() {
        let a = new_session_id();
        let b = new_session_id();
        assert!(a.starts_with("s-"));
        assert!(b.starts_with("s-"));
        assert_ne!(a, b);
    }

    #[test]
    fn process_instance_id_uses_start_time_when_available() {
        assert_eq!(
            process_instance_id("boot", 42, Some(99), 1234),
            "boot:42:99"
        );
    }

    #[test]
    fn process_instance_id_falls_back_when_start_time_is_missing() {
        assert_eq!(
            process_instance_id("boot", 42, None, 1234),
            "boot:42:unknown-1234"
        );
    }

    #[test]
    fn boot_id_is_readable_on_linux() {
        let boot_id = read_boot_id().unwrap();
        assert!(!boot_id.trim().is_empty());
    }
}
