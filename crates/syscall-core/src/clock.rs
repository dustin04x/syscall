//! Clock helpers.
//!
//! Kernel events carry `bpf_ktime_get_ns()`, which is CLOCK_MONOTONIC
//! nanoseconds since boot. We derive a wall-clock timestamp with a single
//! offset captured when the collector starts:
//!
//! `wall_offset_ns = CLOCK_REALTIME - CLOCK_MONOTONIC`
//!
//! The offset is intentionally captured once per session. A later NTP step or
//! manual clock change can make derived wall-clock timestamps differ from a
//! fresh `clock_gettime(CLOCK_REALTIME)` call; monotonic timestamps remain
//! internally consistent and are the preferred ordering key for correlation.

use std::io;

fn clock_gettime(clock: libc::clockid_t) -> io::Result<(i64, i64)> {
    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `ts` points to valid, writable memory. `clock_gettime` is
    // thread-safe and does not retain the pointer.
    let rc = unsafe { libc::clock_gettime(clock, ts.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `clock_gettime` returned 0, so it initialized `ts`.
    let ts = unsafe { ts.assume_init() };
    Ok((ts.tv_sec, ts.tv_nsec))
}

fn to_ns(secs: i64, nanos: i64) -> io::Result<i64> {
    let value = (secs as i128) * 1_000_000_000 + (nanos as i128);
    i64::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "timestamp does not fit in i64 nanoseconds",
        )
    })
}

/// Current CLOCK_MONOTONIC value in nanoseconds since boot.
pub fn monotonic_now_ns() -> io::Result<u64> {
    let (secs, nanos) = clock_gettime(libc::CLOCK_MONOTONIC)?;
    let ns = to_ns(secs, nanos)?;
    u64::try_from(ns).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "monotonic timestamp is negative",
        )
    })
}

/// Current CLOCK_REALTIME value in nanoseconds since the Unix epoch.
pub fn realtime_now_ns() -> io::Result<i64> {
    let (secs, nanos) = clock_gettime(libc::CLOCK_REALTIME)?;
    to_ns(secs, nanos)
}

/// Compute `CLOCK_REALTIME - CLOCK_MONOTONIC` in nanoseconds.
pub fn wall_offset_ns() -> io::Result<i64> {
    let realtime = realtime_now_ns()?;
    let monotonic = monotonic_now_ns()?;
    realtime
        .checked_sub(i64::try_from(monotonic).unwrap_or(i64::MAX))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "clock offset overflow"))
}

/// Convert a kernel monotonic timestamp into wall-clock nanoseconds.
pub fn wall_from_monotonic(offset_ns: i64, monotonic_ns: u64) -> i64 {
    let monotonic = i64::try_from(monotonic_ns).unwrap_or(i64::MAX);
    offset_ns.saturating_add(monotonic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_from_monotonic_adds_offset() {
        assert_eq!(wall_from_monotonic(1_000, 2_000), 3_000);
    }

    #[test]
    fn wall_from_monotonic_saturates() {
        assert_eq!(wall_from_monotonic(i64::MAX, u64::MAX), i64::MAX);
    }

    #[test]
    fn clocks_are_available() {
        assert!(monotonic_now_ns().unwrap() > 0);
        assert!(realtime_now_ns().unwrap() > 0);
        let offset = wall_offset_ns().unwrap();
        let derived = wall_from_monotonic(offset, monotonic_now_ns().unwrap());
        let now = realtime_now_ns().unwrap();
        let delta = (derived - now).abs();
        assert!(delta < 1_000_000_000, "clock offset delta was {delta} ns");
    }
}
