//! Small, dependency-free timestamp formatting helpers.
//!
//! All wall-clock output is UTC and explicitly marked as such. Forensic data
//! should not silently change representation based on the analyst's locale.

/// Format nanoseconds since the Unix epoch as `YYYY-MM-DD HH:MM:SS.nnnnnnnnn UTC`.
pub fn format_unix_ns_utc(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = sod / 3_600;
    let minute = (sod % 3_600) / 60;
    let second = sod % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{nanos:09} UTC")
}

/// Format a duration in nanoseconds for human display.
pub fn format_duration_ns(ns: i64) -> String {
    if ns < 0 {
        return format!("-{}", format_duration_ns(ns.saturating_neg()));
    }
    if ns < 1_000 {
        return format!("{ns}ns");
    }
    if ns < 1_000_000_000 {
        return format!("{:.3}ms", ns as f64 / 1_000_000.0);
    }
    let secs = ns as f64 / 1_000_000_000.0;
    if secs < 60.0 {
        return format!("{secs:.3}s");
    }
    let minutes = (secs / 60.0).floor();
    let remainder = secs - minutes * 60.0;
    if minutes < 60.0 {
        return format!("{minutes:.0}m{remainder:.0}s");
    }
    let hours = (minutes / 60.0).floor();
    let min_remainder = minutes - hours * 60.0;
    format!("{hours:.0}h{min_remainder:.0}m")
}

/// Howard Hinnant's `civil_from_days` algorithm, adapted to i64 days.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(format_unix_ns_utc(0), "1970-01-01 00:00:00.000000000 UTC");
    }

    #[test]
    fn formats_a_known_timestamp() {
        // 2000-01-01T00:00:00Z
        assert_eq!(
            format_unix_ns_utc(946_684_800_000_000_000),
            "2000-01-01 00:00:00.000000000 UTC"
        );
    }

    #[test]
    fn formats_fractional_nanoseconds() {
        assert_eq!(
            format_unix_ns_utc(1_000_000_001),
            "1970-01-01 00:00:01.000000001 UTC"
        );
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_duration_ns(999), "999ns");
        assert_eq!(format_duration_ns(1_500_000), "1.500ms");
        assert_eq!(format_duration_ns(5_001_000_000), "5.001s");
        assert_eq!(format_duration_ns(65_000_000_000), "1m5s");
        assert_eq!(
            format_duration_ns(i64::MIN),
            format!("-{}", format_duration_ns(i64::MAX))
        );
    }
}
