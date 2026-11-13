//! Command line interface for SYSCALL.
//!
//! The CLI is deliberately thin: it parses arguments, opens storage read-only
//! for inspection commands, and delegates recording to [`syscall_collector`].
//! All rendering lives in [`render`] so output is testable without a terminal.

pub mod cli;
pub mod render;

/// Backwards-compatible export namespace; implementation lives in `syscall-export`.
pub use syscall_export as export;

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use syscall_analysis::{analyze, AnalysisConfig, AnalysisOptions};
use syscall_collector::{record, RecordRequest};
use syscall_core::paths::default_db_path;
use syscall_storage::{ActivityFilter, EventQuery, SessionStatus, Storage, TimelineFilter};

use crate::cli::{Cli, Command, ExportFormat};

/// Exit code semantics for `syscall record`.
///
/// Recording itself succeeded when this function is called. The exit code
/// mirrors the target so `syscall record -- cmd` can be used in scripts, with
/// 128+signal for recorder interruptions (130 SIGINT, 143 SIGTERM) and
/// 128+signal for a signalled target.
pub fn record_exit_code(report: &syscall_collector::RecordReport) -> u8 {
    if let Some(signal) = report.interrupt_signal {
        return (128 + signal).clamp(0, 255) as u8;
    }
    if report.interrupted {
        return 130;
    }
    if report.status == SessionStatus::Failed {
        return 1;
    }
    match report.target {
        Some(target) => {
            if let Some(code) = target.exit_code {
                code.clamp(0, 255) as u8
            } else if let Some(signal) = target.signal {
                (128 + signal).clamp(0, 255) as u8
            } else {
                0
            }
        }
        None => 0,
    }
}

/// Execute one CLI invocation. Returns the process exit code.
pub fn execute(cli: Cli) -> Result<u8> {
    let database_path = cli.database.clone().unwrap_or_else(default_db_path);

    match cli.command {
        Command::Info => {
            let report = syscall_collector::environment::inspect(Some(database_path.clone()));
            let text = if cli.json {
                render::render_info_json(&report, &database_path)?
            } else {
                render::render_info(&report, &database_path)
            };
            print!("{text}");
            Ok(0)
        }

        Command::Record {
            scope,
            redact_args,
            session_id,
            command,
        } => {
            anyhow::ensure!(
                !command.is_empty(),
                "a target command is required after `--`"
            );
            let request = RecordRequest {
                database_path: database_path.clone(),
                command,
                scope: scope.into(),
                redact_arguments: redact_args,
                session_id,
            };
            let report = record(request).map_err(|err| anyhow::anyhow!("{err}"))?;
            let text = if cli.json {
                render::render_record_json(&report)?
            } else {
                render::render_record(&report)
            };
            print!("{text}");
            Ok(record_exit_code(&report))
        }

        Command::Sessions { limit } => {
            let storage = open_for_read(&database_path)?;
            let sessions = storage
                .list_sessions(limit)
                .context("could not list sessions")?;
            let text = if cli.json {
                render::render_sessions_json(&sessions)?
            } else {
                render::render_sessions(&sessions)
            };
            print!("{text}");
            Ok(0)
        }

        Command::Inspect { session_id } => {
            let storage = open_for_read(&database_path)?;
            let session = storage
                .get_session(&session_id)
                .with_context(|| format!("could not read session {session_id}"))?
                .with_context(|| format!("session not found: {session_id}"))?;
            let type_counts = storage
                .event_type_counts(&session_id)
                .context("could not count event types")?;
            let processes = storage
                .process_summaries(&session_id, 20)
                .context("could not build process summary")?;

            let text = if cli.json {
                render::render_inspect_json(&session, &type_counts, &processes, &database_path)?
            } else {
                render::render_inspect(&session, &type_counts, &processes, &database_path)
            };
            print!("{text}");
            Ok(0)
        }

        Command::Events {
            session_id,
            limit,
            offset,
            event_type,
            pid,
        } => {
            let storage = open_for_read(&database_path)?;
            // Distinguish "no such session" from "session has no events".
            storage
                .get_session(&session_id)
                .with_context(|| format!("could not read session {session_id}"))?
                .with_context(|| format!("session not found: {session_id}"))?;
            let query = EventQuery {
                session_id,
                limit,
                offset,
                event_type,
                pid,
            };
            let events = storage
                .query_events(&query)
                .context("could not query events")?;
            let text = if cli.json {
                render::render_events_json(&events)?
            } else {
                render::render_events(&events, &query)
            };
            print!("{text}");
            Ok(0)
        }

        Command::Processes { session_id } => {
            let storage = open_for_read(&database_path)?;
            let session = require_session(&storage, &session_id)?;
            let processes = storage
                .list_process_instances(&session_id)
                .context("could not derive process instances")?;
            let text = if cli.json {
                render::render_processes_json(&session_id, &processes, &session)?
            } else {
                render::render_processes(&session_id, &processes, &session)
            };
            print!("{text}");
            Ok(0)
        }

        Command::Tree { session_id } => {
            let storage = open_for_read(&database_path)?;
            let _session = require_session(&storage, &session_id)?;
            let processes = storage
                .list_process_instances(&session_id)
                .context("could not derive process instances")?;
            let text = if cli.json {
                render::render_tree_json(&session_id, &processes)?
            } else {
                render::render_tree(&session_id, &processes)
            };
            print!("{text}");
            Ok(0)
        }

        Command::Files {
            session_id,
            limit,
            offset,
            pid,
            process_instance,
            from,
            to,
            result,
        } => {
            let storage = open_for_read(&database_path)?;
            let _session = require_session(&storage, &session_id)?;
            let from_ns = from.as_deref().map(parse_time_arg).transpose()?;
            let to_ns = to.as_deref().map(parse_time_arg).transpose()?;
            if let (Some(f), Some(t)) = (from_ns, to_ns) {
                if f > t {
                    return Err(anyhow!("--from must be <= --to (from {f}, to {t})"));
                }
            }
            let mut filter = ActivityFilter::new(session_id.clone());
            filter.limit = Some(limit);
            filter.offset = offset;
            filter.pid = pid;
            filter.process_instance_id = process_instance;
            filter.from_ns = from_ns;
            filter.to_ns = to_ns;
            filter.success = result.map(|value| value.as_success());
            let total = storage
                .count_file_activity(&filter)
                .context("could not count file-open events")?;
            let files = storage
                .query_file_activity(&filter)
                .context("could not query file-open events")?;
            let text = if cli.json {
                render::render_files_json(&session_id, &files, total)?
            } else {
                render::render_files(&session_id, &files, total)
            };
            print!("{text}");
            Ok(0)
        }

        Command::Connections {
            session_id,
            limit,
            offset,
            pid,
            process_instance,
            from,
            to,
            family,
            result,
        } => {
            let storage = open_for_read(&database_path)?;
            let _session = require_session(&storage, &session_id)?;
            let from_ns = from.as_deref().map(parse_time_arg).transpose()?;
            let to_ns = to.as_deref().map(parse_time_arg).transpose()?;
            if let (Some(f), Some(t)) = (from_ns, to_ns) {
                if f > t {
                    return Err(anyhow!("--from must be <= --to (from {f}, to {t})"));
                }
            }
            let mut filter = ActivityFilter::new(session_id.clone());
            filter.limit = Some(limit);
            filter.offset = offset;
            filter.pid = pid;
            filter.process_instance_id = process_instance;
            filter.from_ns = from_ns;
            filter.to_ns = to_ns;
            filter.family = family;
            filter.success = result.map(|value| value.as_success());
            let total = storage
                .count_connection_activity(&filter)
                .context("could not count network-connect events")?;
            let connections = storage
                .query_connection_activity(&filter)
                .context("could not query network-connect events")?;
            let text = if cli.json {
                render::render_connections_json(&session_id, &connections, total)?
            } else {
                render::render_connections(&session_id, &connections, total)
            };
            print!("{text}");
            Ok(0)
        }

        Command::Timeline {
            session_id,
            limit,
            offset,
            event_type,
            pid,
            process_instance,
            from,
            to,
        } => {
            let storage = open_for_read(&database_path)?;
            let _session = require_session(&storage, &session_id)?;
            let from_ns = from.as_deref().map(parse_time_arg).transpose()?;
            let to_ns = to.as_deref().map(parse_time_arg).transpose()?;
            if let (Some(f), Some(t)) = (from_ns, to_ns) {
                if f > t {
                    return Err(anyhow!("--from must be <= --to (from {f}, to {t})"));
                }
            }
            let mut filter = TimelineFilter::new(session_id.clone());
            filter.limit = Some(limit);
            filter.offset = offset;
            filter.event_type = event_type;
            filter.pid = pid;
            filter.process_instance_id = process_instance;
            filter.from_ns = from_ns;
            filter.to_ns = to_ns;
            let total = storage
                .count_timeline(&filter)
                .context("could not count timeline events")?;
            let events = storage
                .query_timeline(&filter)
                .context("could not query timeline events")?;
            let text = if cli.json {
                render::render_timeline_json(&events, &session_id, &filter, Some(total))?
            } else {
                render::render_timeline(&events, &session_id, offset, limit, Some(total))
            };
            print!("{text}");
            Ok(0)
        }

        Command::Stats { session_id, verify } => {
            let storage = open_for_read(&database_path)?;
            let _session = require_session(&storage, &session_id)?;
            let stats = storage
                .session_stats(&session_id)
                .context("could not compute session stats")?
                .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
            let verification = if verify {
                Some(
                    storage
                        .verify_session(&session_id)
                        .map_err(|err| anyhow!("verification failed: {err}"))?,
                )
            } else {
                None
            };
            let text = if cli.json {
                render::render_stats_json(&stats, verification.as_ref())?
            } else {
                render::render_stats(&stats, verification.as_ref())
            };
            print!("{text}");
            Ok(0)
        }

        Command::Analyze {
            session_id,
            rule,
            severity,
            min_confidence,
            output,
            config,
        } => {
            let storage = open_for_read(&database_path)?;
            let config = match config {
                Some(path) => AnalysisConfig::from_path(&path).map_err(|err| {
                    anyhow!("invalid analysis configuration {}: {err}", path.display())
                })?,
                None => AnalysisConfig::default()
                    .validate()
                    .map_err(|err| anyhow!("invalid default analysis configuration: {err}"))?,
            };
            let report = analyze(
                &storage,
                &session_id,
                AnalysisOptions {
                    config,
                    rule,
                    min_severity: severity,
                    min_confidence,
                },
            )
            .map_err(|err| anyhow!("analysis failed: {err}"))?;
            let text = if cli.json {
                render::render_analysis_json(&report)?
            } else {
                render::render_analysis(&report)
            };
            if let Some(path) = output {
                write_analysis_output(&path, &text)?;
                eprintln!("Analysis written to {}\n", path.display());
            } else {
                print!("{text}");
            }
            Ok(0)
        }

        Command::Export {
            session_id,
            format,
            output,
            force,
        } => {
            let storage = open_for_read(&database_path)?;
            let _session = require_session(&storage, &session_id)?;
            match format {
                ExportFormat::Json => {}
            }
            let outcome = export::export_json(
                &storage,
                export::ExportRequest {
                    session_id,
                    output,
                    force,
                    database_path: database_path.clone(),
                },
            )?;
            let text = if cli.json {
                render::render_export_result_json(&outcome)?
            } else {
                render::render_export_result(&outcome)
            };
            print!("{text}");
            Ok(0)
        }

        Command::Verify { session_id } => {
            let report = match open_for_read(&database_path) {
                Ok(storage) => storage
                    .verify_session(&session_id)
                    .map_err(|err| anyhow::anyhow!("verification failed: {err}"))?,
                Err(open_err) => {
                    // For unsupported/missing schema or basic inspection cases, attempt
                    // path-based verification to produce a structured unable_to_verify
                    // report when schema version can be read safely (no migrations/writes).
                    match syscall_storage::verify_session_at_path(&database_path, &session_id) {
                        Ok(report) => report,
                        Err(_) => return Err(open_err),
                    }
                }
            };
            let text = if cli.json {
                render::render_verify_json(&report)?
            } else {
                render::render_verify(&report, &database_path)
            };
            print!("{text}");
            Ok(syscall_core::verify_exit_code(report.assessment) as u8)
        }

        Command::VerifyExport { package } => {
            let verification = export::verify_export_json(&package)?;
            let text = if cli.json {
                render::render_export_verification_json(&verification)?
            } else {
                render::render_export_verification(&verification, &package)
            };
            print!("{text}");
            Ok(if verification.valid { 0 } else { 1 })
        }
    }
}

fn write_analysis_output(path: &std::path::Path, text: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("could not open analysis output {}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("could not secure analysis output {}", path.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("could not write analysis output {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("could not sync analysis output {}", path.display()))?;
    Ok(())
}

fn require_session(storage: &Storage, session_id: &str) -> Result<syscall_storage::SessionSummary> {
    storage
        .get_session(session_id)
        .with_context(|| format!("could not read session {session_id}"))?
        .ok_or_else(|| anyhow!("session not found: {session_id}"))
}

fn parse_time_arg(value: &str) -> Result<i64> {
    // Accept integer nanoseconds-since-epoch directly.
    if let Ok(ns) = value.parse::<i64>() {
        return Ok(ns);
    }
    // Accept a simple RFC3339-like UTC form: YYYY-MM-DDTHH:MM:SS[.frac]Z
    // Implement minimal parser to avoid extra deps.
    parse_rfc3339_utc_to_ns(value)
        .ok_or_else(|| anyhow!("invalid time {value:?}: expected integer nanoseconds since Unix epoch or RFC3339 UTC timestamp (e.g. 2026-11-10T12:34:56Z)"))
}

fn parse_rfc3339_utc_to_ns(s: &str) -> Option<i64> {
    // Very small parser for common forms; returns None on invalid input.
    let s = s.trim();
    let (date_time, _z) = s
        .strip_suffix('Z')
        .map(|d| (d, true))
        .or_else(|| s.strip_suffix('z').map(|d| (d, true)))?;
    let (date, time) = date_time.split_once('T')?;
    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if d.next().is_some() {
        return None;
    }
    let (time_main, frac) = match time.split_once('.') {
        Some((t, f)) => (t, Some(f)),
        None => (time, None),
    };
    let mut t = time_main.split(':');
    let hour: i64 = t.next()?.parse().ok()?;
    let min: i64 = t.next()?.parse().ok()?;
    let sec: i64 = t.next()?.parse().ok()?;
    if t.next().is_some() {
        return None;
    }
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return None;
    }
    let mut nanos: i64 = 0;
    if let Some(f) = frac {
        if f.is_empty() || f.len() > 9 || !f.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let mut padded = f.to_string();
        while padded.len() < 9 {
            padded.push('0');
        }
        nanos = padded.parse().ok()?;
    }
    let days = days_from_civil(year, month, day)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hour * 3600 + min * 60 + sec)?;
    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}

// Howard Hinnant civil_from_days inverse
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn open_for_read(path: &PathBuf) -> Result<Storage> {
    Storage::open_read_only(path).with_context(|| {
        format!(
            "could not open {} (run `syscall record` to create it)",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use syscall_collector::{RecordReport, TargetOutcome};

    fn report(
        status: SessionStatus,
        target: Option<TargetOutcome>,
        interrupted: bool,
    ) -> RecordReport {
        RecordReport {
            session_id: "s-test".to_owned(),
            status,
            events_persisted: 0,
            events_filtered: 0,
            events_self_filtered: 0,
            malformed_events: 0,
            ringbuf_lost_events: 0,
            userspace_dropped_events: 0,
            rejections: syscall_collector::RejectionBreakdown::default(),
            target,
            interrupted,
            interrupt_signal: if interrupted { Some(2) } else { None },
            duration_ns: 0,
            database_path: PathBuf::from("/tmp/test.db"),
        }
    }

    #[test]
    fn sigterm_interrupted_recording_exits_143() {
        let mut r = report(SessionStatus::Interrupted, None, true);
        r.interrupt_signal = Some(15);
        assert_eq!(record_exit_code(&r), 143);
    }

    #[test]
    fn interrupted_recording_exits_130() {
        let mut report = report(
            SessionStatus::Interrupted,
            Some(TargetOutcome {
                exit_code: None,
                signal: Some(15),
            }),
            true,
        );
        report.interrupt_signal = Some(2);
        assert_eq!(record_exit_code(&report), 130);
    }

    #[test]
    fn target_exit_code_is_mirrored() {
        assert_eq!(
            record_exit_code(&report(
                SessionStatus::Completed,
                Some(TargetOutcome {
                    exit_code: Some(0),
                    signal: None,
                }),
                false,
            )),
            0
        );
        assert_eq!(
            record_exit_code(&report(
                SessionStatus::Completed,
                Some(TargetOutcome {
                    exit_code: Some(7),
                    signal: None,
                }),
                false,
            )),
            7
        );
    }

    #[test]
    fn target_signal_uses_128_plus_signal() {
        let report = report(
            SessionStatus::Completed,
            Some(TargetOutcome {
                exit_code: None,
                signal: Some(9),
            }),
            false,
        );
        assert_eq!(record_exit_code(&report), 137);
    }

    #[test]
    fn failed_session_exits_1_even_with_clean_target() {
        let report = report(
            SessionStatus::Failed,
            Some(TargetOutcome {
                exit_code: Some(0),
                signal: None,
            }),
            false,
        );
        assert_eq!(record_exit_code(&report), 1);
    }

    #[test]
    fn unknown_target_exits_0() {
        assert_eq!(
            record_exit_code(&report(SessionStatus::Completed, None, false)),
            0
        );
    }
}
