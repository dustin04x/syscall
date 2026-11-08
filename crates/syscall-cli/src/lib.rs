//! Command line interface for SYSCALL.
//!
//! The CLI is deliberately thin: it parses arguments, opens storage read-only
//! for inspection commands, and delegates recording to [`syscall_collector`].
//! All rendering lives in [`render`] so output is testable without a terminal.

pub mod cli;
pub mod render;

use std::path::PathBuf;

use anyhow::{Context, Result};
use syscall_collector::{record, RecordRequest};
use syscall_core::paths::default_db_path;
use syscall_storage::{EventQuery, SessionStatus, Storage};

use crate::cli::{Cli, Command};

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
    }
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
