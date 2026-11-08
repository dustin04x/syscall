//! Clap command definitions.

use std::ffi::OsString;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};
use syscall_core::{EventType, RecordingScope};

#[derive(Debug, Parser)]
#[command(
    name = "syscall",
    version,
    about = "Linux process intelligence and runtime forensics",
    long_about = "Record real process lifecycle events from Linux tracepoints and \
                  inspect the resulting SQLite sessions.\n\n\
                  Mission 01 collects process_exec, process_fork, and process_exit only.\n\
                  Loading eBPF requires root or CAP_BPF+CAP_PERFMON; SYSCALL never \
                  prompts for or stores passwords.",
    propagate_version = true
)]
pub struct Cli {
    /// Session database path. Defaults to the invoking user's data directory.
    #[arg(
        long = "db",
        global = true,
        env = "SYSCALL_DB",
        value_name = "PATH",
        help = "Session database path"
    )]
    pub database: Option<PathBuf>,

    /// Emit machine-readable JSON instead of text tables.
    #[arg(long, global = true, help = "Emit JSON")]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Report platform, kernel, BPF, and database readiness.
    Info,

    /// Record process lifecycle events while running a target command.
    Record {
        /// Attribution scope. Kernel tracepoints are system-wide in both modes.
        #[arg(long, value_enum, default_value_t = ScopeArg::TargetTree)]
        scope: ScopeArg,

        /// Store a placeholder instead of the target's arguments.
        #[arg(long)]
        redact_args: bool,

        /// Override the generated session id.
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,

        /// Target command and arguments, after `--`.
        #[arg(
            last = true,
            required = true,
            num_args = 1..,
            value_name = "COMMAND",
            help = "Target command, for example: -- /usr/bin/sleep 5"
        )]
        command: Vec<OsString>,
    },

    /// List recorded sessions, newest first.
    Sessions {
        /// Maximum number of sessions to show.
        #[arg(long, default_value_t = 50, value_name = "N")]
        limit: usize,
    },

    /// Show session metadata, counters, event types, and processes.
    Inspect {
        /// Session id as shown by `syscall sessions`.
        session_id: String,
    },

    /// List persisted events for a session in chronological order.
    Events {
        /// Session id as shown by `syscall sessions`.
        session_id: String,

        /// Maximum number of events to return.
        #[arg(long, default_value_t = 100, value_name = "N")]
        limit: usize,

        /// Skip this many matching events.
        #[arg(long, default_value_t = 0, value_name = "N")]
        offset: usize,

        /// Only show one event type.
        #[arg(long = "type", value_parser = parse_event_type, value_name = "TYPE")]
        event_type: Option<EventType>,

        /// Only show events for this process id.
        #[arg(long, value_name = "PID")]
        pid: Option<i32>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScopeArg {
    /// Follow the launched target and its descendants.
    TargetTree,
    /// Record every process lifecycle event observed on the host.
    System,
}

impl From<ScopeArg> for RecordingScope {
    fn from(value: ScopeArg) -> Self {
        match value {
            ScopeArg::TargetTree => Self::TargetTree,
            ScopeArg::System => Self::System,
        }
    }
}

fn parse_event_type(value: &str) -> Result<EventType, String> {
    let event_type = EventType::from_str(value).map_err(|_| {
        format!(
            "unknown event type {value:?}; expected one of: process_exec, process_fork, process_exit"
        )
    })?;
    if !event_type.is_collected() {
        return Err(format!(
            "event type {value:?} has no Mission 01 collector and is never persisted"
        ));
    }
    Ok(event_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_requires_a_trailing_command() {
        assert!(Cli::try_parse_from(["syscall", "record", "--", "/usr/bin/sleep", "5"]).is_ok());
        assert!(Cli::try_parse_from(["syscall", "record"]).is_err());
    }

    #[test]
    fn record_keeps_dashes_in_target_arguments() {
        let cli =
            Cli::try_parse_from(["syscall", "record", "--", "/usr/bin/printf", "--json"]).unwrap();
        match cli.command {
            Command::Record { command, .. } => {
                assert_eq!(
                    command,
                    vec![OsString::from("/usr/bin/printf"), OsString::from("--json")]
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn global_database_flag_is_accepted_before_and_after_the_subcommand() {
        let a = Cli::try_parse_from(["syscall", "--db", "/tmp/a.db", "sessions"]).unwrap();
        let b = Cli::try_parse_from(["syscall", "sessions", "--db", "/tmp/a.db"]).unwrap();
        assert_eq!(a.database, b.database);
    }

    #[test]
    fn event_type_filter_is_validated() {
        let cli =
            Cli::try_parse_from(["syscall", "events", "s-1", "--type", "process_exec"]).unwrap();
        match cli.command {
            Command::Events { event_type, .. } => {
                assert_eq!(event_type, Some(EventType::ProcessExec));
            }
            other => panic!("unexpected command: {other:?}"),
        }
        assert!(Cli::try_parse_from(["syscall", "events", "s-1", "--type", "file_open"]).is_err());
    }

    #[test]
    fn scope_argument_maps_to_domain_scope() {
        assert_eq!(
            RecordingScope::from(ScopeArg::TargetTree),
            RecordingScope::TargetTree
        );
        assert_eq!(
            RecordingScope::from(ScopeArg::System),
            RecordingScope::System
        );
    }
}
