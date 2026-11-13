//! Clap command definitions.

use std::ffi::OsString;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};
use syscall_core::{
    AddressFamily, AnalysisConfidence, AnalysisSeverity, EventType, RecordingScope,
};

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

    /// List process instances belonging to a session.
    Processes {
        /// Session id as shown by `syscall sessions`.
        session_id: String,
    },

    /// Display the process hierarchy as a readable tree.
    Tree {
        /// Session id as shown by `syscall sessions`.
        session_id: String,
    },

    /// Provide a chronological event timeline for investigation.
    Timeline {
        /// Session id as shown by `syscall sessions`.
        session_id: String,

        /// Maximum number of events to return.
        #[arg(long, default_value_t = 200, value_name = "N")]
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

        /// Only show events for this process instance id.
        #[arg(long = "process-instance", value_name = "ID")]
        process_instance: Option<String>,

        /// Only show events at or after this wall-clock timestamp (ns since Unix epoch, or RFC3339/UTC datetime).
        #[arg(long, value_name = "TIME")]
        from: Option<String>,

        /// Only show events at or before this wall-clock timestamp (ns since Unix epoch, or RFC3339/UTC datetime).
        #[arg(long, value_name = "TIME")]
        to: Option<String>,
    },

    /// Display recorded file-open attempts.
    Files {
        /// Session id as shown by `syscall sessions`.
        session_id: String,

        /// Maximum number of file-open events to return.
        #[arg(long, default_value_t = 200, value_name = "N")]
        limit: usize,

        /// Skip this many matching file-open events.
        #[arg(long, default_value_t = 0, value_name = "N")]
        offset: usize,

        /// Only show events for this process id.
        #[arg(long, value_name = "PID")]
        pid: Option<i32>,

        /// Only show events for this process instance id.
        #[arg(long = "process-instance", value_name = "ID")]
        process_instance: Option<String>,

        /// Only show events at or after this wall-clock timestamp (ns or RFC3339).
        #[arg(long, value_name = "TIME")]
        from: Option<String>,

        /// Only show events at or before this wall-clock timestamp (ns or RFC3339).
        #[arg(long, value_name = "TIME")]
        to: Option<String>,

        /// Only show successful or failed open attempts.
        #[arg(long = "result", value_enum, value_name = "RESULT")]
        result: Option<ResultFilter>,
    },

    /// Display recorded IPv4/IPv6 connect attempts.
    Connections {
        /// Session id as shown by `syscall sessions`.
        session_id: String,

        /// Maximum number of connection events to return.
        #[arg(long, default_value_t = 200, value_name = "N")]
        limit: usize,

        /// Skip this many matching connection events.
        #[arg(long, default_value_t = 0, value_name = "N")]
        offset: usize,

        /// Only show events for this process id.
        #[arg(long, value_name = "PID")]
        pid: Option<i32>,

        /// Only show events for this process instance id.
        #[arg(long = "process-instance", value_name = "ID")]
        process_instance: Option<String>,

        /// Only show events at or after this wall-clock timestamp (ns or RFC3339).
        #[arg(long, value_name = "TIME")]
        from: Option<String>,

        /// Only show events at or before this wall-clock timestamp (ns or RFC3339).
        #[arg(long, value_name = "TIME")]
        to: Option<String>,

        /// Only show IPv4 or IPv6 attempts.
        #[arg(long, value_parser = parse_address_family, value_name = "FAMILY")]
        family: Option<AddressFamily>,

        /// Only show successful or failed connect attempts.
        #[arg(long = "result", value_enum, value_name = "RESULT")]
        result: Option<ResultFilter>,
    },

    /// Show session statistics and evidence accounting.
    Stats {
        /// Session id as shown by `syscall sessions`.
        session_id: String,

        /// Include a read-only verification assessment when safely available.
        #[arg(long)]
        verify: bool,
    },

    /// Explain recorded behavior using deterministic, evidence-backed rules.
    ///
    /// Analysis is read-only. It does not execute recorded commands and does
    /// not claim a definitive malware verdict.
    Analyze {
        /// Session id as shown by `syscall sessions`.
        session_id: String,

        /// Run only this rule (for example SYSCALL-TEMP-EXEC).
        #[arg(long, value_parser = parse_rule_id, value_name = "RULE_ID")]
        rule: Option<String>,

        /// Only show findings at or above this severity.
        #[arg(long, value_parser = parse_analysis_severity, value_name = "LEVEL")]
        severity: Option<AnalysisSeverity>,

        /// Only show findings at or above this confidence.
        #[arg(long = "min-confidence", value_parser = parse_analysis_confidence, value_name = "LEVEL")]
        min_confidence: Option<AnalysisConfidence>,

        /// Write output to this file instead of stdout (mode 0600).
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Strict JSON configuration file for paths, thresholds, windows, and rule enablement.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },

    /// Export a deterministic forensic evidence package for a session.
    Export {
        /// Session id as shown by `syscall sessions`.
        session_id: String,

        /// Export format (currently only json).
        #[arg(long, default_value = "json", value_parser = parse_export_format, value_name = "FORMAT")]
        format: ExportFormat,

        /// Output file path. Created atomically with restrictive permissions.
        #[arg(long, value_name = "FILE")]
        output: PathBuf,

        /// Overwrite the output file if it already exists.
        #[arg(long)]
        force: bool,
    },

    /// Verify internal consistency and evidence interpretability of a recorded session.
    ///
    /// Verification is strictly read-only: it never migrates, repairs, recovers,
    /// rewrites, or completes missing evidence.
    Verify {
        /// Session id as shown by `syscall sessions`.
        session_id: String,
    },

    /// Verify the SHA-256 manifest of an exported evidence package.
    ///
    /// This is read-only and never rewrites the package.
    VerifyExport {
        /// Exported JSON package to verify.
        package: PathBuf,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ResultFilter {
    Success,
    Failure,
}

impl ResultFilter {
    pub const fn as_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
}

fn parse_event_type(value: &str) -> Result<EventType, String> {
    let event_type = EventType::from_str(value).map_err(|_| {
        format!(
            "unknown event type {value:?}; expected one of: process_exec, process_fork, process_exit, file_open, network_connect"
        )
    })?;
    if !event_type.is_collected() {
        return Err(format!(
            "event type {value:?} has no Mission 01 collector and is never persisted"
        ));
    }
    Ok(event_type)
}

fn parse_address_family(value: &str) -> Result<AddressFamily, String> {
    value.parse::<AddressFamily>()
}

fn parse_rule_id(value: &str) -> Result<String, String> {
    if syscall_analysis::ALL_RULE_IDS.contains(&value) {
        Ok(value.to_owned())
    } else {
        Err(format!(
            "unknown rule {value:?}; expected one of: {}",
            syscall_analysis::ALL_RULE_IDS.join(", ")
        ))
    }
}

fn parse_analysis_severity(value: &str) -> Result<AnalysisSeverity, String> {
    match value.to_ascii_lowercase().as_str() {
        "informational" | "info" => Ok(AnalysisSeverity::Informational),
        "low" => Ok(AnalysisSeverity::Low),
        "medium" => Ok(AnalysisSeverity::Medium),
        "high" => Ok(AnalysisSeverity::High),
        "critical" => Ok(AnalysisSeverity::Critical),
        _ => Err(format!(
            "unknown analysis severity {value:?}; expected informational, low, medium, high, or critical"
        )),
    }
}

fn parse_analysis_confidence(value: &str) -> Result<AnalysisConfidence, String> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Ok(AnalysisConfidence::Low),
        "medium" => Ok(AnalysisConfidence::Medium),
        "high" => Ok(AnalysisConfidence::High),
        _ => Err(format!(
            "unknown analysis confidence {value:?}; expected low, medium, or high"
        )),
    }
}

fn parse_export_format(value: &str) -> Result<ExportFormat, String> {
    match value {
        "json" => Ok(ExportFormat::Json),
        other => Err(format!(
            "unsupported export format {other:?}; supported formats: json"
        )),
    }
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
        let cli = Cli::try_parse_from(["syscall", "events", "s-1", "--type", "file_open"]).unwrap();
        match cli.command {
            Command::Events { event_type, .. } => {
                assert_eq!(event_type, Some(EventType::FileOpen));
            }
            other => panic!("unexpected command: {other:?}"),
        }
        assert!(Cli::try_parse_from(["syscall", "events", "s-1", "--type", "not_a_type"]).is_err());
    }

    #[test]
    fn analyze_parses_rule_severity_confidence_and_rejects_invalid_values() {
        let cli = Cli::try_parse_from([
            "syscall",
            "analyze",
            "s-1",
            "--rule",
            syscall_analysis::RULE_TEMP_EXEC,
            "--severity",
            "high",
            "--min-confidence",
            "medium",
            "--config",
            "/tmp/analysis.json",
            "--output",
            "/tmp/report.txt",
        ])
        .unwrap();
        match cli.command {
            Command::Analyze {
                session_id,
                rule,
                severity,
                min_confidence,
                output,
                config,
            } => {
                assert_eq!(session_id, "s-1");
                assert_eq!(rule.as_deref(), Some(syscall_analysis::RULE_TEMP_EXEC));
                assert_eq!(severity, Some(AnalysisSeverity::High));
                assert_eq!(min_confidence, Some(AnalysisConfidence::Medium));
                assert_eq!(output, Some(PathBuf::from("/tmp/report.txt")));
                assert_eq!(config, Some(PathBuf::from("/tmp/analysis.json")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
        assert!(Cli::try_parse_from(["syscall", "analyze", "s-1", "--rule", "NOPE"]).is_err());
        assert!(
            Cli::try_parse_from(["syscall", "analyze", "s-1", "--severity", "urgent"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["syscall", "analyze", "s-1", "--min-confidence", "certain"])
                .is_err()
        );
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
