use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

/// Version of the on-disk and in-memory event schema.
pub const SCHEMA_VERSION: u16 = 1;

/// `TASK_COMM_LEN` in the Linux kernel.
pub const COMM_LEN: usize = 16;

/// Maximum filename bytes captured from `sched_process_exec`.
pub const MAX_FILENAME_LEN: usize = 256;

/// Event types understood by the current schema.
///
/// Only the first three variants have real collectors in Mission 01. The
/// remaining variants are reserved by the schema and must not be emitted until
/// a real kernel collector exists for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ProcessExec,
    ProcessFork,
    ProcessExit,
    FileOpen,
    NetworkConnect,
}

impl EventType {
    pub const ALL: [Self; 5] = [
        Self::ProcessExec,
        Self::ProcessFork,
        Self::ProcessExit,
        Self::FileOpen,
        Self::NetworkConnect,
    ];

    /// Event types implemented by Mission 01 collectors.
    pub const COLLECTED: [Self; 3] = [Self::ProcessExec, Self::ProcessFork, Self::ProcessExit];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::ProcessFork => "process_fork",
            Self::ProcessExit => "process_exit",
            Self::FileOpen => "file_open",
            Self::NetworkConnect => "network_connect",
        }
    }

    pub const fn wire_id(self) -> u16 {
        match self {
            Self::ProcessExec => 1,
            Self::ProcessFork => 2,
            Self::ProcessExit => 3,
            Self::FileOpen => 4,
            Self::NetworkConnect => 5,
        }
    }

    pub const fn from_wire_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::ProcessExec),
            2 => Some(Self::ProcessFork),
            3 => Some(Self::ProcessExit),
            4 => Some(Self::FileOpen),
            5 => Some(Self::NetworkConnect),
            _ => None,
        }
    }

    pub const fn is_collected(self) -> bool {
        matches!(
            self,
            Self::ProcessExec | Self::ProcessFork | Self::ProcessExit
        )
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EventType {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "process_exec" => Ok(Self::ProcessExec),
            "process_fork" => Ok(Self::ProcessFork),
            "process_exit" => Ok(Self::ProcessExit),
            "file_open" => Ok(Self::FileOpen),
            "network_connect" => Ok(Self::NetworkConnect),
            other => Err(CoreError::UnknownEventType(other.to_owned())),
        }
    }
}

/// Process metadata shared by lifecycle events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMetadata {
    pub ppid: Option<i32>,
    /// `/proc/<pid>/stat` field 22, in clock ticks since boot.
    pub start_time_ticks: Option<u64>,
}

/// Type-specific event payload.
///
/// `FileOpen` and `NetworkConnect` are schema placeholders. They are defined so
/// clients can be written against a stable schema, but no Mission 01 collector
/// emits them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventPayload {
    ProcessExec {
        filename: String,
        #[serde(flatten)]
        process: ProcessMetadata,
        old_pid: Option<i32>,
    },
    ProcessFork {
        parent_pid: i32,
        parent_tgid: Option<i32>,
        child_pid: i32,
        child_comm: String,
        child_start_time_ticks: Option<u64>,
    },
    ProcessExit {
        #[serde(flatten)]
        process: ProcessMetadata,
        exit_priority: i32,
    },
    /// Schema-only placeholder. Not collected in Mission 01.
    FileOpen { path: String },
    /// Schema-only placeholder. Not collected in Mission 01.
    NetworkConnect {
        family: String,
        address: String,
        port: u16,
    },
}

impl EventPayload {
    pub const fn event_type(&self) -> EventType {
        match self {
            Self::ProcessExec { .. } => EventType::ProcessExec,
            Self::ProcessFork { .. } => EventType::ProcessFork,
            Self::ProcessExit { .. } => EventType::ProcessExit,
            Self::FileOpen { .. } => EventType::FileOpen,
            Self::NetworkConnect { .. } => EventType::NetworkConnect,
        }
    }
}

/// A normalized SYSCALL event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Database-assigned row id; `None` before persistence.
    pub id: Option<i64>,
    pub session_id: String,
    pub schema_version: u16,
    pub event_type: EventType,
    /// Wall-clock nanoseconds since the Unix epoch, derived from the monotonic
    /// kernel timestamp plus a process-wide clock offset.
    pub timestamp_ns: i64,
    /// `bpf_ktime_get_ns()` value: CLOCK_MONOTONIC nanoseconds since boot.
    pub monotonic_ns: u64,
    pub pid: i32,
    pub tid: i32,
    pub uid: u32,
    pub gid: u32,
    pub ppid: Option<i32>,
    pub comm: String,
    /// Stable identity for this PID instance: boot id + pid + start time ticks.
    pub process_instance_id: String,
    pub payload: EventPayload,
}

impl Event {
    /// Validate invariants before persistence or display.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CoreError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        validate_token("session_id", &self.session_id, 128)?;
        if self.pid <= 0 {
            return Err(CoreError::InvalidEvent(format!(
                "pid must be positive, got {}",
                self.pid
            )));
        }
        if self.tid <= 0 {
            return Err(CoreError::InvalidEvent(format!(
                "tid must be positive, got {}",
                self.tid
            )));
        }
        if self.timestamp_ns <= 0 {
            return Err(CoreError::InvalidEvent(
                "wall-clock timestamp must be positive".to_owned(),
            ));
        }
        if self.monotonic_ns == 0 {
            return Err(CoreError::InvalidEvent(
                "monotonic timestamp must be non-zero".to_owned(),
            ));
        }
        if self.comm.is_empty() {
            return Err(CoreError::InvalidEvent("comm must not be empty".to_owned()));
        }
        if self.comm.len() > COMM_LEN {
            return Err(CoreError::InvalidEvent(format!(
                "comm is {} bytes, limit is {COMM_LEN}",
                self.comm.len()
            )));
        }
        if self.comm.as_bytes().contains(&0) {
            return Err(CoreError::InvalidEvent(
                "comm contains a NUL byte".to_owned(),
            ));
        }
        // `comm` is raw kernel data. A process can set control characters via
        // prctl(PR_SET_NAME); rejecting them here would abort a whole write
        // batch. Text renderers escape control characters instead.
        validate_token("process_instance_id", &self.process_instance_id, 256)?;
        if self.event_type != self.payload.event_type() {
            return Err(CoreError::InvalidEvent(format!(
                "event_type {} does not match payload {}",
                self.event_type,
                self.payload.event_type()
            )));
        }
        if !self.event_type.is_collected() {
            return Err(CoreError::InvalidEvent(format!(
                "event type {} has no Mission 01 collector",
                self.event_type
            )));
        }

        match &self.payload {
            EventPayload::ProcessExec {
                filename, old_pid, ..
            } => {
                if filename.len() > MAX_FILENAME_LEN {
                    return Err(CoreError::InvalidEvent(format!(
                        "exec filename is {} bytes, limit is {MAX_FILENAME_LEN}",
                        filename.len()
                    )));
                }
                if filename.as_bytes().contains(&0) {
                    return Err(CoreError::InvalidEvent(
                        "exec filename contains a NUL byte".to_owned(),
                    ));
                }
                if matches!(old_pid, Some(pid) if *pid < 0) {
                    return Err(CoreError::InvalidEvent(
                        "old_pid must not be negative".to_owned(),
                    ));
                }
            }
            EventPayload::ProcessFork {
                parent_pid,
                child_pid,
                child_comm,
                ..
            } => {
                if *parent_pid <= 0 || *child_pid <= 0 {
                    return Err(CoreError::InvalidEvent(
                        "fork parent_pid and child_pid must be positive".to_owned(),
                    ));
                }
                if child_comm.len() > COMM_LEN || child_comm.as_bytes().contains(&0) {
                    return Err(CoreError::InvalidEvent(
                        "fork child_comm is invalid".to_owned(),
                    ));
                }
            }
            EventPayload::ProcessExit { .. } => {}
            EventPayload::FileOpen { .. } | EventPayload::NetworkConnect { .. } => {
                return Err(CoreError::InvalidEvent(
                    "schema-only event type must not be persisted".to_owned(),
                ));
            }
        }

        if matches!(self.ppid, Some(ppid) if ppid < 0) {
            return Err(CoreError::InvalidEvent(
                "ppid must not be negative".to_owned(),
            ));
        }

        Ok(())
    }
}

fn validate_token(name: &str, value: &str, limit: usize) -> Result<()> {
    if value.is_empty() {
        return Err(CoreError::InvalidEvent(format!("{name} must not be empty")));
    }
    if value.len() > limit {
        return Err(CoreError::InvalidEvent(format!(
            "{name} is {} bytes, limit is {limit}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(CoreError::InvalidEvent(format!(
            "{name} contains control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event() -> Event {
        Event {
            id: None,
            session_id: "s-1".to_owned(),
            schema_version: SCHEMA_VERSION,
            event_type: EventType::ProcessExec,
            timestamp_ns: 1_700_000_000_000_000_000,
            monotonic_ns: 123_456,
            pid: 42,
            tid: 42,
            uid: 1000,
            gid: 1000,
            ppid: Some(1),
            comm: "sleep".to_owned(),
            process_instance_id: "boot:42:100".to_owned(),
            payload: EventPayload::ProcessExec {
                filename: "/usr/bin/sleep".to_owned(),
                process: ProcessMetadata {
                    ppid: Some(1),
                    start_time_ticks: Some(100),
                },
                old_pid: Some(41),
            },
        }
    }

    #[test]
    fn valid_event_passes() {
        exec_event().validate().unwrap();
    }

    #[test]
    fn schema_version_is_enforced() {
        let mut event = exec_event();
        event.schema_version = 99;
        assert!(matches!(
            event.validate(),
            Err(CoreError::UnsupportedSchemaVersion { .. })
        ));
    }

    #[test]
    fn payload_must_match_event_type() {
        let mut event = exec_event();
        event.event_type = EventType::ProcessExit;
        assert!(event.validate().is_err());
    }

    #[test]
    fn schema_only_events_are_rejected_by_storage_validation() {
        let mut event = exec_event();
        event.event_type = EventType::FileOpen;
        event.payload = EventPayload::FileOpen {
            path: "/etc/passwd".to_owned(),
        };
        assert!(event.validate().is_err());
    }

    #[test]
    fn comm_limit_is_enforced() {
        let mut event = exec_event();
        event.comm = "x".repeat(COMM_LEN + 1);
        assert!(event.validate().is_err());
    }

    #[test]
    fn comm_control_characters_are_preserved_not_rejected() {
        let mut event = exec_event();
        event.comm = "evil\nname".to_owned();
        event.validate().unwrap();
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("evil\\nname"));
    }

    #[test]
    fn comm_nul_is_rejected() {
        let mut event = exec_event();
        event.comm = "bad\0name".to_owned();
        assert!(event.validate().is_err());
    }

    #[test]
    fn event_type_round_trips() {
        for event_type in EventType::ALL {
            assert_eq!(
                event_type.as_str().parse::<EventType>().unwrap(),
                event_type
            );
            assert_eq!(
                EventType::from_wire_id(event_type.wire_id()).unwrap(),
                event_type
            );
        }
        assert!(EventType::from_wire_id(999).is_none());
    }

    #[test]
    fn payload_serialization_is_tagged() {
        let event = exec_event();
        let json = serde_json::to_value(&event.payload).unwrap();
        assert_eq!(json["kind"], "process_exec");
        assert_eq!(json["filename"], "/usr/bin/sleep");
    }

    #[test]
    fn event_serialization_round_trips() {
        let event = exec_event();
        let json = serde_json::to_string(&event).unwrap();
        let decoded: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn collected_types_are_explicit() {
        assert!(EventType::ProcessExec.is_collected());
        assert!(EventType::ProcessFork.is_collected());
        assert!(EventType::ProcessExit.is_collected());
        assert!(!EventType::FileOpen.is_collected());
        assert!(!EventType::NetworkConnect.is_collected());
    }
}
