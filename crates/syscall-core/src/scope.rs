use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

/// The logical scope of a recording session.
///
/// The kernel tracepoints used by Mission 01 are system-wide. This value
/// describes what the userspace collector *attributes* to the session, not a
/// kernel-side cgroup or PID filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordingScope {
    /// Follow the launched target process and its descendants.
    TargetTree,
    /// Persist process lifecycle events for every process observed.
    System,
}

impl RecordingScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetTree => "target-tree",
            Self::System => "system",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::TargetTree => {
                "follows the launched target and descendants; filtered in userspace"
            }
            Self::System => "captures all observed process lifecycle events on the host",
        }
    }
}

impl fmt::Display for RecordingScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RecordingScope {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "target-tree" => Ok(Self::TargetTree),
            "system" => Ok(Self::System),
            other => Err(CoreError::UnknownRecordingScope(other.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_round_trips() {
        for scope in [RecordingScope::TargetTree, RecordingScope::System] {
            assert_eq!(scope.as_str().parse::<RecordingScope>().unwrap(), scope);
        }
    }

    #[test]
    fn unknown_scope_is_rejected() {
        assert!("everything".parse::<RecordingScope>().is_err());
    }
}
