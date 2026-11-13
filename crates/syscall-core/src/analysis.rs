//! Shared, serializable analysis result model.
//!
//! The analysis engine consumes persisted evidence and emits these structures.
//! They deliberately contain only data that can be traced to recorded events;
//! there is no opaque score or probability field.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{CoreError, EventType, Result};

/// Version of the `syscall analyze --json` result schema.
pub const ANALYSIS_SCHEMA_VERSION: &str = "syscall-analysis/v1";

/// Severity of an analytical finding. This is an investigative priority, not
/// a probability that behavior is malicious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl AnalysisSeverity {
    pub const ALL: [Self; 5] = [
        Self::Informational,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub const fn rank(self) -> u8 {
        match self {
            Self::Informational => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

impl fmt::Display for AnalysisSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AnalysisSeverity {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "informational" | "info" => Ok(Self::Informational),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(CoreError::InvalidEvent(format!(
                "unknown analysis severity {other:?}; expected informational, low, medium, high, or critical"
            ))),
        }
    }
}

/// Confidence in an analytical conclusion. These labels describe the quality
/// and directness of recorded evidence; they are not calibrated probabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisConfidence {
    Low,
    Medium,
    High,
}

impl AnalysisConfidence {
    pub const ALL: [Self; 3] = [Self::Low, Self::Medium, Self::High];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub const fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
        }
    }
}

impl fmt::Display for AnalysisConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AnalysisConfidence {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            other => Err(CoreError::InvalidEvent(format!(
                "unknown analysis confidence {other:?}; expected low, medium, or high"
            ))),
        }
    }
}

/// Inclusive wall-clock range of events supporting a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisTimeRange {
    pub start_ns: i64,
    pub end_ns: i64,
}

/// One persisted event referenced by a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportingEvent {
    pub event_id: i64,
    pub timestamp_ns: i64,
    pub monotonic_ns: u64,
    pub event_type: EventType,
    pub pid: i32,
    pub process_instance_id: String,
    pub comm: String,
    /// Sanitized-at-render-time, human-readable event summary.
    pub summary: String,
}

/// Process identity relevant to a finding. `parent_process_instance_id` is
/// only present when recorded evidence established it unambiguously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisProcessRef {
    pub process_instance_id: String,
    pub pid: i32,
    pub comm: String,
    pub executable: Option<String>,
    pub parent_process_instance_id: Option<String>,
    pub exit_observed: bool,
}

/// A single explainable analytical finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisFinding {
    /// Stable for the same rule, session evidence, and primary key.
    pub finding_id: String,
    pub rule_id: String,
    pub rule_version: u16,
    pub severity: AnalysisSeverity,
    pub confidence: AnalysisConfidence,
    pub title: String,
    /// What was observed, including exact event-derived numbers.
    pub explanation: String,
    /// Why the observation may matter during an investigation.
    pub significance: String,
    /// Original persisted event IDs. Never synthesized.
    pub event_ids: Vec<i64>,
    pub process_instance_ids: Vec<String>,
    pub pids: Vec<i32>,
    pub time_range: AnalysisTimeRange,
    /// IDs of related findings emitted in the same report, when applicable.
    pub related_findings: Vec<String>,
    pub limitations: Vec<String>,
    pub next_steps: Vec<String>,
    pub supporting_events: Vec<SupportingEvent>,
    pub related_processes: Vec<AnalysisProcessRef>,
    /// How the evidence is related: same_process, process_tree, or independent.
    pub correlation: String,
}

/// Static documentation for a rule, included in every report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisRuleMetadata {
    pub rule_id: String,
    pub version: u16,
    pub title: String,
    pub description: String,
    pub conditions: Vec<String>,
    pub required_evidence: Vec<String>,
    pub exclusions: Vec<String>,
    pub known_false_positives: Vec<String>,
    pub severity_rationale: String,
    pub confidence_rationale: String,
    pub default_severity: AnalysisSeverity,
    pub default_confidence: AnalysisConfidence,
}

/// Evidence completeness for the analyzed session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCompleteness {
    pub status: String,
    pub session_status: String,
    pub event_count: i64,
    pub process_count: i64,
    pub ringbuf_lost_events: u64,
    pub userspace_dropped_events: u64,
    pub malformed_events: u64,
    pub filtered_events: u64,
    pub events_persist_failed: u64,
    pub events_self_filtered: u64,
    pub unresolved_identity_count: u64,
    pub verification_assessment: Option<String>,
    pub may_be_incomplete: bool,
    pub notes: Vec<String>,
}

impl EvidenceCompleteness {
    pub fn is_complete(&self) -> bool {
        !self.may_be_incomplete && self.verification_assessment.as_deref() == Some("valid")
    }
}

/// Versioned analysis result returned by the CLI and included in exports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: String,
    pub session_id: String,
    pub session_command: String,
    pub session_scope: String,
    pub session_started_at_ns: i64,
    pub session_ended_at_ns: Option<i64>,
    pub evidence: EvidenceCompleteness,
    pub rules_evaluated: Vec<AnalysisRuleMetadata>,
    pub findings: Vec<AnalysisFinding>,
    /// Report-level limitations that apply beyond one finding.
    pub limitations: Vec<String>,
    /// True when a configured bound omitted evidence or findings.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_and_confidence_round_trip_and_order() {
        for severity in AnalysisSeverity::ALL {
            assert_eq!(
                severity.as_str().parse::<AnalysisSeverity>().unwrap(),
                severity
            );
        }
        for confidence in AnalysisConfidence::ALL {
            assert_eq!(
                confidence.as_str().parse::<AnalysisConfidence>().unwrap(),
                confidence
            );
        }
        assert!(AnalysisSeverity::Critical > AnalysisSeverity::High);
        assert!(AnalysisConfidence::High > AnalysisConfidence::Low);
        assert_eq!(
            "info".parse::<AnalysisSeverity>().unwrap(),
            AnalysisSeverity::Informational
        );
    }
}
