//! Forensic verification model for recorded SYSCALL sessions.
//!
//! Verification evaluates internal consistency and evidence interpretability.
//! It never repairs, migrates, rewrites, or completes missing evidence.

use serde::{Deserialize, Serialize};

/// Severity of a verification finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl FindingSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// Overall verification assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationAssessment {
    /// Internally consistent and evidence is interpretable as recorded.
    Valid,
    /// Internally consistent where checkable, but evidence is incomplete/limited.
    ValidButIncomplete,
    /// No hard contradictions found, but notable warnings/limitations exist.
    Warning,
    /// Contradictory, corrupt, or invalid evidence/state detected.
    Invalid,
    /// Verification could not be completed sufficiently to assess trustworthiness.
    UnableToVerify,
}

impl VerificationAssessment {
    pub const fn as_str(self) -> &'static str {
        match self {
            VerificationAssessment::Valid => "valid",
            VerificationAssessment::ValidButIncomplete => "valid_but_incomplete",
            VerificationAssessment::Warning => "warning",
            VerificationAssessment::Invalid => "invalid",
            VerificationAssessment::UnableToVerify => "unable_to_verify",
        }
    }
}

/// A single structured verification finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationFinding {
    /// Stable machine-readable finding code.
    pub code: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub detail: String,
    pub session_id: Option<String>,
    pub event_id: Option<i64>,
    pub process_instance_id: Option<String>,
    /// Supporting evidence (already sanitized/redacted as appropriate).
    #[serde(default)]
    pub evidence: Vec<String>,
    /// Recommended interpretation or investigation action.
    pub recommendation: String,
}

impl VerificationFinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        code: impl Into<String>,
        severity: FindingSeverity,
        title: impl Into<String>,
        detail: impl Into<String>,
        session_id: Option<String>,
        event_id: Option<i64>,
        process_instance_id: Option<String>,
        evidence: Vec<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity,
            title: title.into(),
            detail: detail.into(),
            session_id,
            event_id,
            process_instance_id,
            evidence,
            recommendation: recommendation.into(),
        }
    }
}

/// Counts of findings by severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub info: usize,
    pub warning: usize,
    pub error: usize,
    pub critical: usize,
}

impl SeverityCounts {
    pub fn add(&mut self, severity: FindingSeverity) {
        match severity {
            FindingSeverity::Info => self.info += 1,
            FindingSeverity::Warning => self.warning += 1,
            FindingSeverity::Error => self.error += 1,
            FindingSeverity::Critical => self.critical += 1,
        }
    }

    pub fn total(self) -> usize {
        self.info + self.warning + self.error + self.critical
    }
}

/// Full verification result for a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionVerificationReport {
    pub session_id: String,
    pub verification_timestamp_ns: i64,
    pub database_schema_version: u32,
    pub session_status: Option<String>,
    pub assessment: VerificationAssessment,
    pub severity_counts: SeverityCounts,
    pub findings: Vec<VerificationFinding>,
    /// High-level limitations of this verification pass.
    #[serde(default)]
    pub limitations: Vec<String>,
}

impl SessionVerificationReport {
    pub fn compute_assessment(
        findings: &[VerificationFinding],
        unable: bool,
    ) -> VerificationAssessment {
        // Genuine contradictions/corruption take precedence.
        if findings.iter().any(|f| {
            matches!(
                f.severity,
                FindingSeverity::Error | FindingSeverity::Critical
            )
        }) {
            return VerificationAssessment::Invalid;
        }
        // Required checks could not be completed sufficiently.
        if unable {
            return VerificationAssessment::UnableToVerify;
        }
        let has_warning = findings
            .iter()
            .any(|f| f.severity == FindingSeverity::Warning);
        if !has_warning {
            return VerificationAssessment::Valid;
        }
        let incomplete = findings.iter().any(|f| {
            matches!(
                f.code.as_str(),
                "SESSION_RECOVERED"
                    | "SESSION_INCOMPLETE"
                    | "EVIDENCE_LOSS_RINGBUF"
                    | "EVIDENCE_LOSS_USERSPACE"
                    | "ACCOUNTING_INCOMPLETE"
                    | "ACCOUNTING_UNAVAILABLE_LEGACY"
                    | "PROVENANCE_UNAVAILABLE_LEGACY"
                    | "PROVENANCE_UNAVAILABLE"
                    | "FORK_IDENTITY_UNRESOLVED"
                    | "SESSION_RECOVERY_METADATA_MISSING"
                    | "EVENT_SCAN_TRUNCATED"
                    | "FINDINGS_TRUNCATED"
            )
        });
        if incomplete {
            VerificationAssessment::ValidButIncomplete
        } else {
            VerificationAssessment::Warning
        }
    }

    /// Count findings by severity.
    pub fn severity_counts(findings: &[VerificationFinding]) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        for f in findings {
            counts.add(f.severity);
        }
        counts
    }
}

/// Exit-code contract for `syscall verify`.
/// - 0: valid (internally consistent, no error/critical findings)
/// - 2: valid_but_incomplete or warning (consistent where checkable but incomplete/limited, or warnings without contradictions)
/// - 3: invalid (contradictory/corrupt/invalid evidence or state)
/// - 4: unable_to_verify (verification could not be completed sufficiently)
pub fn verify_exit_code(assessment: VerificationAssessment) -> i32 {
    match assessment {
        VerificationAssessment::Valid => 0,
        VerificationAssessment::ValidButIncomplete | VerificationAssessment::Warning => 2,
        VerificationAssessment::Invalid => 3,
        VerificationAssessment::UnableToVerify => 4,
    }
}
