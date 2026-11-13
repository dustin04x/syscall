//! Shared domain model for SYSCALL.
//!
//! This crate deliberately has no dependency on eBPF, SQLite, or the CLI. It
//! defines the versioned event schema, process identity rules, clock helpers,
//! and the recording-scope vocabulary used by every other crate.

pub mod analysis;
pub mod clock;
pub mod error;
pub mod event;
pub mod ids;
pub mod paths;
pub mod scope;
pub mod timefmt;
pub mod verify;

pub use analysis::{
    AnalysisConfidence, AnalysisFinding, AnalysisProcessRef, AnalysisReport, AnalysisRuleMetadata,
    AnalysisSeverity, AnalysisTimeRange, EvidenceCompleteness, SupportingEvent,
    ANALYSIS_SCHEMA_VERSION,
};
pub use error::{CoreError, Result};
pub use event::{
    AddressFamily, Event, EventPayload, EventProvenance, EventType, ProcessMetadata, COMM_LEN,
    MAX_FILENAME_LEN, MIN_READABLE_SCHEMA_VERSION, SCHEMA_VERSION,
};
pub use scope::RecordingScope;

pub use verify::{
    verify_exit_code, FindingSeverity, SessionVerificationReport, SeverityCounts,
    VerificationAssessment, VerificationFinding,
};
