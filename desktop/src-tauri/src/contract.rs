//! Versioned request/response contract between the Rust backend and the
//! TypeScript workbench. Serde produces camelCase JSON; no raw SQL or database
//! path is accepted from the frontend.

use serde::{Deserialize, Serialize};

pub const CONTRACT_VERSION: &str = "syscall-desktop/v2";
pub const MAX_SESSION_LIST: usize = 500;
pub const MAX_PAGE_SIZE: usize = 500;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSessionsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub sort_by: Option<String>,
    #[serde(default)]
    pub sort_direction: Option<String>,
    #[serde(default)]
    pub include_intelligence: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewRequest {
    #[serde(default)]
    pub recent_limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    pub session_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineRequest {
    pub session_id: String,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub pid: Option<i32>,
    #[serde(default)]
    pub process_instance_id: Option<String>,
    #[serde(default)]
    pub from_ns: Option<i64>,
    #[serde(default)]
    pub to_ns: Option<i64>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityRequest {
    pub session_id: String,
    #[serde(default)]
    pub pid: Option<i32>,
    #[serde(default)]
    pub process_instance_id: Option<String>,
    #[serde(default)]
    pub from_ns: Option<i64>,
    #[serde(default)]
    pub to_ns: Option<i64>,
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRequest {
    pub session_id: String,
    pub event_id: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportRequest {
    pub session_id: String,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub contract_version: String,
    pub app_version: String,
    pub database_path: String,
    pub database_exists: bool,
    pub read_only: bool,
    pub export_directory: String,
    pub recording_supported: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCountsView {
    pub info: usize,
    pub warning: usize,
    pub error: usize,
    pub critical: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingCountsView {
    pub informational: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationSummary {
    pub assessment: String,
    pub counts: SeverityCountsView,
    pub total_findings: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    pub id: String,
    pub status: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub command_display: String,
    pub recording_scope: String,
    pub started_at_ns: i64,
    pub ended_at_ns: Option<i64>,
    pub duration_ns: Option<i64>,
    pub process_count: i64,
    pub event_count: i64,
    pub dropped_events: u64,
    pub ringbuf_lost_events: u64,
    pub userspace_dropped_events: u64,
    pub malformed_events: u64,
    pub filtered_events: u64,
    pub persist_failed_events: u64,
    pub evidence_incomplete: bool,
    pub target_exit_code: Option<i32>,
    pub target_exit_signal: Option<i32>,
    pub termination_reason: Option<String>,
    pub error: Option<String>,
    pub kernel_release: Option<String>,
    pub collector_version: Option<String>,
    pub verification: Option<VerificationSummary>,
    pub finding_counts: Option<FindingCountsView>,
    pub intelligence_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionListResponse {
    pub sessions: Vec<SessionView>,
    pub total_matched: usize,
    pub intelligence_limited: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewResponse {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub completed_sessions: usize,
    pub interrupted_sessions: usize,
    pub recovered_sessions: usize,
    pub failed_sessions: usize,
    pub sessions_with_loss: usize,
    pub recent_sessions: Vec<SessionView>,
    pub recent_finding_counts: FindingCountsView,
    pub latest_verification: Option<VerificationSummary>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatsView {
    pub event_count: i64,
    pub process_count: i64,
    pub events_persisted: u64,
    pub events_by_type: Vec<EventTypeCount>,
    pub ringbuf_lost_events: u64,
    pub userspace_dropped_events: u64,
    pub dropped_events_total: u64,
    pub malformed_events: u64,
    pub filtered_events: u64,
    pub events_persist_failed: u64,
    pub events_self_filtered: u64,
    pub unresolved_identity_count: u64,
    pub evidence_may_be_incomplete: bool,
    pub termination_reason: Option<String>,
    pub target_exit_code: Option<i32>,
    pub target_exit_signal: Option<i32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventTypeCount {
    pub event_type: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetail {
    pub session: SessionView,
    pub stats: SessionStatsView,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessView {
    pub process_instance_id: String,
    pub pid: i32,
    pub comm: String,
    pub executable: Option<String>,
    pub command_line: Option<String>,
    pub first_seen_ns: i64,
    pub last_seen_ns: i64,
    pub event_count: u64,
    pub exit_observed: bool,
    pub exit_priority: Option<i32>,
    pub parent_pid: Option<i32>,
    pub parent_process_instance_id: Option<String>,
    pub identity_unresolved: bool,
    pub ancestry_unresolved: bool,
    pub notes: Vec<String>,
    pub child_instance_ids: Vec<String>,
    pub relationship: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTreeResponse {
    pub processes: Vec<ProcessView>,
    pub roots: Vec<String>,
    pub unresolved_ancestry_count: usize,
    pub identity_unresolved_count: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventView {
    pub id: i64,
    pub event_type: String,
    pub timestamp_ns: i64,
    pub monotonic_ns: u64,
    pub pid: i32,
    pub tid: i32,
    pub uid: u32,
    pub gid: u32,
    pub ppid: Option<i32>,
    pub comm: String,
    pub process_instance_id: String,
    pub payload: EventPayloadView,
    pub provenance: Option<ProvenanceView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum EventPayloadView {
    ProcessExec {
        filename: String,
        ppid: Option<i32>,
        start_time_ticks: Option<u64>,
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
        ppid: Option<i32>,
        start_time_ticks: Option<u64>,
        exit_priority: i32,
    },
    FileOpen {
        path: String,
        path_is_absolute: bool,
        path_truncated: bool,
        dirfd: i32,
        flags: u32,
        result: i64,
        success: bool,
        errno: Option<i32>,
    },
    NetworkConnect {
        family: String,
        source_address: Option<String>,
        source_port: Option<u16>,
        destination_address: String,
        destination_port: u16,
        result: i64,
        success: bool,
        errno: Option<i32>,
        established: bool,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvenanceView {
    pub raw_bpf_pid: Option<i32>,
    pub raw_bpf_tgid: Option<i32>,
    pub observer_pid: Option<i32>,
    pub observer_tgid: Option<i32>,
    pub source_tracepoint: Option<String>,
    pub wire_schema_version: Option<u16>,
    pub attribution_method: Option<String>,
    pub timestamp_clock_domain: Option<String>,
    pub monotonic_clock_domain: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineResponse {
    pub events: Vec<EventView>,
    pub total: u64,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
    pub evidence_incomplete: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileActivityView {
    pub event_id: i64,
    pub timestamp_ns: i64,
    pub pid: i32,
    pub process_instance_id: String,
    pub comm: String,
    pub path: String,
    pub path_is_absolute: bool,
    pub path_truncated: bool,
    pub dirfd: i32,
    pub flags: u32,
    pub result: i64,
    pub success: bool,
    pub errno: Option<i32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileActivityResponse {
    pub files: Vec<FileActivityView>,
    pub total: u64,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
    pub evidence_incomplete: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionView {
    pub event_id: i64,
    pub timestamp_ns: i64,
    pub pid: i32,
    pub process_instance_id: String,
    pub comm: String,
    pub family: String,
    pub source_address: Option<String>,
    pub source_port: Option<u16>,
    pub destination_address: String,
    pub destination_port: u16,
    pub result: i64,
    pub success: bool,
    pub errno: Option<i32>,
    pub established: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionResponse {
    pub connections: Vec<ConnectionView>,
    pub total: u64,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
    pub evidence_incomplete: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportManifestEntry {
    pub component: String,
    pub format: String,
    pub version: String,
    pub sha256: String,
    pub byte_length: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    pub session_id: String,
    pub output_path: String,
    pub format_version: String,
    pub bytes_written: usize,
    pub manifest: Vec<ExportManifestEntry>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDetail {
    pub event: EventView,
}
