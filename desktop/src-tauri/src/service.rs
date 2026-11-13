use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use syscall_analysis::{analyze, AnalysisOptions};
use syscall_core::{
    AddressFamily, AnalysisReport, AnalysisSeverity, Event, EventPayload, EventType,
    SessionVerificationReport,
};
use syscall_export::{export_json, ExportRequest as CoreExportRequest};
use syscall_storage::{ActivityFilter, SessionSummary, Storage, TimelineFilter};

use crate::contract::*;
use crate::error::{open_read_only, DesktopError};

const INTELLIGENCE_LIMIT: usize = 25;
const MAX_SEARCH_CHARS: usize = 200;

#[derive(Debug, Clone)]
pub struct DesktopService {
    database_path: PathBuf,
    export_directory: PathBuf,
}

impl DesktopService {
    pub fn new(database_path: impl Into<PathBuf>, export_directory: impl Into<PathBuf>) -> Self {
        Self {
            database_path: database_path.into(),
            export_directory: export_directory.into(),
        }
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn export_directory(&self) -> &Path {
        &self.export_directory
    }

    pub fn app_info(&self) -> AppInfo {
        AppInfo {
            contract_version: CONTRACT_VERSION.to_owned(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            database_path: self.database_path.display().to_string(),
            database_exists: self.database_path.exists(),
            read_only: true,
            export_directory: self.export_directory.display().to_string(),
            recording_supported: false,
        }
    }

    pub fn list_sessions(
        &self,
        request: ListSessionsRequest,
    ) -> Result<SessionListResponse, DesktopError> {
        let limit = request.limit.unwrap_or(100).clamp(1, MAX_SESSION_LIST);
        let search = normalize_search(request.search)?;
        let status = normalize_status_filter(request.status)?;
        let sort_by = normalize_sort(request.sort_by)?;
        let sort_direction = normalize_direction(request.sort_direction)?;
        let include_intelligence = request.include_intelligence.unwrap_or(true);

        let storage = open_read_only(&self.database_path)?;
        let mut summaries = storage.list_sessions(MAX_SESSION_LIST)?;
        if let Some(status) = &status {
            summaries.retain(|session| session.status.as_str() == status);
        }
        if let Some(search) = &search {
            summaries.retain(|session| session_matches(session, search));
        }

        let total_matched = summaries.len();
        let mut sessions = summaries.iter().map(basic_session_view).collect::<Vec<_>>();

        // Sorting by derived intelligence requires loading it before truncation;
        // otherwise the result depends on the storage's incidental row order.
        let sort_needs_all_intelligence =
            include_intelligence && matches!(sort_by, "findings" | "verification");
        if sort_needs_all_intelligence {
            for session in &mut sessions {
                let intelligence = load_intelligence(&storage, &session.id);
                apply_intelligence(session, intelligence);
            }
        }

        sort_session_views(&mut sessions, sort_by, sort_direction);
        sessions.truncate(limit);

        if include_intelligence && !sort_needs_all_intelligence {
            for session in sessions.iter_mut().take(INTELLIGENCE_LIMIT) {
                let intelligence = load_intelligence(&storage, &session.id);
                apply_intelligence(session, intelligence);
            }
        }
        let intelligence_limited = include_intelligence
            && !sort_needs_all_intelligence
            && total_matched > INTELLIGENCE_LIMIT;

        Ok(SessionListResponse {
            sessions,
            total_matched,
            intelligence_limited,
        })
    }

    pub fn overview(&self, request: OverviewRequest) -> Result<OverviewResponse, DesktopError> {
        let recent_limit = request.recent_limit.unwrap_or(8).clamp(1, 20);
        let response = self.list_sessions(ListSessionsRequest {
            limit: Some(MAX_SESSION_LIST),
            search: None,
            status: None,
            sort_by: Some("started".to_owned()),
            sort_direction: Some("desc".to_owned()),
            include_intelligence: Some(false),
        })?;
        let storage = open_read_only(&self.database_path)?;
        let all = storage.list_sessions(MAX_SESSION_LIST)?;

        let active_sessions = all
            .iter()
            .filter(|session| {
                matches!(
                    session.status,
                    syscall_storage::SessionStatus::Starting
                        | syscall_storage::SessionStatus::Recording
                )
            })
            .count();
        let completed_sessions = all
            .iter()
            .filter(|session| session.status == syscall_storage::SessionStatus::Completed)
            .count();
        let interrupted_sessions = all
            .iter()
            .filter(|session| session.status == syscall_storage::SessionStatus::Interrupted)
            .count();
        let recovered_sessions = all
            .iter()
            .filter(|session| session.status == syscall_storage::SessionStatus::Recovered)
            .count();
        let failed_sessions = all
            .iter()
            .filter(|session| session.status == syscall_storage::SessionStatus::Failed)
            .count();
        let sessions_with_loss = all
            .iter()
            .filter(|session| {
                session.ringbuf_lost_events > 0
                    || session.userspace_dropped_events > 0
                    || session.events_persist_failed > 0
            })
            .count();

        let mut recent_sessions = response.sessions;
        recent_sessions.truncate(recent_limit);
        let mut recent_finding_counts = FindingCountsView::default();
        for summary in recent_sessions.iter_mut().take(INTELLIGENCE_LIMIT) {
            let intelligence = load_intelligence(&storage, &summary.id);
            apply_intelligence(summary, intelligence);
            if let Some(counts) = &summary.finding_counts {
                add_finding_counts(&mut recent_finding_counts, counts);
            }
        }
        let latest_verification = recent_sessions
            .iter()
            .find_map(|session| session.verification.clone());

        Ok(OverviewResponse {
            total_sessions: all.len(),
            active_sessions,
            completed_sessions,
            interrupted_sessions,
            recovered_sessions,
            failed_sessions,
            sessions_with_loss,
            recent_sessions,
            recent_finding_counts,
            latest_verification,
        })
    }

    pub fn get_session(&self, request: SessionRequest) -> Result<SessionDetail, DesktopError> {
        validate_session_id(&request.session_id)?;
        let storage = open_read_only(&self.database_path)?;
        let summary = storage
            .get_session(&request.session_id)?
            .ok_or_else(|| DesktopError::SessionNotFound(request.session_id.clone()))?;
        let stats = storage
            .session_stats(&request.session_id)?
            .ok_or_else(|| DesktopError::SessionNotFound(request.session_id.clone()))?;
        let mut session = basic_session_view(&summary);
        apply_intelligence(
            &mut session,
            load_intelligence(&storage, &request.session_id),
        );
        let events_by_type = stats
            .events_by_type
            .into_iter()
            .map(|(event_type, count)| EventTypeCount { event_type, count })
            .collect();
        Ok(SessionDetail {
            session,
            stats: SessionStatsView {
                event_count: stats.event_count,
                process_count: stats.process_count,
                events_persisted: stats.events_persisted,
                events_by_type,
                ringbuf_lost_events: stats.ringbuf_lost_events,
                userspace_dropped_events: stats.userspace_dropped_events,
                dropped_events_total: stats.dropped_events_total,
                malformed_events: stats.malformed_events,
                filtered_events: stats.filtered_events,
                events_persist_failed: stats.events_persist_failed,
                events_self_filtered: stats.events_self_filtered,
                unresolved_identity_count: stats.unresolved_identity_count,
                evidence_may_be_incomplete: stats.evidence_may_be_incomplete,
                termination_reason: stats.termination_reason,
                target_exit_code: stats.target_exit_code,
                target_exit_signal: stats.target_exit_signal,
            },
        })
    }

    pub fn list_processes(
        &self,
        request: SessionRequest,
    ) -> Result<ProcessTreeResponse, DesktopError> {
        validate_session_id(&request.session_id)?;
        let storage = open_read_only(&self.database_path)?;
        require_session(&storage, &request.session_id)?;
        let instances = storage.list_process_instances(&request.session_id)?;
        Ok(build_process_tree(instances))
    }

    pub fn query_timeline(
        &self,
        request: TimelineRequest,
    ) -> Result<TimelineResponse, DesktopError> {
        validate_session_id(&request.session_id)?;
        validate_range(request.from_ns, request.to_ns)?;
        let event_type = request
            .event_type
            .as_deref()
            .map(EventType::from_str)
            .transpose()
            .map_err(|err| DesktopError::InvalidRequest(err.to_string()))?;
        let search = normalize_search(request.search)?;
        let limit = request.limit.unwrap_or(100).clamp(1, MAX_PAGE_SIZE);
        let offset = request.offset.unwrap_or(0).min(10_000_000);
        let storage = open_read_only(&self.database_path)?;
        require_session(&storage, &request.session_id)?;

        let mut filter = TimelineFilter::new(request.session_id.clone());
        filter.event_type = event_type;
        filter.pid = request.pid;
        filter.process_instance_id = request.process_instance_id;
        filter.from_ns = request.from_ns;
        filter.to_ns = request.to_ns;
        filter.search = search;
        filter.limit = Some(limit);
        filter.offset = offset;

        let total = storage.count_timeline(&filter)?;
        let events = storage
            .query_timeline(&filter)?
            .iter()
            .map(event_view)
            .collect::<Result<Vec<_>, _>>()?;
        let evidence_incomplete = storage
            .session_stats(&request.session_id)?
            .map(|stats| stats.evidence_may_be_incomplete)
            .unwrap_or(true);
        Ok(TimelineResponse {
            has_more: offset.saturating_add(events.len()) < total as usize,
            events,
            total,
            limit,
            offset,
            evidence_incomplete,
        })
    }

    pub fn query_filesystem(
        &self,
        request: ActivityRequest,
    ) -> Result<FileActivityResponse, DesktopError> {
        validate_session_id(&request.session_id)?;
        validate_range(request.from_ns, request.to_ns)?;
        if request.family.is_some() {
            return Err(DesktopError::InvalidRequest(
                "family filter applies only to network activity".to_owned(),
            ));
        }
        let search = normalize_search(request.search)?;
        let limit = request.limit.unwrap_or(100).clamp(1, MAX_PAGE_SIZE);
        let offset = request.offset.unwrap_or(0).min(10_000_000);
        let storage = open_read_only(&self.database_path)?;
        require_session(&storage, &request.session_id)?;

        let mut filter = ActivityFilter::new(request.session_id.clone());
        filter.pid = request.pid;
        filter.process_instance_id = request.process_instance_id;
        filter.from_ns = request.from_ns;
        filter.to_ns = request.to_ns;
        filter.success = request.success;
        filter.search = search;
        filter.limit = Some(limit);
        filter.offset = offset;

        let total = storage.count_file_activity(&filter)?;
        let files = storage
            .query_file_activity(&filter)?
            .into_iter()
            .map(|file| FileActivityView {
                event_id: file.event_id,
                timestamp_ns: file.timestamp_ns,
                pid: file.pid,
                process_instance_id: file.process_instance_id,
                comm: file.comm,
                path: file.path,
                path_is_absolute: file.path_is_absolute,
                path_truncated: file.path_truncated,
                dirfd: file.dirfd,
                flags: file.flags,
                result: file.result,
                success: file.success,
                errno: file.errno,
            })
            .collect::<Vec<_>>();
        let evidence_incomplete = evidence_incomplete(&storage, &request.session_id)?;
        Ok(FileActivityResponse {
            has_more: offset.saturating_add(files.len()) < total as usize,
            files,
            total,
            limit,
            offset,
            evidence_incomplete,
        })
    }

    pub fn query_network(
        &self,
        request: ActivityRequest,
    ) -> Result<ConnectionResponse, DesktopError> {
        validate_session_id(&request.session_id)?;
        validate_range(request.from_ns, request.to_ns)?;
        let family = request
            .family
            .as_deref()
            .map(AddressFamily::from_str)
            .transpose()
            .map_err(DesktopError::InvalidRequest)?;
        let search = normalize_search(request.search)?;
        let limit = request.limit.unwrap_or(100).clamp(1, MAX_PAGE_SIZE);
        let offset = request.offset.unwrap_or(0).min(10_000_000);
        let storage = open_read_only(&self.database_path)?;
        require_session(&storage, &request.session_id)?;

        let mut filter = ActivityFilter::new(request.session_id.clone());
        filter.pid = request.pid;
        filter.process_instance_id = request.process_instance_id;
        filter.from_ns = request.from_ns;
        filter.to_ns = request.to_ns;
        filter.success = request.success;
        filter.family = family;
        filter.search = search;
        filter.limit = Some(limit);
        filter.offset = offset;

        let total = storage.count_connection_activity(&filter)?;
        let connections = storage
            .query_connection_activity(&filter)?
            .into_iter()
            .map(|connection| ConnectionView {
                event_id: connection.event_id,
                timestamp_ns: connection.timestamp_ns,
                pid: connection.pid,
                process_instance_id: connection.process_instance_id,
                comm: connection.comm,
                family: connection.family.as_str().to_owned(),
                source_address: connection.source_address,
                source_port: connection.source_port,
                destination_address: connection.destination_address,
                destination_port: connection.destination_port,
                result: connection.result,
                success: connection.success,
                errno: connection.errno,
                established: connection.established,
            })
            .collect::<Vec<_>>();
        let evidence_incomplete = evidence_incomplete(&storage, &request.session_id)?;
        Ok(ConnectionResponse {
            has_more: offset.saturating_add(connections.len()) < total as usize,
            connections,
            total,
            limit,
            offset,
            evidence_incomplete,
        })
    }

    pub fn get_event(&self, request: EventRequest) -> Result<EvidenceDetail, DesktopError> {
        validate_session_id(&request.session_id)?;
        if request.event_id <= 0 {
            return Err(DesktopError::InvalidRequest(
                "event id must be positive".to_owned(),
            ));
        }
        let storage = open_read_only(&self.database_path)?;
        require_session(&storage, &request.session_id)?;
        let event = storage
            .get_event(&request.session_id, request.event_id)?
            .ok_or_else(|| {
                DesktopError::InvalidRequest(format!(
                    "event {} does not belong to session {}",
                    request.event_id, request.session_id
                ))
            })?;
        Ok(EvidenceDetail {
            event: event_view(&event)?,
        })
    }

    pub fn run_analysis(&self, request: SessionRequest) -> Result<AnalysisReport, DesktopError> {
        validate_session_id(&request.session_id)?;
        let storage = open_read_only(&self.database_path)?;
        require_session(&storage, &request.session_id)?;
        Ok(analyze(
            &storage,
            &request.session_id,
            AnalysisOptions::default(),
        )?)
    }

    pub fn run_verification(
        &self,
        request: SessionRequest,
    ) -> Result<SessionVerificationReport, DesktopError> {
        validate_session_id(&request.session_id)?;
        let storage = open_read_only(&self.database_path)?;
        require_session(&storage, &request.session_id)?;
        Ok(storage.verify_session(&request.session_id)?)
    }

    pub fn export_session(&self, request: ExportRequest) -> Result<ExportResult, DesktopError> {
        validate_session_id(&request.session_id)?;
        fs::create_dir_all(&self.export_directory).map_err(|err| {
            DesktopError::Export(format!("could not create export directory: {err}"))
        })?;
        fs::set_permissions(&self.export_directory, fs::Permissions::from_mode(0o700)).map_err(
            |err| DesktopError::Export(format!("could not secure export directory: {err}")),
        )?;
        let output = self
            .export_directory
            .join(format!("{}.json", request.session_id));
        if output.exists() && !request.force {
            return Err(DesktopError::Export(format!(
                "export already exists at {}; confirm overwrite to replace it",
                output.display()
            )));
        }
        let storage = open_read_only(&self.database_path)?;
        require_session(&storage, &request.session_id)?;
        let outcome = export_json(
            &storage,
            CoreExportRequest {
                session_id: request.session_id.clone(),
                output: output.clone(),
                force: request.force,
                database_path: self.database_path.clone(),
            },
        )
        .map_err(|err| DesktopError::Export(err.to_string()))?;
        Ok(ExportResult {
            session_id: request.session_id,
            output_path: outcome.output.display().to_string(),
            format_version: outcome.format_version,
            bytes_written: outcome.bytes_written,
            manifest: outcome
                .sha256_manifest
                .into_iter()
                .map(|entry| ExportManifestEntry {
                    component: entry.component,
                    format: entry.format,
                    version: entry.version,
                    sha256: entry.sha256,
                    byte_length: entry.byte_length,
                })
                .collect(),
            status: "exported".to_owned(),
        })
    }
}

fn require_session(storage: &Storage, session_id: &str) -> Result<SessionSummary, DesktopError> {
    storage
        .get_session(session_id)?
        .ok_or_else(|| DesktopError::SessionNotFound(session_id.to_owned()))
}

fn evidence_incomplete(storage: &Storage, session_id: &str) -> Result<bool, DesktopError> {
    Ok(storage
        .session_stats(session_id)?
        .map(|stats| stats.evidence_may_be_incomplete)
        .unwrap_or(true))
}

fn validate_session_id(value: &str) -> Result<(), DesktopError> {
    if value.is_empty() {
        return Err(DesktopError::InvalidRequest(
            "session id must not be empty".to_owned(),
        ));
    }
    if value.len() > 128 {
        return Err(DesktopError::InvalidRequest(
            "session id is too long".to_owned(),
        ));
    }
    if value == "." || value == ".." || value.contains(['/', '\\']) {
        return Err(DesktopError::InvalidRequest(
            "session id contains an unsafe path component".to_owned(),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(DesktopError::InvalidRequest(
            "session id contains control characters".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_search(value: Option<String>) -> Result<Option<String>, DesktopError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > MAX_SEARCH_CHARS {
        return Err(DesktopError::InvalidRequest(format!(
            "search text exceeds {MAX_SEARCH_CHARS} characters"
        )));
    }
    Ok(Some(value))
}

fn normalize_status_filter(value: Option<String>) -> Result<Option<String>, DesktopError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() || value == "all" {
        return Ok(None);
    }
    match value.as_str() {
        "starting" | "recording" | "completed" | "interrupted" | "failed" | "recovered"
        | "unknown" => Ok(Some(value)),
        _ => Err(DesktopError::InvalidRequest(format!(
            "unknown session status {value:?}"
        ))),
    }
}

fn normalize_sort(value: Option<String>) -> Result<&'static str, DesktopError> {
    match value.as_deref().unwrap_or("started") {
        "started" => Ok("started"),
        "status" => Ok("status"),
        "events" => Ok("events"),
        "processes" => Ok("processes"),
        "findings" => Ok("findings"),
        "verification" => Ok("verification"),
        other => Err(DesktopError::InvalidRequest(format!(
            "unknown session sort {other:?}"
        ))),
    }
}

fn normalize_direction(value: Option<String>) -> Result<&'static str, DesktopError> {
    match value.as_deref().unwrap_or("desc") {
        "asc" => Ok("asc"),
        "desc" => Ok("desc"),
        other => Err(DesktopError::InvalidRequest(format!(
            "unknown sort direction {other:?}"
        ))),
    }
}

fn validate_range(from: Option<i64>, to: Option<i64>) -> Result<(), DesktopError> {
    if let (Some(from), Some(to)) = (from, to) {
        if from > to {
            return Err(DesktopError::InvalidRequest(
                "fromNs must be less than or equal to toNs".to_owned(),
            ));
        }
    }
    Ok(())
}

fn session_matches(session: &SessionSummary, search: &str) -> bool {
    let needle = search.to_ascii_lowercase();
    session.id.to_ascii_lowercase().contains(&needle)
        || session.command.to_ascii_lowercase().contains(&needle)
        || session
            .arguments
            .iter()
            .any(|argument| argument.to_ascii_lowercase().contains(&needle))
        || session
            .status
            .as_str()
            .to_ascii_lowercase()
            .contains(&needle)
        || session
            .recording_scope
            .as_str()
            .to_ascii_lowercase()
            .contains(&needle)
}

fn basic_session_view(session: &SessionSummary) -> SessionView {
    let duration_ns = session
        .ended_at_ns
        .map(|ended| ended.saturating_sub(session.started_at_ns));
    let evidence_incomplete = session.ringbuf_lost_events > 0
        || session.userspace_dropped_events > 0
        || session.dropped_events > 0
        || session.malformed_events > 0
        || session.events_persist_failed > 0
        || matches!(
            session.status,
            syscall_storage::SessionStatus::Recovered
                | syscall_storage::SessionStatus::Interrupted
                | syscall_storage::SessionStatus::Starting
                | syscall_storage::SessionStatus::Recording
        );
    let mut command_parts = vec![session.command.clone()];
    command_parts.extend(session.arguments.iter().cloned());
    SessionView {
        id: session.id.clone(),
        status: session.status.as_str().to_owned(),
        command: session.command.clone(),
        arguments: session.arguments.clone(),
        command_display: command_parts.join(" "),
        recording_scope: session.recording_scope.as_str().to_owned(),
        started_at_ns: session.started_at_ns,
        ended_at_ns: session.ended_at_ns,
        duration_ns,
        process_count: session.process_count,
        event_count: session.event_count,
        dropped_events: session.dropped_events,
        ringbuf_lost_events: session.ringbuf_lost_events,
        userspace_dropped_events: session.userspace_dropped_events,
        malformed_events: session.malformed_events,
        filtered_events: session.filtered_events,
        persist_failed_events: session.events_persist_failed,
        evidence_incomplete,
        target_exit_code: session.target_exit_code,
        target_exit_signal: session.target_exit_signal,
        termination_reason: session.termination_reason.clone(),
        error: session.error.clone(),
        kernel_release: session.kernel_release.clone(),
        collector_version: session.collector_version.clone(),
        verification: None,
        finding_counts: None,
        intelligence_error: None,
    }
}

struct Intelligence {
    verification: Option<VerificationSummary>,
    findings: Option<FindingCountsView>,
    error: Option<String>,
}

fn load_intelligence(storage: &Storage, session_id: &str) -> Intelligence {
    let mut errors = Vec::new();
    let verification = match storage.verify_session(session_id) {
        Ok(report) => Some(verification_summary(&report)),
        Err(err) => {
            errors.push(format!("verification unavailable: {err}"));
            None
        }
    };
    let findings = match analyze(storage, session_id, AnalysisOptions::default()) {
        Ok(report) => Some(finding_counts(&report)),
        Err(err) => {
            errors.push(format!("analysis unavailable: {err}"));
            None
        }
    };
    Intelligence {
        verification,
        findings,
        error: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
    }
}

fn apply_intelligence(view: &mut SessionView, intelligence: Intelligence) {
    view.verification = intelligence.verification;
    view.finding_counts = intelligence.findings;
    view.intelligence_error = intelligence.error;
}

fn verification_summary(report: &SessionVerificationReport) -> VerificationSummary {
    VerificationSummary {
        assessment: report.assessment.as_str().to_owned(),
        counts: SeverityCountsView {
            info: report.severity_counts.info,
            warning: report.severity_counts.warning,
            error: report.severity_counts.error,
            critical: report.severity_counts.critical,
        },
        total_findings: report.severity_counts.total(),
        limitations: report.limitations.clone(),
    }
}

fn finding_counts(report: &AnalysisReport) -> FindingCountsView {
    let mut counts = FindingCountsView::default();
    for finding in &report.findings {
        match finding.severity {
            AnalysisSeverity::Informational => counts.informational += 1,
            AnalysisSeverity::Low => counts.low += 1,
            AnalysisSeverity::Medium => counts.medium += 1,
            AnalysisSeverity::High => counts.high += 1,
            AnalysisSeverity::Critical => counts.critical += 1,
        }
    }
    counts.total = report.findings.len();
    counts
}

fn add_finding_counts(target: &mut FindingCountsView, source: &FindingCountsView) {
    target.informational += source.informational;
    target.low += source.low;
    target.medium += source.medium;
    target.high += source.high;
    target.critical += source.critical;
    target.total += source.total;
}

fn sort_session_views(sessions: &mut [SessionView], sort_by: &str, direction: &str) {
    sessions.sort_by(|a, b| {
        let ordering = match sort_by {
            "status" => a.status.cmp(&b.status),
            "events" => a.event_count.cmp(&b.event_count),
            "processes" => a.process_count.cmp(&b.process_count),
            "findings" => a
                .finding_counts
                .as_ref()
                .map(|counts| counts.total)
                .unwrap_or(0)
                .cmp(
                    &b.finding_counts
                        .as_ref()
                        .map(|counts| counts.total)
                        .unwrap_or(0),
                ),
            "verification" => verification_rank(a).cmp(&verification_rank(b)),
            _ => a.started_at_ns.cmp(&b.started_at_ns),
        };
        let ordering = ordering.then_with(|| a.id.cmp(&b.id));
        if direction == "asc" {
            ordering
        } else {
            ordering.reverse()
        }
    });
}

fn verification_rank(session: &SessionView) -> u8 {
    match session
        .verification
        .as_ref()
        .map(|verification| verification.assessment.as_str())
    {
        Some("invalid") => 4,
        Some("unable_to_verify") => 3,
        Some("warning") => 2,
        Some("valid_but_incomplete") => 1,
        Some("valid") => 0,
        _ => 0,
    }
}

fn build_process_tree(
    instances: Vec<syscall_storage::ProcessInstanceEvidence>,
) -> ProcessTreeResponse {
    let ids: HashSet<String> = instances
        .iter()
        .map(|process| process.process_instance_id.clone())
        .collect();
    let mut parent_links: HashMap<String, String> = HashMap::new();
    for process in &instances {
        if let Some(parent) = &process.parent_process_instance_id {
            if parent != &process.process_instance_id && ids.contains(parent) {
                parent_links.insert(process.process_instance_id.clone(), parent.clone());
            }
        }
    }

    let mut notes = Vec::new();
    let mut cycle_edges = Vec::new();
    let process_ids: Vec<String> = parent_links.keys().cloned().collect();
    for start in process_ids {
        let mut seen = HashSet::new();
        let mut current = start.clone();
        while let Some(parent) = parent_links.get(&current) {
            if !seen.insert(parent.clone()) {
                cycle_edges.push(start.clone());
                break;
            }
            current = parent.clone();
        }
    }
    for id in cycle_edges {
        parent_links.remove(&id);
        notes.push(format!(
            "Removed a cyclic ancestry link for process instance {id}; relationship is unresolved."
        ));
    }

    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    for (child, parent) in &parent_links {
        children
            .entry(parent.clone())
            .or_default()
            .push(child.clone());
    }
    let order: HashMap<&str, usize> = instances
        .iter()
        .enumerate()
        .map(|(index, process)| (process.process_instance_id.as_str(), index))
        .collect();
    for values in children.values_mut() {
        values.sort_by_key(|id| order.get(id.as_str()).copied().unwrap_or(usize::MAX));
    }

    let mut roots = Vec::new();
    let mut processes = Vec::with_capacity(instances.len());
    let mut unresolved_ancestry_count = 0;
    let mut identity_unresolved_count = 0;
    for process in instances {
        if process.ancestry_unresolved {
            unresolved_ancestry_count += 1;
        }
        if process.identity_unresolved {
            identity_unresolved_count += 1;
        }
        let has_parent = parent_links.contains_key(&process.process_instance_id);
        let relationship = if has_parent {
            "observed"
        } else if process.ancestry_unresolved {
            "unresolved"
        } else {
            "root"
        };
        if !has_parent {
            roots.push(process.process_instance_id.clone());
        }
        processes.push(ProcessView {
            child_instance_ids: children
                .get(&process.process_instance_id)
                .cloned()
                .unwrap_or_default(),
            process_instance_id: process.process_instance_id,
            pid: process.pid,
            comm: process.comm,
            executable: process.executable,
            command_line: process.command_line,
            first_seen_ns: process.first_seen_ns,
            last_seen_ns: process.last_seen_ns,
            event_count: process.event_count,
            exit_observed: process.exit_observed,
            exit_priority: process.exit_priority,
            parent_pid: process.parent_pid,
            parent_process_instance_id: process.parent_process_instance_id,
            identity_unresolved: process.identity_unresolved,
            ancestry_unresolved: process.ancestry_unresolved,
            notes: process.notes,
            relationship: relationship.to_owned(),
        });
    }
    if unresolved_ancestry_count > 0 {
        notes.push(format!(
            "{unresolved_ancestry_count} process instance(s) have unresolved or ambiguous ancestry; they are not assigned invented parents."
        ));
    }
    ProcessTreeResponse {
        processes,
        roots,
        unresolved_ancestry_count,
        identity_unresolved_count,
        notes,
    }
}

fn event_view(event: &Event) -> Result<EventView, DesktopError> {
    let id = event
        .id
        .ok_or_else(|| DesktopError::Internal("persisted event has no row id".to_owned()))?;
    let payload = match &event.payload {
        EventPayload::ProcessExec {
            filename,
            process,
            old_pid,
        } => EventPayloadView::ProcessExec {
            filename: filename.clone(),
            ppid: process.ppid,
            start_time_ticks: process.start_time_ticks,
            old_pid: *old_pid,
        },
        EventPayload::ProcessFork {
            parent_pid,
            parent_tgid,
            child_pid,
            child_comm,
            child_start_time_ticks,
        } => EventPayloadView::ProcessFork {
            parent_pid: *parent_pid,
            parent_tgid: *parent_tgid,
            child_pid: *child_pid,
            child_comm: child_comm.clone(),
            child_start_time_ticks: *child_start_time_ticks,
        },
        EventPayload::ProcessExit {
            process,
            exit_priority,
        } => EventPayloadView::ProcessExit {
            ppid: process.ppid,
            start_time_ticks: process.start_time_ticks,
            exit_priority: *exit_priority,
        },
        EventPayload::FileOpen {
            path,
            path_is_absolute,
            path_truncated,
            dirfd,
            flags,
            result,
            success,
            errno,
        } => EventPayloadView::FileOpen {
            path: path.clone(),
            path_is_absolute: *path_is_absolute,
            path_truncated: *path_truncated,
            dirfd: *dirfd,
            flags: *flags,
            result: *result,
            success: *success,
            errno: *errno,
        },
        EventPayload::NetworkConnect {
            family,
            source_address,
            source_port,
            destination_address,
            destination_port,
            result,
            success,
            errno,
            established,
        } => EventPayloadView::NetworkConnect {
            family: family.as_str().to_owned(),
            source_address: source_address.clone(),
            source_port: *source_port,
            destination_address: destination_address.clone(),
            destination_port: *destination_port,
            result: *result,
            success: *success,
            errno: *errno,
            established: *established,
        },
    };
    let provenance = event.provenance.as_ref().map(|provenance| ProvenanceView {
        raw_bpf_pid: provenance.raw_bpf_pid,
        raw_bpf_tgid: provenance.raw_bpf_tgid,
        observer_pid: provenance.observer_pid,
        observer_tgid: provenance.observer_tgid,
        source_tracepoint: provenance.source_tracepoint.clone(),
        wire_schema_version: provenance.wire_schema_version,
        attribution_method: provenance.attribution_method.clone(),
        timestamp_clock_domain: provenance.timestamp_clock_domain.clone(),
        monotonic_clock_domain: provenance.monotonic_clock_domain.clone(),
    });
    Ok(EventView {
        id,
        event_type: event.event_type.as_str().to_owned(),
        timestamp_ns: event.timestamp_ns,
        monotonic_ns: event.monotonic_ns,
        pid: event.pid,
        tid: event.tid,
        uid: event.uid,
        gid: event.gid,
        ppid: event.ppid,
        comm: event.comm.clone(),
        process_instance_id: event.process_instance_id.clone(),
        payload,
        provenance,
    })
}
