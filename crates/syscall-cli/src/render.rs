//! Deterministic text and JSON rendering.
//!
//! Text output is plain ASCII-safe: control characters in process names,
//! filenames, and command arguments are escaped so untrusted kernel data cannot
//! inject terminal escape sequences. Timestamps are always UTC.

use anyhow::Result;
use serde_json::{json, Value};
use syscall_collector::{EnvironmentReport, RecordReport};
use syscall_core::timefmt::{format_duration_ns, format_unix_ns_utc};
use syscall_core::{
    AnalysisReport, AnalysisSeverity, Event, EventPayload, SessionVerificationReport,
};
use syscall_storage::{EventQuery, ProcessSummary, SessionSummary};

const ELLIPSIS: &str = "...";

/// Escape control characters and truncate to `width` characters.
pub fn sanitize(value: &str, width: usize) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }

    if escaped.chars().count() <= width {
        return escaped;
    }
    if width <= ELLIPSIS.len() {
        return ELLIPSIS.chars().take(width).collect();
    }
    let mut truncated = escaped
        .chars()
        .take(width - ELLIPSIS.len())
        .collect::<String>();
    truncated.push_str(ELLIPSIS);
    truncated
}

fn render_table(headers: &[&str], widths: &[usize], rows: &[Vec<String>]) -> String {
    debug_assert_eq!(headers.len(), widths.len());
    let mut output = String::new();

    let header = headers
        .iter()
        .zip(widths)
        .map(|(title, width)| sanitize(title, *width))
        .collect::<Vec<_>>();
    output.push_str(join_cells(&header, widths).trim_end());
    output.push('\n');

    let separator = widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<_>>();
    output.push_str(join_cells(&separator, widths).trim_end());
    output.push('\n');

    for row in rows {
        let cells = row
            .iter()
            .zip(widths)
            .map(|(cell, width)| sanitize(cell, *width))
            .collect::<Vec<_>>();
        output.push_str(join_cells(&cells, widths).trim_end());
        output.push('\n');
    }
    output
}

fn join_cells(cells: &[String], widths: &[usize]) -> String {
    cells
        .iter()
        .zip(widths)
        .map(|(cell, width)| format!("{cell:<width$}"))
        .collect::<Vec<_>>()
        .join("  ")
}

fn command_line(session: &SessionSummary) -> String {
    if session.arguments.is_empty() {
        session.command.clone()
    } else {
        format!("{} {}", session.command, session.arguments.join(" "))
    }
}

fn optional_time(ns: Option<i64>) -> String {
    ns.map(format_unix_ns_utc).unwrap_or_else(|| "-".to_owned())
}

fn session_duration(session: &SessionSummary) -> String {
    match session.ended_at_ns {
        Some(ended) => format_duration_ns(ended.saturating_sub(session.started_at_ns)),
        None => "active".to_owned(),
    }
}

pub fn render_sessions(sessions: &[SessionSummary]) -> String {
    if sessions.is_empty() {
        return "No sessions recorded.\n".to_owned();
    }

    let headers = [
        "ID",
        "STATUS",
        "STARTED (UTC)",
        "DURATION",
        "EVENTS",
        "PROCS",
        "SCOPE",
        "COMMAND",
    ];
    let widths = [34, 11, 33, 10, 8, 7, 12, 48];
    let rows = sessions
        .iter()
        .map(|session| {
            vec![
                session.id.clone(),
                session.status.to_string(),
                format_unix_ns_utc(session.started_at_ns),
                session_duration(session),
                session.event_count.to_string(),
                session.process_count.to_string(),
                session.recording_scope.to_string(),
                command_line(session),
            ]
        })
        .collect::<Vec<_>>();

    render_table(&headers, &widths, &rows)
}

pub fn render_sessions_json(sessions: &[SessionSummary]) -> Result<String> {
    let values = sessions.iter().map(session_json).collect::<Vec<Value>>();
    to_json(&Value::Array(values))
}

fn session_json(session: &SessionSummary) -> Value {
    json!({
        "id": session.id,
        "schema_version": session.schema_version,
        "started_at_ns": session.started_at_ns,
        "started_at": format_unix_ns_utc(session.started_at_ns),
        "ended_at_ns": session.ended_at_ns,
        "ended_at": session.ended_at_ns.map(format_unix_ns_utc),
        "duration_ns": session.ended_at_ns.map(|ended| ended.saturating_sub(session.started_at_ns)),
        "command": session.command,
        "arguments": session.arguments,
        "recording_scope": session.recording_scope.as_str(),
        "status": session.status.as_str(),
        "boot_id": session.boot_id,
        "kernel_release": session.kernel_release,
        "collector_version": session.collector_version,
        "dropped_events": session.dropped_events,
        "ringbuf_lost_events": session.ringbuf_lost_events,
        "userspace_dropped_events": session.userspace_dropped_events,
        "malformed_events": session.malformed_events,
        "filtered_events": session.filtered_events,
        "error": session.error,
        "event_count": session.event_count,
        "process_count": session.process_count,
    })
}

pub fn render_inspect(
    session: &SessionSummary,
    type_counts: &[(syscall_core::EventType, u64)],
    processes: &[ProcessSummary],
    database_path: &std::path::Path,
) -> String {
    let mut output = String::new();
    output.push_str(&format!("Session {}\n", session.id));
    output.push_str(&format!("  Status:      {}\n", session.status));
    output.push_str(&format!(
        "  Scope:       {} ({})\n",
        session.recording_scope,
        session.recording_scope.description()
    ));
    output.push_str(&format!("  Command:     {}\n", command_line(session)));
    output.push_str(&format!(
        "  Started:     {}\n",
        format_unix_ns_utc(session.started_at_ns)
    ));
    output.push_str(&format!(
        "  Ended:       {}\n",
        optional_time(session.ended_at_ns)
    ));
    output.push_str(&format!("  Duration:    {}\n", session_duration(session)));
    output.push_str(&format!(
        "  Boot ID:     {}\n",
        session.boot_id.as_deref().unwrap_or("-")
    ));
    output.push_str(&format!(
        "  Kernel:      {}\n",
        session.kernel_release.as_deref().unwrap_or("-")
    ));
    output.push_str(&format!(
        "  Collector:   {}\n",
        session.collector_version.as_deref().unwrap_or("-")
    ));
    output.push_str(&format!(
        "  Session/core schema: {}\n",
        session.schema_version
    ));
    output.push_str(&format!("  Database:    {}\n", database_path.display()));
    if let Some(error) = &session.error {
        output.push_str(&format!("  Error:       {}\n", sanitize(error, 512)));
    }

    output.push_str("\nCounters\n");
    output.push_str(&format!(
        "  Events:                {}\n",
        session.event_count
    ));
    output.push_str(&format!(
        "  Processes:             {}\n",
        session.process_count
    ));
    output.push_str(&format!(
        "  Ring-buffer lost:      {}\n",
        session.ringbuf_lost_events
    ));
    output.push_str(&format!(
        "  Userspace dropped:     {}\n",
        session.userspace_dropped_events
    ));
    output.push_str(&format!(
        "  Filtered by scope:     {}\n",
        session.filtered_events
    ));
    output.push_str(&format!(
        "  Malformed:             {}\n",
        session.malformed_events
    ));
    output.push_str(&format!(
        "  Total dropped:         {}\n",
        session.dropped_events
    ));

    output.push_str("\nEvent types\n");
    if type_counts.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for (event_type, count) in type_counts {
            output.push_str(&format!("  {:<16} {count}\n", event_type.as_str()));
        }
    }

    output.push_str("\nProcesses (most active first)\n");
    if processes.is_empty() {
        output.push_str("  (none)\n");
    } else {
        let headers = [
            "PID",
            "COMM",
            "EVENTS",
            "EXITED",
            "FIRST SEEN (UTC)",
            "LAST SEEN (UTC)",
            "PROCESS INSTANCE",
        ];
        let widths = [8, 16, 7, 7, 33, 33, 52];
        let rows = processes
            .iter()
            .map(|process| {
                vec![
                    process.pid.to_string(),
                    process.comm.clone(),
                    process.event_count.to_string(),
                    if process.exited { "yes" } else { "no" }.to_owned(),
                    format_unix_ns_utc(process.first_seen_ns),
                    format_unix_ns_utc(process.last_seen_ns),
                    process.process_instance_id.clone(),
                ]
            })
            .collect::<Vec<_>>();
        output.push_str(&render_table(&headers, &widths, &rows));
    }

    output
}

pub fn render_inspect_json(
    session: &SessionSummary,
    type_counts: &[(syscall_core::EventType, u64)],
    processes: &[ProcessSummary],
    database_path: &std::path::Path,
) -> Result<String> {
    let mut value = session_json(session);
    let object = value
        .as_object_mut()
        .expect("session_json always produces an object");
    object.insert(
        "database_path".to_owned(),
        Value::String(database_path.display().to_string()),
    );
    object.insert(
        "event_type_counts".to_owned(),
        Value::Array(
            type_counts
                .iter()
                .map(|(event_type, count)| {
                    json!({
                        "event_type": event_type.as_str(),
                        "count": count,
                    })
                })
                .collect(),
        ),
    );
    object.insert(
        "processes".to_owned(),
        Value::Array(
            processes
                .iter()
                .map(|process| {
                    json!({
                        "process_instance_id": process.process_instance_id,
                        "pid": process.pid,
                        "comm": process.comm,
                        "first_seen_ns": process.first_seen_ns,
                        "first_seen": format_unix_ns_utc(process.first_seen_ns),
                        "last_seen_ns": process.last_seen_ns,
                        "last_seen": format_unix_ns_utc(process.last_seen_ns),
                        "event_count": process.event_count,
                        "exited": process.exited,
                    })
                })
                .collect(),
        ),
    );
    to_json(&value)
}

fn event_details(event: &Event) -> String {
    match &event.payload {
        EventPayload::ProcessExec {
            filename, old_pid, ..
        } => match old_pid {
            Some(old_pid) => format!("filename={filename} old_pid={old_pid}"),
            None => format!("filename={filename}"),
        },
        EventPayload::ProcessFork {
            parent_pid,
            child_pid,
            child_comm,
            ..
        } => format!("child={child_pid} parent={parent_pid} child_comm={child_comm}"),
        EventPayload::ProcessExit { exit_priority, .. } => {
            format!("exit_priority={exit_priority}")
        }
        EventPayload::FileOpen {
            path,
            path_is_absolute,
            path_truncated,
            flags,
            result,
            success,
            errno,
            ..
        } => {
            let mut detail = format!(
                "path={path} absolute={path_is_absolute} truncated={path_truncated} flags=0x{flags:x} result={result} {}",
                if *success { "success" } else { "failed" }
            );
            if let Some(errno) = errno {
                detail.push_str(&format!(" errno={errno}"));
            }
            detail
        }
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
        } => {
            let source = match (source_address, source_port) {
                (Some(address), Some(port)) => format!(" source={address}:{port}"),
                _ => " source=unavailable".to_owned(),
            };
            let mut detail = format!(
                "family={family}{source} destination={destination_address}:{destination_port} result={result} {} established={established}",
                if *success { "success" } else { "failed" }
            );
            if let Some(errno) = errno {
                detail.push_str(&format!(" errno={errno}"));
            }
            detail
        }
    }
}

pub fn render_events(events: &[Event], query: &EventQuery) -> String {
    if events.is_empty() {
        return format!("No events matched in session {}.\n", query.session_id);
    }

    let headers = ["ID", "TIME (UTC)", "TYPE", "PID", "PPID", "COMM", "DETAILS"];
    let widths = [8, 33, 13, 7, 7, 16, 80];
    let rows = events
        .iter()
        .map(|event| {
            vec![
                event
                    .id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                format_unix_ns_utc(event.timestamp_ns),
                event.event_type.to_string(),
                event.pid.to_string(),
                event
                    .ppid
                    .map(|ppid| ppid.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                event.comm.clone(),
                event_details(event),
            ]
        })
        .collect::<Vec<_>>();

    render_table(&headers, &widths, &rows)
}

pub fn render_events_json(events: &[Event]) -> Result<String> {
    to_json(&serde_json::to_value(events)?)
}

pub fn render_record(report: &RecordReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("Recorded session {}\n", report.session_id));
    output.push_str(&format!(
        "  Database:              {}\n",
        report.database_path.display()
    ));
    output.push_str(&format!("  Status:                {}\n", report.status));
    output.push_str(&format!(
        "  Duration:              {}\n",
        format_duration_ns(report.duration_ns)
    ));
    output.push_str(&format!(
        "  Events persisted:      {}\n",
        report.events_persisted
    ));
    output.push_str(&format!(
        "  Filtered by scope:     {}\n",
        report.events_filtered
    ));
    output.push_str(&format!(
        "  Collector self-filtered: {}\n",
        report.events_self_filtered
    ));
    output.push_str(&format!(
        "  Malformed:             {}\n",
        report.malformed_events
    ));
    output.push_str(&format!(
        "  Ring-buffer lost:      {}\n",
        report.ringbuf_lost_events
    ));
    output.push_str(&format!(
        "  Userspace dropped:     {}\n",
        report.userspace_dropped_events
    ));
    if report.rejections.ring_samples > 0
        || report.rejections.decoded > 0
        || report.rejections.thread_context > 0
        || report.rejections.out_of_scope > 0
    {
        output.push_str(&format!(
            "  Ring samples:          {} (decoded {}, exec {}, fork {}, exit {})\n",
            report.rejections.ring_samples,
            report.rejections.decoded,
            report.rejections.decoded_exec,
            report.rejections.decoded_fork,
            report.rejections.decoded_exit,
        ));
        output.push_str(&format!(
            "  Rejections:            thread-context {}, out-of-scope {}\n",
            report.rejections.thread_context, report.rejections.out_of_scope,
        ));
    }
    match report.target {
        Some(target) => {
            if let Some(code) = target.exit_code {
                output.push_str(&format!("  Target:                exit code {code}\n"));
            } else if let Some(signal) = target.signal {
                output.push_str(&format!("  Target:                signal {signal}\n"));
            } else {
                output.push_str("  Target:                terminated\n");
            }
        }
        None => output.push_str("  Target:                unknown\n"),
    }
    if report.interrupted {
        output.push_str("  Interrupted:           yes\n");
    }
    output
}

pub fn render_record_json(report: &RecordReport) -> Result<String> {
    to_json(&json!({
        "session_id": report.session_id,
        "status": report.status.as_str(),
        "database_path": report.database_path.display().to_string(),
        "duration_ns": report.duration_ns,
        "events_persisted": report.events_persisted,
        "events_filtered": report.events_filtered,
        "events_self_filtered": report.events_self_filtered,
        "malformed_events": report.malformed_events,
        "ringbuf_lost_events": report.ringbuf_lost_events,
        "userspace_dropped_events": report.userspace_dropped_events,
        "rejections": {
            "ring_samples": report.rejections.ring_samples,
            "decoded": report.rejections.decoded,
            "decoded_exec": report.rejections.decoded_exec,
            "decoded_fork": report.rejections.decoded_fork,
            "decoded_exit": report.rejections.decoded_exit,
            "thread_context": report.rejections.thread_context,
            "out_of_scope": report.rejections.out_of_scope,
        },
        "interrupted": report.interrupted,
        "interrupt_signal": report.interrupt_signal,
        "target": report.target.map(|target| json!({
            "exit_code": target.exit_code,
            "signal": target.signal,
        })),
    }))
}

pub fn render_info(report: &EnvironmentReport, database_path: &std::path::Path) -> String {
    let mut output = String::new();
    output.push_str(&format!("SYSCALL {}\n", env!("CARGO_PKG_VERSION")));
    output.push_str(&format!(
        "  OS:                   {}\n",
        report.os_release.as_deref().unwrap_or("unknown")
    ));
    output.push_str(&format!(
        "  Kernel:               {}\n",
        report.kernel_release.as_deref().unwrap_or("unknown")
    ));
    output.push_str(&format!(
        "  WSL2:                 {}\n",
        if report.is_wsl { "yes" } else { "no" }
    ));
    output.push_str(&format!(
        "  Core schema:          {}\n",
        report.core_schema_version
    ));
    output.push_str(&format!(
        "  BPF wire schema:      {}\n",
        report.wire_schema_version
    ));
    output.push_str(&format!(
        "  BTF:                  {} ({})\n",
        report.btf_path,
        if report.btf_available {
            "present"
        } else {
            "missing"
        }
    ));
    output.push_str(&format!(
        "  Tracefs:              {} (events readable: {})\n",
        report.tracefs_root.as_deref().unwrap_or("not found"),
        if report.tracefs_events_readable {
            "yes"
        } else {
            "no"
        }
    ));

    output.push_str("  Tracepoints:\n");
    for tracepoint in &report.tracepoints {
        let status = match tracepoint.available {
            Some(true) => "available",
            Some(false) => "missing",
            None => "unknown (tracefs not readable)",
        };
        output.push_str(&format!("    {:<22} {status}\n", tracepoint.name));
    }

    output.push_str(&format!(
        "  Ring buffer support:  {}\n",
        if report.ringbuf_kernel_support {
            "yes (kernel >= 5.8)"
        } else {
            "no"
        }
    ));

    let privilege = &report.privilege;
    output.push_str(&format!(
        "  Effective UID:        {}\n",
        privilege.effective_uid
    ));
    output.push_str(&format!(
        "  Capabilities:         CAP_BPF={} CAP_PERFMON={} CAP_SYS_ADMIN={}\n",
        yes_no(privilege.cap_bpf),
        yes_no(privilege.cap_perfmon),
        yes_no(privilege.cap_sys_admin)
    ));
    output.push_str(&format!(
        "  unprivileged_bpf:     {}\n",
        privilege
            .unprivileged_bpf_disabled
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned())
    ));
    output.push_str(&format!(
        "  Can load eBPF:        {} ({})\n",
        yes_no(privilege.can_load_bpf),
        privilege.reason
    ));

    output.push_str(&format!(
        "  Database:             {} ({})\n",
        database_path.display(),
        if report.database_exists {
            "present"
        } else {
            "not created"
        }
    ));
    output.push_str(&format!(
        "  Collected:            {}\n",
        report
            .collected_event_types
            .iter()
            .map(|event_type| event_type.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output.push_str(&format!(
        "  Schema-only:          {}\n",
        report
            .schema_only_event_types
            .iter()
            .map(|event_type| event_type.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    output
}

pub fn render_info_json(
    report: &EnvironmentReport,
    database_path: &std::path::Path,
) -> Result<String> {
    let privilege = &report.privilege;
    to_json(&json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os_release": report.os_release,
        "kernel_release": report.kernel_release,
        "wsl": report.is_wsl,
        "core_schema_version": report.core_schema_version,
        "wire_schema_version": report.wire_schema_version,
        "btf": {
            "path": report.btf_path,
            "available": report.btf_available,
        },
        "tracefs": {
            "root": report.tracefs_root,
            "events_readable": report.tracefs_events_readable,
        },
        "tracepoints": report.tracepoints.iter().map(|tracepoint| json!({
            "name": tracepoint.name,
            "available": tracepoint.available,
        })).collect::<Vec<_>>(),
        "ringbuf_kernel_support": report.ringbuf_kernel_support,
        "privileges": {
            "effective_uid": privilege.effective_uid,
            "cap_effective": privilege.cap_effective,
            "cap_bpf": privilege.cap_bpf,
            "cap_perfmon": privilege.cap_perfmon,
            "cap_sys_admin": privilege.cap_sys_admin,
            "unprivileged_bpf_disabled": privilege.unprivileged_bpf_disabled,
            "can_load_bpf": privilege.can_load_bpf,
            "reason": privilege.reason,
        },
        "database": {
            "path": database_path.display().to_string(),
            "exists": report.database_exists,
        },
        "event_types": {
            "collected": report.collected_event_types.iter().map(|event_type| event_type.as_str()).collect::<Vec<_>>(),
            "schema_only": report.schema_only_event_types.iter().map(|event_type| event_type.as_str()).collect::<Vec<_>>(),
        },
    }))
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn to_json(value: &Value) -> Result<String> {
    let mut output = serde_json::to_string_pretty(value)?;
    output.push('\n');
    Ok(output)
}

pub fn render_verify(
    report: &SessionVerificationReport,
    database_path: &std::path::Path,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("Session {}\n", report.session_id));
    out.push_str(&format!("  Database:    {}\n", database_path.display()));
    out.push_str(&format!(
        "  DB schema:   {}\n",
        report.database_schema_version
    ));
    out.push_str(&format!(
        "  Status:      {}\n",
        report.session_status.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!(
        "  Verified at: {}\n",
        format_unix_ns_utc(report.verification_timestamp_ns)
    ));
    out.push_str(&format!(
        "  Assessment:  {} ({})\n",
        report.assessment.as_str(),
        assessment_label(report.assessment)
    ));
    out.push_str("\nSeverity summary\n");
    out.push_str(&format!(
        "  Critical: {}\n",
        report.severity_counts.critical
    ));
    out.push_str(&format!("  Error:    {}\n", report.severity_counts.error));
    out.push_str(&format!("  Warning:  {}\n", report.severity_counts.warning));
    out.push_str(&format!("  Info:     {}\n", report.severity_counts.info));
    out.push_str(&format!("  Total:    {}\n", report.severity_counts.total()));

    out.push_str("\nFindings\n");
    if report.findings.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (i, f) in report.findings.iter().enumerate() {
            out.push_str(&format!(
                "  {}. [{}] {} - {}\n",
                i + 1,
                f.severity.as_str().to_uppercase(),
                f.code,
                sanitize(&f.title, 200)
            ));
            out.push_str(&format!("     Detail: {}\n", sanitize(&f.detail, 800)));
            if let Some(eid) = f.event_id {
                out.push_str(&format!("     Event:  {eid}\n"));
            }
            if let Some(inst) = &f.process_instance_id {
                out.push_str(&format!("     Process instance: {}\n", sanitize(inst, 200)));
            }
            if !f.evidence.is_empty() {
                out.push_str("     Evidence:\n");
                for ev in &f.evidence {
                    out.push_str(&format!("       - {}\n", sanitize(ev, 400)));
                }
            }
            out.push_str(&format!(
                "     Recommendation: {}\n",
                sanitize(&f.recommendation, 800)
            ));
        }
    }

    out.push_str("\nLimitations\n");
    if report.limitations.is_empty() {
        out.push_str("  (none reported)\n");
    } else {
        for l in &report.limitations {
            out.push_str(&format!("  - {}\n", sanitize(l, 400)));
        }
    }
    out.push_str("  - Verification is read-only and does not prove cryptographic authenticity or tamper-proofing.\n");
    out
}

fn assessment_label(a: syscall_core::VerificationAssessment) -> &'static str {
    match a {
        syscall_core::VerificationAssessment::Valid => {
            "internally consistent; evidence interpretable"
        }
        syscall_core::VerificationAssessment::ValidButIncomplete => {
            "consistent where checkable, but incomplete/limited"
        }
        syscall_core::VerificationAssessment::Warning => {
            "no hard contradictions found, but warnings/limitations exist"
        }
        syscall_core::VerificationAssessment::Invalid => {
            "contradictory, corrupt, or invalid evidence/state"
        }
        syscall_core::VerificationAssessment::UnableToVerify => {
            "verification could not be completed sufficiently"
        }
    }
}

pub fn render_verify_json(report: &SessionVerificationReport) -> Result<String> {
    to_json(&serde_json::to_value(report)?)
}

use syscall_storage::{
    ConnectionActivity, FileActivity, ProcessInstanceEvidence, SessionStats, TimelineFilter,
};

pub fn render_processes(
    session_id: &str,
    processes: &[ProcessInstanceEvidence],
    session: &SessionSummary,
) -> String {
    if processes.is_empty() {
        return format!("No process instances recorded in session {session_id}.\n");
    }
    let headers = [
        "PID",
        "PPID",
        "PARENT INSTANCE",
        "COMM",
        "EXECUTABLE/CMDLINE",
        "FIRST (UTC)",
        "LAST (UTC)",
        "EVENTS",
        "EXIT",
        "UNRESOLVED",
        "PROCESS INSTANCE",
    ];
    let widths = [7, 7, 28, 16, 40, 33, 33, 7, 10, 18, 40];
    let session_cmd = command_line(session);
    let root_hint_pid = session_cmd.split_whitespace().next().map(|_| ()).is_some(); // just marker
    let rows = processes
        .iter()
        .map(|p| {
            let cmdline = if let Some(cl) = &p.command_line {
                cl.clone()
            } else if p.executable.is_some() {
                // if executable known, show it; session command line only when plausible target match not certain
                p.executable.clone().unwrap_or_default()
            } else {
                "-".to_owned()
            };
            // best-effort: if this looks like session target and no per-process cmdline, show session cmd when not sensitive beyond recorded args
            let cmdline = if cmdline == "-" || cmdline.is_empty() {
                // attempt: first seen process matching session command basename? keep simple: show session cmd for earliest instance only as hint
                "-".to_owned()
            } else {
                cmdline
            };
            let exit = if p.exit_observed {
                p.exit_priority
                    .map(|v| format!("obs(prio:{v})"))
                    .unwrap_or_else(|| "observed".to_owned())
            } else {
                "-".to_owned()
            };
            let unresolved = match (p.identity_unresolved, p.ancestry_unresolved) {
                (false, false) => "-".to_owned(),
                (true, true) => "identity,ancestry".to_owned(),
                (true, false) => "identity".to_owned(),
                (false, true) => "ancestry".to_owned(),
            };
            vec![
                p.pid.to_string(),
                p.parent_pid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                p.parent_process_instance_id
                    .clone()
                    .unwrap_or_else(|| "-".to_owned()),
                p.comm.clone(),
                cmdline,
                format_unix_ns_utc(p.first_seen_ns),
                format_unix_ns_utc(p.last_seen_ns),
                p.event_count.to_string(),
                exit,
                unresolved,
                p.process_instance_id.clone(),
            ]
        })
        .collect::<Vec<_>>();
    let mut out = render_table(&headers, &widths, &rows);
    out.push_str(&format!(
        "\nNote: command-line arguments are only available at session/recorded-evidence level and may be redacted; per-process argv is not fabricated. Session command: {}\n",
        sanitize(&session_cmd, 300)
    ));
    let unresolved_any = processes
        .iter()
        .any(|p| p.identity_unresolved || p.ancestry_unresolved);
    if unresolved_any {
        out.push_str("Unresolved identity/ancestry indicates incomplete evidence; relationships are not invented.\n");
    }
    let _ = root_hint_pid;
    out
}

pub fn render_processes_json(
    session_id: &str,
    processes: &[ProcessInstanceEvidence],
    session: &SessionSummary,
) -> Result<String> {
    to_json(&json!({
        "session_id": session_id,
        "session_command": command_line(session),
        "process_instances": processes,
        "limitations": [
            "Per-process command-line arguments are not captured in event payloads; session command reflects recorded/redacted session arguments only.",
            "Exit status/signal is not available per process from exit payloads (exit priority may be shown); target exit is session-level.",
            "Unresolved identity/ancestry means evidence is incomplete or ambiguous; relationships are not invented."
        ]
    }))
}

pub fn render_tree(session_id: &str, processes: &[ProcessInstanceEvidence]) -> String {
    if processes.is_empty() {
        return format!("No process instances recorded in session {session_id}.\n");
    }
    let by_id: std::collections::HashMap<&str, &ProcessInstanceEvidence> = processes
        .iter()
        .map(|p| (p.process_instance_id.as_str(), p))
        .collect();
    let mut children: std::collections::HashMap<String, Vec<&ProcessInstanceEvidence>> =
        std::collections::HashMap::new();
    let mut roots: Vec<&ProcessInstanceEvidence> = Vec::new();
    for p in processes {
        if let Some(parent) = &p.parent_process_instance_id {
            if by_id.contains_key(parent.as_str()) {
                children.entry(parent.clone()).or_default().push(p);
            } else {
                roots.push(p);
            }
        } else {
            roots.push(p);
        }
    }
    for v in children.values_mut() {
        v.sort_by(|a, b| {
            a.first_seen_ns
                .cmp(&b.first_seen_ns)
                .then(a.pid.cmp(&b.pid))
                .then(a.process_instance_id.cmp(&b.process_instance_id))
        });
    }
    roots.sort_by(|a, b| {
        a.first_seen_ns
            .cmp(&b.first_seen_ns)
            .then(a.pid.cmp(&b.pid))
            .then(a.process_instance_id.cmp(&b.process_instance_id))
    });

    let mut out = String::new();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut stack: std::collections::HashSet<String> = std::collections::HashSet::new();

    fn walk(
        node: &ProcessInstanceEvidence,
        depth: usize,
        relation: &str,
        children: &std::collections::HashMap<String, Vec<&ProcessInstanceEvidence>>,
        visited: &mut std::collections::HashSet<String>,
        stack: &mut std::collections::HashSet<String>,
        out: &mut String,
    ) {
        let indent = "  ".repeat(depth);
        let marker = if stack.contains(&node.process_instance_id) {
            "[CYCLE]"
        } else if relation == "missing-parent" {
            "[MISSING-PARENT]"
        } else if relation == "unresolved-parent" {
            "[UNRESOLVED-PARENT]"
        } else if node.ancestry_unresolved || node.identity_unresolved {
            "[UNRESOLVED]"
        } else {
            ""
        };
        let exec = node.executable.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "{indent}- pid={} comm={} exec={} instance={} parent_pid={} {marker}\n",
            node.pid,
            sanitize(&node.comm, 32),
            sanitize(exec, 80),
            node.process_instance_id,
            node.parent_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_owned()),
        ));
        if stack.contains(&node.process_instance_id) || visited.contains(&node.process_instance_id)
        {
            return;
        }
        visited.insert(node.process_instance_id.clone());
        stack.insert(node.process_instance_id.clone());
        if let Some(kids) = children.get(&node.process_instance_id) {
            for kid in kids {
                let rel = if kid.parent_process_instance_id.is_some() {
                    "observed"
                } else {
                    "unresolved-parent"
                };
                walk(kid, depth + 1, rel, children, visited, stack, out);
            }
        }
        stack.remove(&node.process_instance_id);
    }

    for root in &roots {
        let rel = if root.parent_pid.is_some() || root.parent_process_instance_id.is_some() {
            "missing-parent"
        } else {
            "root"
        };
        walk(root, 0, rel, &children, &mut visited, &mut stack, &mut out);
    }
    // Any unvisited due to oddities
    for p in processes {
        if !visited.contains(&p.process_instance_id) {
            walk(
                p,
                0,
                "unresolved-parent",
                &children,
                &mut visited,
                &mut stack,
                &mut out,
            );
        }
    }
    out.push_str("\nLegend: [MISSING-PARENT]=parent not present in recorded instances; [UNRESOLVED]/[UNRESOLVED-PARENT]=identity or ancestry incomplete/ambiguous; [CYCLE]=cycle detected (not traversed). Relationships are based only on recorded evidence.\n");
    out
}

pub fn render_tree_json(session_id: &str, processes: &[ProcessInstanceEvidence]) -> Result<String> {
    // Provide both flat instances and derived tree structure.
    #[derive(serde::Serialize)]
    struct Node {
        process_instance_id: String,
        pid: i32,
        parent_pid: Option<i32>,
        parent_process_instance_id: Option<String>,
        comm: String,
        executable: Option<String>,
        first_seen_ns: i64,
        last_seen_ns: i64,
        event_count: u64,
        exit_observed: bool,
        exit_priority: Option<i32>,
        identity_unresolved: bool,
        ancestry_unresolved: bool,
        relation: String,
        cycle: bool,
        children: Vec<Node>,
    }
    let by_id: std::collections::HashMap<&str, &ProcessInstanceEvidence> = processes
        .iter()
        .map(|p| (p.process_instance_id.as_str(), p))
        .collect();
    let mut children: std::collections::HashMap<String, Vec<&ProcessInstanceEvidence>> =
        std::collections::HashMap::new();
    let mut roots: Vec<&ProcessInstanceEvidence> = Vec::new();
    for p in processes {
        if let Some(parent) = &p.parent_process_instance_id {
            if by_id.contains_key(parent.as_str()) {
                children.entry(parent.clone()).or_default().push(p);
            } else {
                roots.push(p);
            }
        } else {
            roots.push(p);
        }
    }
    let sort_kids = |v: &mut Vec<&ProcessInstanceEvidence>| {
        v.sort_by(|a, b| {
            a.first_seen_ns
                .cmp(&b.first_seen_ns)
                .then(a.pid.cmp(&b.pid))
                .then(a.process_instance_id.cmp(&b.process_instance_id))
        });
    };
    for v in children.values_mut() {
        sort_kids(v);
    }
    roots.sort_by(|a, b| {
        a.first_seen_ns
            .cmp(&b.first_seen_ns)
            .then(a.pid.cmp(&b.pid))
            .then(a.process_instance_id.cmp(&b.process_instance_id))
    });

    fn build(
        p: &ProcessInstanceEvidence,
        relation: &str,
        children: &std::collections::HashMap<String, Vec<&ProcessInstanceEvidence>>,
        stack: &mut std::collections::HashSet<String>,
        visited: &mut std::collections::HashSet<String>,
    ) -> Node {
        let cycle = stack.contains(&p.process_instance_id);
        let mut kids = Vec::new();
        if !cycle && !visited.contains(&p.process_instance_id) {
            visited.insert(p.process_instance_id.clone());
            stack.insert(p.process_instance_id.clone());
            if let Some(ch) = children.get(&p.process_instance_id) {
                for c in ch {
                    let rel = if c.parent_process_instance_id.is_some() {
                        "observed"
                    } else {
                        "unresolved_parent"
                    };
                    kids.push(build(c, rel, children, stack, visited));
                }
            }
            stack.remove(&p.process_instance_id);
        }
        Node {
            process_instance_id: p.process_instance_id.clone(),
            pid: p.pid,
            parent_pid: p.parent_pid,
            parent_process_instance_id: p.parent_process_instance_id.clone(),
            comm: p.comm.clone(),
            executable: p.executable.clone(),
            first_seen_ns: p.first_seen_ns,
            last_seen_ns: p.last_seen_ns,
            event_count: p.event_count,
            exit_observed: p.exit_observed,
            exit_priority: p.exit_priority,
            identity_unresolved: p.identity_unresolved,
            ancestry_unresolved: p.ancestry_unresolved,
            relation: relation.to_owned(),
            cycle,
            children: kids,
        }
    }
    let mut visited = std::collections::HashSet::new();
    let mut stack = std::collections::HashSet::new();
    let mut tree = Vec::new();
    for r in &roots {
        let rel = if r.parent_pid.is_some() || r.parent_process_instance_id.is_some() {
            "missing_parent"
        } else {
            "root"
        };
        tree.push(build(r, rel, &children, &mut stack, &mut visited));
    }
    for p in processes {
        if !visited.contains(&p.process_instance_id) {
            let rel = if p.parent_pid.is_some() {
                "missing_parent"
            } else {
                "root"
            };
            tree.push(build(p, rel, &children, &mut stack, &mut visited));
        }
    }
    to_json(&json!({
        "session_id": session_id,
        "process_instances": processes,
        "tree": tree,
        "limitations": [
            "Parent-child links use process-instance identity derived from recorded evidence; PID alone is not used as identity.",
            "Missing parents, unresolved forks/identity, and cycles are reported explicitly; relationships are never invented."
        ]
    }))
}

pub fn render_files(session_id: &str, files: &[FileActivity], total: u64) -> String {
    if files.is_empty() {
        return format!(
            "No file-open events matched in session {session_id} (matched total {total}).\n"
        );
    }
    let headers = [
        "ID",
        "TIME (UTC)",
        "PID",
        "INSTANCE",
        "COMM",
        "PATH",
        "FLAGS",
        "RESULT",
        "OUTCOME",
        "NOTES",
    ];
    let widths = [8, 33, 7, 28, 16, 40, 10, 8, 10, 30];
    let rows = files
        .iter()
        .map(|file| {
            let outcome = if file.success {
                "success".to_owned()
            } else {
                match file.errno {
                    Some(errno) => format!("failed (errno {errno})"),
                    None => "failed".to_owned(),
                }
            };
            let mut notes = Vec::new();
            if !file.path_is_absolute {
                notes.push(format!("relative path (dirfd {})", file.dirfd));
            }
            if file.path_truncated {
                notes.push("path truncated".to_owned());
            }
            vec![
                file.event_id.to_string(),
                format_unix_ns_utc(file.timestamp_ns),
                file.pid.to_string(),
                file.process_instance_id.clone(),
                file.comm.clone(),
                file.path.clone(),
                format!("0x{:x}", file.flags),
                file.result.to_string(),
                outcome,
                notes.join("; "),
            ]
        })
        .collect::<Vec<_>>();
    let mut out = render_table(&headers, &widths, &rows);
    out.push_str(&format!(
        "\nShowing {} file-open event(s), matched total {} (chronological: timestamp_ns, monotonic_ns, id).\n",
        files.len(),
        total
    ));
    out
}

pub fn render_files_json(session_id: &str, files: &[FileActivity], total: u64) -> Result<String> {
    to_json(&json!({
        "session_id": session_id,
        "file_opens": files,
        "matched_total": total,
        "ordering": "timestamp_ns ASC, monotonic_ns ASC, id ASC",
        "limitations": [
            "Paths are the raw openat(2) strings; relative paths are not resolved by the collector.",
            "An event records an open attempt and its result, not that file contents were read.",
            "Truncated paths are marked explicitly; absent events may reflect loss or unsupported syscalls."
        ]
    }))
}

pub fn render_connections(
    session_id: &str,
    connections: &[ConnectionActivity],
    total: u64,
) -> String {
    if connections.is_empty() {
        return format!(
            "No network-connect events matched in session {session_id} (matched total {total}).\n"
        );
    }
    let headers = [
        "ID",
        "TIME (UTC)",
        "PID",
        "INSTANCE",
        "COMM",
        "FAMILY",
        "SOURCE",
        "DESTINATION",
        "RESULT",
        "OUTCOME",
    ];
    let widths = [8, 33, 7, 28, 16, 8, 28, 30, 8, 18];
    let rows = connections
        .iter()
        .map(|connection| {
            let source = match (&connection.source_address, connection.source_port) {
                (Some(address), Some(port)) => format!("{address}:{port}"),
                _ => "unavailable".to_owned(),
            };
            let outcome = if connection.success {
                "success".to_owned()
            } else {
                match connection.errno {
                    Some(errno) => format!("failed (errno {errno})"),
                    None => "failed".to_owned(),
                }
            };
            vec![
                connection.event_id.to_string(),
                format_unix_ns_utc(connection.timestamp_ns),
                connection.pid.to_string(),
                connection.process_instance_id.clone(),
                connection.comm.clone(),
                connection.family.to_string(),
                source,
                format!(
                    "{}:{}",
                    connection.destination_address, connection.destination_port
                ),
                connection.result.to_string(),
                outcome,
            ]
        })
        .collect::<Vec<_>>();
    let mut out = render_table(&headers, &widths, &rows);
    out.push_str(&format!(
        "\nShowing {} network-connect event(s), matched total {} (chronological: timestamp_ns, monotonic_ns, id).\n",
        connections.len(),
        total
    ));
    out
}

pub fn render_connections_json(
    session_id: &str,
    connections: &[ConnectionActivity],
    total: u64,
) -> Result<String> {
    to_json(&json!({
        "session_id": session_id,
        "connections": connections,
        "matched_total": total,
        "ordering": "timestamp_ns ASC, monotonic_ns ASC, id ASC",
        "limitations": [
            "Events are connect(2) attempts for IPv4/IPv6 addresses, not proof of an established connection.",
            "The syscall tracepoint does not distinguish TCP from UDP; no payloads or DNS resolution are recorded.",
            "Source address/port are reported unavailable when the hook cannot expose them."
        ]
    }))
}

pub fn render_timeline(
    events: &[Event],
    session_id: &str,
    offset: usize,
    limit: usize,
    total: Option<u64>,
) -> String {
    if events.is_empty() {
        let mut out = format!("No events matched in session {session_id}.\n");
        if let Some(t) = total {
            out.push_str(&format!(
                "Matched events: {t}, offset: {offset}, limit: {limit}\n"
            ));
        }
        return out;
    }
    let headers = [
        "ID",
        "TIME (UTC)",
        "MONO_NS",
        "TYPE",
        "PID",
        "PPID",
        "INSTANCE",
        "COMM",
        "DETAILS",
    ];
    let widths = [8, 33, 18, 13, 7, 7, 28, 16, 72];
    let rows = events
        .iter()
        .map(|event| {
            vec![
                event
                    .id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                format_unix_ns_utc(event.timestamp_ns),
                event.monotonic_ns.to_string(),
                event.event_type.to_string(),
                event.pid.to_string(),
                event
                    .ppid
                    .map(|ppid| ppid.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                event.process_instance_id.clone(),
                event.comm.clone(),
                event_details(event),
            ]
        })
        .collect::<Vec<_>>();
    let mut out = render_table(&headers, &widths, &rows);
    match total {
        Some(t) => out.push_str(&format!(
            "\nShowing {} event(s), offset {}, limit {}, matched total {} (chronological: timestamp_ns, monotonic_ns, id).\n",
            events.len(), offset, limit, t
        )),
        None => out.push_str(&format!(
            "\nShowing {} event(s), offset {}, limit {} (chronological: timestamp_ns, monotonic_ns, id).\n",
            events.len(), offset, limit
        )),
    }
    out
}

pub fn render_timeline_json(
    events: &[Event],
    session_id: &str,
    filter: &TimelineFilter,
    total: Option<u64>,
) -> Result<String> {
    to_json(&json!({
        "session_id": session_id,
        "filter": {
            "event_type": filter.event_type.map(|e| e.as_str().to_owned()),
            "pid": filter.pid,
            "process_instance_id": filter.process_instance_id,
            "from_ns": filter.from_ns,
            "to_ns": filter.to_ns,
            "limit": filter.limit,
            "offset": filter.offset,
        },
        "matched_total": total,
        "events": events,
        "ordering": "timestamp_ns ASC, monotonic_ns ASC, id ASC",
    }))
}

pub fn render_stats(
    stats: &SessionStats,
    verification: Option<&SessionVerificationReport>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("Session {}\n", stats.session_id));
    out.push_str(&format!("  Status:                {}\n", stats.status));
    out.push_str(&format!(
        "  Started:               {}\n",
        format_unix_ns_utc(stats.started_at_ns)
    ));
    out.push_str(&format!(
        "  Ended:                 {}\n",
        stats
            .ended_at_ns
            .map(format_unix_ns_utc)
            .unwrap_or_else(|| "-".to_owned())
    ));
    out.push_str(&format!(
        "  Duration:              {}\n",
        stats
            .duration_ns
            .map(format_duration_ns)
            .unwrap_or_else(|| "active/unknown".to_owned())
    ));
    out.push_str(&format!(
        "  Processes:             {}\n",
        stats.process_count
    ));
    out.push_str(&format!("  Events (stored):       {}\n", stats.event_count));
    out.push_str(&format!(
        "  Events persisted:      {}\n",
        stats.events_persisted
    ));
    out.push_str("  Events by type:\n");
    if stats.events_by_type.is_empty() {
        out.push_str("    (none)\n");
    } else {
        for (k, v) in &stats.events_by_type {
            out.push_str(&format!("    {:<16} {}\n", k, v));
        }
    }
    out.push_str("  Accounting/loss:\n");
    out.push_str(&format!(
        "    Ring-buffer lost:    {}\n",
        stats.ringbuf_lost_events
    ));
    out.push_str(&format!(
        "    Userspace dropped:   {}\n",
        stats.userspace_dropped_events
    ));
    out.push_str(&format!(
        "    Dropped total:       {}\n",
        stats.dropped_events_total
    ));
    out.push_str(&format!(
        "    Malformed:           {}\n",
        stats.malformed_events
    ));
    out.push_str(&format!(
        "    Filtered by scope:   {}\n",
        stats.filtered_events
    ));
    out.push_str(&format!(
        "    Rejected (scope):    {}\n",
        stats.events_rejected_scope
    ));
    out.push_str(&format!(
        "    Rejected (malformed):{}\n",
        stats.events_rejected_malformed
    ));
    out.push_str(&format!(
        "    Persist failed:      {}\n",
        stats.events_persist_failed
    ));
    out.push_str(&format!(
        "    Unresolved identity: {}\n",
        stats.unresolved_identity_count
    ));
    out.push_str(&format!(
        "  Termination:           {}\n",
        stats.termination_reason.as_deref().unwrap_or("-")
    ));
    if let Some(code) = stats.target_exit_code {
        out.push_str(&format!("  Target exit code:      {}\n", code));
    }
    if let Some(sig) = stats.target_exit_signal {
        out.push_str(&format!("  Target exit signal:    {}\n", sig));
    }
    if let Some(v) = verification {
        out.push_str(&format!(
            "  Verification:          {} ({})\n",
            v.assessment.as_str(),
            assessment_label(v.assessment)
        ));
    } else {
        out.push_str("  Verification:          (not requested)\n");
    }
    if stats.evidence_may_be_incomplete {
        out.push_str("\nWARNING: Evidence may be incomplete (losses, drops, recovery, non-terminal state, or unresolved identity). Observed counts do not necessarily represent all runtime activity.\n");
    }
    out
}

pub fn render_stats_json(
    stats: &SessionStats,
    verification: Option<&SessionVerificationReport>,
) -> Result<String> {
    to_json(&json!({
        "stats": stats,
        "verification": verification,
        "note": if stats.evidence_may_be_incomplete {
            Some("Evidence may be incomplete; observed counts do not necessarily represent all runtime activity.")
        } else {
            None
        }
    }))
}

pub fn render_analysis(report: &AnalysisReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("Session {}\n", report.session_id));
    out.push_str(&format!(
        "  Command:      {}\n",
        sanitize(&report.session_command, 300)
    ));
    out.push_str(&format!("  Scope:        {}\n", report.session_scope));
    out.push_str(&format!(
        "  Started:      {}\n",
        format_unix_ns_utc(report.session_started_at_ns)
    ));
    out.push_str(&format!(
        "  Ended:        {}\n",
        report
            .session_ended_at_ns
            .map(format_unix_ns_utc)
            .unwrap_or_else(|| "-".to_owned())
    ));
    out.push_str(&format!("  Analysis schema: {}\n", report.schema_version));

    out.push_str("\nEvidence completeness\n");
    let evidence = &report.evidence;
    out.push_str(&format!("  Status:              {}\n", evidence.status));
    out.push_str(&format!(
        "  Session status:      {}\n",
        evidence.session_status
    ));
    out.push_str(&format!(
        "  Events/processes:    {} / {}\n",
        evidence.event_count, evidence.process_count
    ));
    out.push_str(&format!(
        "  Ring-buffer lost:    {}\n",
        evidence.ringbuf_lost_events
    ));
    out.push_str(&format!(
        "  Userspace dropped:   {}\n",
        evidence.userspace_dropped_events
    ));
    out.push_str(&format!(
        "  Malformed:           {}\n",
        evidence.malformed_events
    ));
    out.push_str(&format!(
        "  Persist failed:      {}\n",
        evidence.events_persist_failed
    ));
    out.push_str(&format!(
        "  Unresolved identity: {}\n",
        evidence.unresolved_identity_count
    ));
    out.push_str(&format!(
        "  Verification:        {}\n",
        evidence
            .verification_assessment
            .as_deref()
            .unwrap_or("unavailable")
    ));
    if evidence.may_be_incomplete {
        out.push_str(
            "  WARNING: Evidence is incomplete or unverified; negative conclusions are limited.\n",
        );
    }

    out.push_str("\nRules evaluated\n");
    if report.rules_evaluated.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for rule in &report.rules_evaluated {
            out.push_str(&format!(
                "  - {} v{}: {}\n",
                rule.rule_id, rule.version, rule.title
            ));
        }
    }

    out.push_str("\nFindings by severity\n");
    let mut total = 0usize;
    for severity in AnalysisSeverity::ALL.iter().rev() {
        let findings = report
            .findings
            .iter()
            .filter(|finding| finding.severity == *severity)
            .collect::<Vec<_>>();
        if findings.is_empty() {
            continue;
        }
        total += findings.len();
        out.push_str(&format!(
            "  {} ({}):\n",
            severity.as_str().to_uppercase(),
            findings.len()
        ));
        for finding in findings {
            out.push_str(&format!(
                "  [{}] {} ({}, confidence {})\n",
                finding.severity.as_str().to_uppercase(),
                sanitize(&finding.title, 160),
                finding.rule_id,
                finding.confidence
            ));
            out.push_str(&format!(
                "       ID: {}\n       Time: {} .. {}\n",
                finding.finding_id,
                format_unix_ns_utc(finding.time_range.start_ns),
                format_unix_ns_utc(finding.time_range.end_ns)
            ));
            out.push_str(&format!(
                "       Explanation: {}\n",
                sanitize(&finding.explanation, 1_000)
            ));
            out.push_str(&format!(
                "       Why it matters: {}\n",
                sanitize(&finding.significance, 600)
            ));
            if !finding.related_findings.is_empty() {
                out.push_str(&format!(
                    "       Related findings: {}\n",
                    finding.related_findings.join(", ")
                ));
            }
            out.push_str("       Supporting events:\n");
            if finding.supporting_events.is_empty() {
                out.push_str("         (none)\n");
            } else {
                for event in finding.supporting_events.iter().take(10) {
                    out.push_str(&format!(
                        "         - #{} {} {} pid={} {}\n",
                        event.event_id,
                        format_unix_ns_utc(event.timestamp_ns),
                        event.event_type.as_str(),
                        event.pid,
                        sanitize(&event.summary, 300)
                    ));
                }
                if finding.supporting_events.len() > 10 {
                    out.push_str(&format!(
                        "         ... {} more event(s)\n",
                        finding.supporting_events.len() - 10
                    ));
                }
            }
            out.push_str("       Relevant process tree:\n");
            if finding.related_processes.is_empty() {
                out.push_str("         (none)\n");
            } else {
                for process in &finding.related_processes {
                    out.push_str(&format!(
                        "         - pid={} comm={} exec={} instance={} parent={}\n",
                        process.pid,
                        sanitize(&process.comm, 48),
                        sanitize(process.executable.as_deref().unwrap_or("-"), 120),
                        process.process_instance_id,
                        process.parent_process_instance_id.as_deref().unwrap_or("-")
                    ));
                }
            }
            out.push_str("       Limitations:\n");
            if finding.limitations.is_empty() {
                out.push_str("         (none)\n");
            } else {
                for limitation in &finding.limitations {
                    out.push_str(&format!("         - {}\n", sanitize(limitation, 500)));
                }
            }
            out.push_str("       Recommended next steps:\n");
            if finding.next_steps.is_empty() {
                out.push_str("         (none)\n");
            } else {
                for step in &finding.next_steps {
                    out.push_str(&format!("         - {}\n", sanitize(step, 500)));
                }
            }
        }
    }
    if total == 0 {
        out.push_str("  (no findings)\n");
    }

    out.push_str("\nLimitations\n");
    if report.limitations.is_empty() {
        out.push_str("  (none reported)\n");
    } else {
        for limitation in &report.limitations {
            out.push_str(&format!("  - {}\n", sanitize(limitation, 600)));
        }
    }
    if report.truncated {
        out.push_str("\nEvidence or findings were truncated by configured safety bounds.\n");
    }
    out
}

pub fn render_analysis_json(report: &AnalysisReport) -> Result<String> {
    to_json(&serde_json::to_value(report)?)
}

pub fn render_export_result(outcome: &crate::export::ExportOutcome) -> String {
    let mut out = String::new();
    out.push_str("Exported evidence package\n");
    out.push_str(&format!(
        "  Output:          {}\n",
        outcome.output.display()
    ));
    out.push_str(&format!("  Format:          {}\n", outcome.format_version));
    out.push_str(&format!("  Bytes written:   {}\n", outcome.bytes_written));
    out.push_str("  Manifest (SHA-256, exported components):\n");
    for e in &outcome.sha256_manifest {
        out.push_str(&format!(
            "    - {} ({} v{}, {} bytes): {}\n",
            e.component, e.format, e.version, e.byte_length, e.sha256
        ));
    }
    out.push_str("  Integrity note:   manifest enables post-export integrity checking; not proof of pre-export authenticity.\n");
    out
}

pub fn render_export_result_json(outcome: &crate::export::ExportOutcome) -> Result<String> {
    to_json(&json!({
        "output": outcome.output.display().to_string(),
        "format_version": outcome.format_version,
        "bytes_written": outcome.bytes_written,
        "manifest": outcome.sha256_manifest,
        "integrity_note": "SHA-256 manifest enables post-export integrity checking, not proof of pre-export database authenticity."
    }))
}

pub fn render_export_verification(
    verification: &crate::export::ExportVerification,
    package: &std::path::Path,
) -> String {
    let mut out = String::new();
    out.push_str(if verification.valid {
        "Export verification passed\n"
    } else {
        "Export verification failed\n"
    });
    out.push_str(&format!("  Package:        {}\n", package.display()));
    out.push_str(&format!(
        "  Format:         {}\n",
        verification.format_version
    ));
    out.push_str(&format!(
        "  Manifest:       {}\n",
        verification.manifest_version
    ));
    out.push_str("  Components:\n");
    for component in &verification.components {
        out.push_str(&format!(
            "    - {:<18} {}{}\n",
            component.component,
            if component.valid { "ok" } else { "MISMATCH" },
            if component.valid {
                String::new()
            } else {
                format!(
                    " (expected {} bytes / {}, got {} bytes / {})",
                    component.expected_byte_length,
                    component.expected_sha256,
                    component.actual_byte_length,
                    component.actual_sha256
                )
            }
        ));
    }
    if !verification.warnings.is_empty() {
        out.push_str("  Warnings:\n");
        for warning in &verification.warnings {
            out.push_str(&format!("    - {}\n", sanitize(warning, 400)));
        }
    }
    if !verification.errors.is_empty() {
        out.push_str("  Errors:\n");
        for error in &verification.errors {
            out.push_str(&format!("    - {}\n", sanitize(error, 400)));
        }
    }
    out.push_str(
        "  Note:           verification checks package integrity, not pre-export authenticity.\n",
    );
    out
}

pub fn render_export_verification_json(
    verification: &crate::export::ExportVerification,
) -> Result<String> {
    to_json(&serde_json::to_value(verification)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscall_core::{EventPayload, EventType, ProcessMetadata, RecordingScope, SCHEMA_VERSION};
    use syscall_storage::{ProcessSummary, SessionStatus, SessionSummary};

    fn session() -> SessionSummary {
        SessionSummary {
            id: "s-1700000000000-0000000000000001".to_owned(),
            schema_version: SCHEMA_VERSION,
            started_at_ns: 1_700_000_000_000_000_000,
            ended_at_ns: Some(1_700_000_005_000_000_000),
            command: "/usr/bin/sleep".to_owned(),
            arguments: vec!["5".to_owned()],
            recording_scope: RecordingScope::TargetTree,
            status: SessionStatus::Completed,
            boot_id: Some("boot".to_owned()),
            kernel_release: Some("6.6.0".to_owned()),
            collector_version: Some("0.1.0".to_owned()),
            dropped_events: 0,
            ringbuf_lost_events: 0,
            userspace_dropped_events: 0,
            malformed_events: 0,
            filtered_events: 2,
            error: None,
            termination_reason: Some("target_exit".to_owned()),
            target_exit_code: Some(0),
            target_exit_signal: None,
            recovered_from_status: None,
            recovered_at_ns: None,
            finalized_at_ns: Some(1_700_000_005_000_000_000),
            events_received: 5,
            events_decoded: 5,
            events_attributed: 3,
            events_persisted: 3,
            events_rejected_scope: 2,
            events_rejected_malformed: 0,
            events_persist_failed: 0,
            events_self_filtered: 0,
            event_count: 3,
            process_count: 2,
        }
    }

    fn exec_event() -> Event {
        Event {
            id: Some(1),
            session_id: "s-1".to_owned(),
            schema_version: SCHEMA_VERSION,
            event_type: EventType::ProcessExec,
            timestamp_ns: 1_700_000_001_000_000_000,
            monotonic_ns: 100,
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
            provenance: None,
        }
    }

    #[test]
    fn sanitize_escapes_control_characters() {
        let value = sanitize("evil\x1b[31m\nname", 80);
        assert!(!value.contains('\u{1b}'));
        assert!(!value.contains('\n'));
        assert!(value.contains("\\u{1b}"));
    }

    #[test]
    fn sanitize_truncates_by_character() {
        assert_eq!(sanitize("abcdef", 4), "a...");
        assert_eq!(sanitize("abcdef", 80), "abcdef");
    }

    #[test]
    fn sessions_table_contains_real_values() {
        let text = render_sessions(&[session()]);
        assert!(text.contains("s-1700000000000-0000000000000001"));
        assert!(text.contains("completed"));
        assert!(text.contains("5.000s"));
        assert!(text.contains("/usr/bin/sleep 5"));
    }

    #[test]
    fn empty_session_list_is_explicit() {
        assert_eq!(render_sessions(&[]), "No sessions recorded.\n");
    }

    #[test]
    fn session_json_round_trips() {
        let text = render_sessions_json(&[session()]).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value[0]["status"], "completed");
        assert_eq!(value[0]["recording_scope"], "target-tree");
    }

    #[test]
    fn event_table_includes_payload_details() {
        let query = EventQuery::new("s-1");
        let text = render_events(&[exec_event()], &query);
        assert!(text.contains("process_exec"));
        assert!(text.contains("filename=/usr/bin/sleep"));
        assert!(text.contains("old_pid=41"));
    }

    #[test]
    fn event_json_contains_ids() {
        let text = render_events_json(&[exec_event()]).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value[0]["id"], 1);
        assert_eq!(value[0]["payload"]["kind"], "process_exec");
    }

    #[test]
    fn inspect_reports_counters_and_process_identity() {
        let process = ProcessSummary {
            process_instance_id: "boot:42:100".to_owned(),
            pid: 42,
            comm: "sleep".to_owned(),
            first_seen_ns: 1_700_000_001_000_000_000,
            last_seen_ns: 1_700_000_002_000_000_000,
            event_count: 2,
            exited: true,
        };
        let text = render_inspect(
            &session(),
            &[(EventType::ProcessExec, 1)],
            &[process],
            std::path::Path::new("/tmp/syscall.db"),
        );
        assert!(text.contains("Filtered by scope:     2"));
        assert!(text.contains("boot:42:100"));
        assert!(text.contains("process_exec"));
    }

    #[test]
    fn record_text_reports_target_status() {
        let report = RecordReport {
            session_id: "s-1".to_owned(),
            status: SessionStatus::Completed,
            events_persisted: 3,
            events_filtered: 0,
            events_self_filtered: 0,
            malformed_events: 0,
            ringbuf_lost_events: 0,
            userspace_dropped_events: 0,
            rejections: syscall_collector::RejectionBreakdown::default(),
            target: Some(syscall_collector::TargetOutcome {
                exit_code: Some(0),
                signal: None,
            }),
            interrupted: false,
            interrupt_signal: None,
            duration_ns: 5_000_000_000,
            database_path: std::path::PathBuf::from("/tmp/syscall.db"),
        };
        let text = render_record(&report);
        assert!(text.contains("Events persisted:      3"));
        assert!(text.contains("exit code 0"));
    }
}
