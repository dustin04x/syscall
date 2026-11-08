//! Deterministic text and JSON rendering.
//!
//! Text output is plain ASCII-safe: control characters in process names,
//! filenames, and command arguments are escaped so untrusted kernel data cannot
//! inject terminal escape sequences. Timestamps are always UTC.

use anyhow::Result;
use serde_json::{json, Value};
use syscall_collector::{EnvironmentReport, RecordReport};
use syscall_core::timefmt::{format_duration_ns, format_unix_ns_utc};
use syscall_core::{Event, EventPayload};
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
        EventPayload::FileOpen { path } => format!("path={path} (schema placeholder)"),
        EventPayload::NetworkConnect {
            family,
            address,
            port,
        } => format!("family={family} address={address} port={port} (schema placeholder)"),
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
