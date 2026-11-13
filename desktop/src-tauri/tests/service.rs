use std::os::unix::fs::PermissionsExt;

use syscall_core::{
    AddressFamily, Event, EventPayload, EventProvenance, EventType, ProcessMetadata,
    RecordingScope, SCHEMA_VERSION,
};
use syscall_desktop::{
    ActivityRequest, DesktopService, EventRequest, ExportRequest, ListSessionsRequest,
    OverviewRequest, SessionRequest, TimelineRequest,
};
use syscall_storage::{NewSession, SessionFinish, SessionStatus, Storage};
use tempfile::TempDir;

fn new_session(id: &str) -> NewSession {
    NewSession {
        id: id.to_owned(),
        schema_version: SCHEMA_VERSION,
        started_at_ns: 1_700_000_000_000_000_000,
        command: "/bin/bash".to_owned(),
        arguments: vec!["-c".to_owned(), "cat /etc/hostname".to_owned()],
        recording_scope: RecordingScope::TargetTree,
        boot_id: Some("boot".to_owned()),
        kernel_release: Some("6.6.0-test".to_owned()),
        collector_version: Some("0.1.0".to_owned()),
    }
}

fn finish(storage: &mut Storage, id: &str, persisted: u64) {
    storage
        .update_session_status(id, SessionStatus::Recording)
        .unwrap();
    storage
        .finish_session(
            id,
            &SessionFinish {
                ended_at_ns: 1_700_000_020_000_000_000,
                status: SessionStatus::Completed,
                dropped_events: 0,
                ringbuf_lost_events: 0,
                userspace_dropped_events: 0,
                malformed_events: 0,
                filtered_events: 8,
                error: None,
                termination_reason: Some("target_exit".to_owned()),
                target_exit_code: Some(0),
                target_exit_signal: None,
                recovered_from_status: None,
                recovered_at_ns: None,
                finalized_at_ns: Some(1_700_000_020_000_000_000),
                events_received: persisted,
                events_decoded: persisted,
                events_attributed: persisted,
                events_persisted: persisted,
                events_rejected_scope: 8,
                events_rejected_malformed: 0,
                events_persist_failed: 0,
                events_self_filtered: 0,
            },
        )
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn base_event(
    session: &str,
    pid: i32,
    instance: &str,
    timestamp_ns: i64,
    event_type: EventType,
    comm: &str,
    payload: EventPayload,
) -> Event {
    let tracepoint = match event_type {
        EventType::ProcessExec => "sched/sched_process_exec",
        EventType::ProcessFork => "sched/sched_process_fork",
        EventType::ProcessExit => "sched/sched_process_exit",
        EventType::FileOpen => "syscalls/sys_exit_openat",
        EventType::NetworkConnect => "syscalls/sys_exit_connect",
    };
    Event {
        id: None,
        session_id: session.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type,
        timestamp_ns,
        monotonic_ns: timestamp_ns as u64,
        pid,
        tid: pid,
        uid: 1000,
        gid: 1000,
        ppid: Some(1),
        comm: comm.to_owned(),
        process_instance_id: instance.to_owned(),
        payload,
        provenance: Some(EventProvenance {
            raw_bpf_pid: Some(pid),
            raw_bpf_tgid: Some(pid),
            observer_pid: Some(pid),
            observer_tgid: Some(pid),
            source_tracepoint: Some(tracepoint.to_owned()),
            wire_schema_version: Some(3),
            attribution_method: Some("observed".to_owned()),
            timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
            monotonic_clock_domain: Some("monotonic_boot_raw".to_owned()),
        }),
    }
}

fn exec(
    session: &str,
    pid: i32,
    instance: &str,
    timestamp_ns: i64,
    filename: &str,
    comm: &str,
) -> Event {
    base_event(
        session,
        pid,
        instance,
        timestamp_ns,
        EventType::ProcessExec,
        comm,
        EventPayload::ProcessExec {
            filename: filename.to_owned(),
            process: ProcessMetadata {
                ppid: Some(1),
                start_time_ticks: Some(100),
            },
            old_pid: None,
        },
    )
}

fn fork(
    session: &str,
    parent_pid: i32,
    child_pid: i32,
    child_instance: &str,
    timestamp_ns: i64,
    child_comm: &str,
) -> Event {
    base_event(
        session,
        child_pid,
        child_instance,
        timestamp_ns,
        EventType::ProcessFork,
        child_comm,
        EventPayload::ProcessFork {
            parent_pid,
            parent_tgid: Some(parent_pid),
            child_pid,
            child_comm: child_comm.to_owned(),
            child_start_time_ticks: Some(200),
        },
    )
}

fn file_open(
    session: &str,
    pid: i32,
    instance: &str,
    timestamp_ns: i64,
    path: &str,
    success: bool,
) -> Event {
    base_event(
        session,
        pid,
        instance,
        timestamp_ns,
        EventType::FileOpen,
        "bash",
        EventPayload::FileOpen {
            path: path.to_owned(),
            path_is_absolute: path.starts_with('/'),
            path_truncated: false,
            dirfd: -100,
            flags: 0,
            result: if success { 5 } else { -13 },
            success,
            errno: if success { None } else { Some(13) },
        },
    )
}

fn connect(
    session: &str,
    pid: i32,
    instance: &str,
    timestamp_ns: i64,
    endpoint: (AddressFamily, &str, u16),
    success: bool,
) -> Event {
    let (family, destination, port) = endpoint;
    base_event(
        session,
        pid,
        instance,
        timestamp_ns,
        EventType::NetworkConnect,
        "bash",
        EventPayload::NetworkConnect {
            family,
            source_address: None,
            source_port: None,
            destination_address: destination.to_owned(),
            destination_port: port,
            result: if success { 0 } else { -111 },
            success,
            errno: if success { None } else { Some(111) },
            established: false,
        },
    )
}

fn seeded_database() -> (TempDir, DesktopService) {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("workbench.db");
    let mut storage = Storage::open(&db).unwrap();
    storage
        .create_session(&new_session("session-alpha"))
        .unwrap();
    let events = vec![
        exec(
            "session-alpha",
            100,
            "boot:100:1",
            1_700_000_001_000_000_000,
            "/bin/bash",
            "bash",
        ),
        fork(
            "session-alpha",
            100,
            101,
            "boot:101:2",
            1_700_000_002_000_000_000,
            "cat",
        ),
        exec(
            "session-alpha",
            101,
            "boot:101:2",
            1_700_000_003_000_000_000,
            "/usr/bin/cat",
            "cat",
        ),
        file_open(
            "session-alpha",
            101,
            "boot:101:2",
            1_700_000_004_000_000_000,
            "/etc/hostname",
            true,
        ),
        connect(
            "session-alpha",
            101,
            "boot:101:2",
            1_700_000_005_000_000_000,
            (AddressFamily::Ipv4, "127.0.0.1", 9),
            false,
        ),
        file_open(
            "session-alpha",
            101,
            "boot:101:2",
            1_700_000_006_000_000_000,
            "relative.txt",
            false,
        ),
    ];
    storage.insert_events("session-alpha", &events).unwrap();
    finish(&mut storage, "session-alpha", events.len() as u64);
    let export_dir = dir.path().join("exports");
    (dir, DesktopService::new(db, export_dir))
}

#[test]
fn session_browser_overview_and_detail_use_persisted_rows() {
    let (_dir, service) = seeded_database();
    let list = service
        .list_sessions(ListSessionsRequest {
            limit: Some(20),
            search: None,
            status: None,
            sort_by: None,
            sort_direction: None,
            include_intelligence: Some(true),
        })
        .unwrap();
    assert_eq!(list.total_matched, 1);
    let session = &list.sessions[0];
    assert_eq!(session.id, "session-alpha");
    assert_eq!(session.event_count, 6);
    assert_eq!(session.process_count, 2);
    assert_eq!(session.status, "completed");
    assert!(
        !session.evidence_incomplete,
        "out-of-scope filtered events are not evidence loss"
    );
    assert!(session.verification.is_some());
    assert!(session.finding_counts.is_some());

    let overview = service
        .overview(OverviewRequest {
            recent_limit: Some(5),
        })
        .unwrap();
    assert_eq!(overview.total_sessions, 1);
    assert_eq!(overview.completed_sessions, 1);
    assert_eq!(overview.recent_sessions.len(), 1);

    let detail = service
        .get_session(SessionRequest {
            session_id: "session-alpha".to_owned(),
        })
        .unwrap();
    assert_eq!(detail.stats.event_count, 6);
    assert!(!detail.session.evidence_incomplete);
    assert!(!detail.stats.evidence_may_be_incomplete);
    assert!(detail
        .stats
        .events_by_type
        .iter()
        .any(|entry| entry.event_type == "file_open" && entry.count == 2));
    assert_eq!(
        detail.session.command_display,
        "/bin/bash -c cat /etc/hostname"
    );
}

#[test]
fn process_tree_links_only_observed_instances() {
    let (_dir, service) = seeded_database();
    let tree = service
        .list_processes(SessionRequest {
            session_id: "session-alpha".to_owned(),
        })
        .unwrap();
    assert_eq!(tree.processes.len(), 2);
    let root = tree
        .processes
        .iter()
        .find(|process| process.pid == 100)
        .unwrap();
    let child = tree
        .processes
        .iter()
        .find(|process| process.pid == 101)
        .unwrap();
    assert_eq!(root.child_instance_ids, vec!["boot:101:2"]);
    assert_eq!(
        child.parent_process_instance_id.as_deref(),
        Some("boot:100:1")
    );
    assert_eq!(child.relationship, "observed");
    assert!(tree.roots.contains(&"boot:100:1".to_owned()));
}

#[test]
fn timeline_filters_search_pagination_and_event_lookup() {
    let (_dir, service) = seeded_database();
    let response = service
        .query_timeline(TimelineRequest {
            session_id: "session-alpha".to_owned(),
            event_type: Some("file_open".to_owned()),
            pid: None,
            process_instance_id: None,
            from_ns: None,
            to_ns: None,
            search: Some("hostname".to_owned()),
            limit: Some(10),
            offset: Some(0),
        })
        .unwrap();
    assert_eq!(response.total, 1);
    assert_eq!(response.events.len(), 1);
    assert_eq!(response.events[0].event_type, "file_open");
    assert!(response.events[0].provenance.is_some());

    let event_id = response.events[0].id;
    let detail = service
        .get_event(EventRequest {
            session_id: "session-alpha".to_owned(),
            event_id,
        })
        .unwrap();
    assert_eq!(detail.event.id, event_id);

    let paged = service
        .query_timeline(TimelineRequest {
            session_id: "session-alpha".to_owned(),
            event_type: None,
            pid: None,
            process_instance_id: None,
            from_ns: None,
            to_ns: None,
            search: None,
            limit: Some(2),
            offset: Some(2),
        })
        .unwrap();
    assert_eq!(paged.total, 6);
    assert_eq!(paged.events.len(), 2);
    assert!(paged.has_more);

    let wrong_session = service.get_event(EventRequest {
        session_id: "session-alpha".to_owned(),
        event_id: 999_999,
    });
    assert!(wrong_session.is_err());
}

#[test]
fn filesystem_and_network_views_preserve_attempt_semantics() {
    let (_dir, service) = seeded_database();
    let files = service
        .query_filesystem(ActivityRequest {
            session_id: "session-alpha".to_owned(),
            pid: None,
            process_instance_id: None,
            from_ns: None,
            to_ns: None,
            success: Some(false),
            family: None,
            search: Some("relative".to_owned()),
            limit: Some(10),
            offset: Some(0),
        })
        .unwrap();
    assert_eq!(files.total, 1);
    assert!(!files.files[0].success);
    assert!(!files.files[0].path_is_absolute);

    let network = service
        .query_network(ActivityRequest {
            session_id: "session-alpha".to_owned(),
            pid: None,
            process_instance_id: None,
            from_ns: None,
            to_ns: None,
            success: Some(false),
            family: Some("ipv4".to_owned()),
            search: Some("127.0.0.1".to_owned()),
            limit: Some(10),
            offset: Some(0),
        })
        .unwrap();
    assert_eq!(network.total, 1);
    assert!(!network.connections[0].established);
    assert!(!network.connections[0].success);
    assert_eq!(network.connections[0].destination_port, 9);
}

#[test]
fn analysis_and_verification_run_through_existing_engines() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("analysis.db");
    let mut storage = Storage::open(&db).unwrap();
    storage
        .create_session(&new_session("session-analysis"))
        .unwrap();
    let events = vec![exec(
        "session-analysis",
        200,
        "boot:200:1",
        1_700_000_001_000_000_000,
        "/tmp/payload",
        "payload",
    )];
    storage.insert_events("session-analysis", &events).unwrap();
    finish(&mut storage, "session-analysis", events.len() as u64);
    drop(storage);
    let service = DesktopService::new(db, dir.path().join("exports"));

    let analysis = service
        .run_analysis(SessionRequest {
            session_id: "session-analysis".to_owned(),
        })
        .unwrap();
    assert!(analysis
        .findings
        .iter()
        .any(|finding| finding.rule_id == "SYSCALL-TEMP-EXEC"));

    let verification = service
        .run_verification(SessionRequest {
            session_id: "session-analysis".to_owned(),
        })
        .unwrap();
    assert_eq!(verification.session_id, "session-analysis");
    assert!(verification.verification_timestamp_ns > 0);
}

#[test]
fn export_writes_manifest_and_requires_explicit_overwrite() {
    let (_dir, service) = seeded_database();
    let exported = service
        .export_session(ExportRequest {
            session_id: "session-alpha".to_owned(),
            force: false,
        })
        .unwrap();
    assert_eq!(exported.format_version, "syscall-export/v2");
    assert_eq!(exported.status, "exported");
    assert!(!exported.manifest.is_empty());
    assert!(!exported
        .manifest
        .iter()
        .any(|entry| entry.component == "manifest"));
    let verification = syscall_export::verify_export_json(&exported.output_path).unwrap();
    assert!(verification.valid, "export must verify: {verification:?}");
    let metadata = std::fs::metadata(&exported.output_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let text = std::fs::read_to_string(&exported.output_path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["export_format_version"], "syscall-export/v2");
    assert_eq!(value["session"]["id"], "session-alpha");

    let error = service
        .export_session(ExportRequest {
            session_id: "session-alpha".to_owned(),
            force: false,
        })
        .unwrap_err();
    assert!(error.to_string().contains("already exists"));
    let overwritten = service
        .export_session(ExportRequest {
            session_id: "session-alpha".to_owned(),
            force: true,
        })
        .unwrap();
    assert_eq!(overwritten.status, "exported");
}

#[test]
fn invalid_requests_and_missing_database_have_structured_errors() {
    let (_dir, service) = seeded_database();
    let bad_id = service
        .get_session(SessionRequest {
            session_id: "../escape".to_owned(),
        })
        .unwrap_err();
    assert!(bad_id.to_string().contains("unsafe path component"));

    let bad_range = service
        .query_timeline(TimelineRequest {
            session_id: "session-alpha".to_owned(),
            event_type: None,
            pid: None,
            process_instance_id: None,
            from_ns: Some(2),
            to_ns: Some(1),
            search: None,
            limit: None,
            offset: None,
        })
        .unwrap_err();
    assert!(bad_range.to_string().contains("fromNs"));

    let bad_sort = service
        .list_sessions(ListSessionsRequest {
            limit: None,
            search: None,
            status: None,
            sort_by: Some("sql".to_owned()),
            sort_direction: None,
            include_intelligence: Some(false),
        })
        .unwrap_err();
    assert!(bad_sort.to_string().contains("unknown session sort"));

    let missing = DesktopService::new("/definitely/not/a/database.db", "/tmp/exports");
    let error = missing
        .list_sessions(ListSessionsRequest {
            limit: None,
            search: None,
            status: None,
            sort_by: None,
            sort_direction: None,
            include_intelligence: Some(false),
        })
        .unwrap_err();
    assert_eq!(error.code(), "DATABASE_NOT_FOUND");
}

#[test]
fn session_search_and_status_filter_do_not_cross_sessions() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("two.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("alpha")).unwrap();
    storage.create_session(&new_session("beta")).unwrap();
    let alpha_events = vec![exec(
        "alpha",
        10,
        "boot:10:1",
        1_700_000_001_000_000_000,
        "/bin/alpha",
        "alpha",
    )];
    storage.insert_events("alpha", &alpha_events).unwrap();
    finish(&mut storage, "alpha", 1);
    drop(storage);
    let service = DesktopService::new(db, dir.path().join("exports"));

    let response = service
        .list_sessions(ListSessionsRequest {
            limit: None,
            search: Some("alpha".to_owned()),
            status: Some("all".to_owned()),
            sort_by: Some("events".to_owned()),
            sort_direction: Some("desc".to_owned()),
            include_intelligence: Some(false),
        })
        .unwrap();
    assert_eq!(response.total_matched, 1);
    assert_eq!(response.sessions[0].id, "alpha");

    let missing = service
        .get_session(SessionRequest {
            session_id: "does-not-exist".to_owned(),
        })
        .unwrap_err();
    assert_eq!(missing.code(), "SESSION_NOT_FOUND");
}
