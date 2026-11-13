use rusqlite::params;
use syscall_core::{
    AddressFamily, Event, EventPayload, EventProvenance, EventType, RecordingScope, SCHEMA_VERSION,
};
use syscall_storage::{
    ActivityFilter, NewSession, SessionFinish, SessionStatus, Storage, TimelineFilter,
};
use tempfile::TempDir;

fn new_session(id: &str) -> NewSession {
    NewSession {
        id: id.to_owned(),
        schema_version: SCHEMA_VERSION,
        started_at_ns: 1_700_000_000_000_000_000,
        command: "/usr/bin/target".to_owned(),
        arguments: vec![],
        recording_scope: RecordingScope::TargetTree,
        boot_id: Some("boot".to_owned()),
        kernel_release: Some("6.6.0".to_owned()),
        collector_version: Some("0.1.0".to_owned()),
    }
}

fn complete(storage: &mut Storage, id: &str, persisted: u64) {
    storage
        .update_session_status(id, SessionStatus::Recording)
        .unwrap();
    storage
        .finish_session(
            id,
            &SessionFinish {
                ended_at_ns: 1_700_000_010_000_000_000,
                status: SessionStatus::Completed,
                dropped_events: 0,
                ringbuf_lost_events: 0,
                userspace_dropped_events: 0,
                malformed_events: 0,
                filtered_events: 0,
                error: None,
                termination_reason: Some("target_exit".to_owned()),
                target_exit_code: Some(0),
                target_exit_signal: None,
                recovered_from_status: None,
                recovered_at_ns: None,
                finalized_at_ns: Some(1_700_000_010_000_000_000),
                events_received: persisted,
                events_decoded: persisted,
                events_attributed: persisted,
                events_persisted: persisted,
                events_rejected_scope: 0,
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
    monotonic_ns: u64,
    event_type: EventType,
    payload: EventPayload,
    tracepoint: &str,
) -> Event {
    Event {
        id: None,
        session_id: session.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type,
        timestamp_ns,
        monotonic_ns,
        pid,
        tid: pid,
        uid: 1000,
        gid: 1000,
        ppid: Some(1),
        comm: "target".to_owned(),
        process_instance_id: instance.to_owned(),
        payload,
        provenance: Some(EventProvenance {
            raw_bpf_pid: Some(pid),
            raw_bpf_tgid: Some(pid),
            observer_pid: Some(pid),
            observer_tgid: Some(pid),
            source_tracepoint: Some(tracepoint.to_owned()),
            wire_schema_version: Some(3),
            attribution_method: Some("syscall_pair_attributed".to_owned()),
            timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
            monotonic_clock_domain: Some("monotonic_boot_raw".to_owned()),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn file_event(
    session: &str,
    pid: i32,
    instance: &str,
    timestamp_ns: i64,
    monotonic_ns: u64,
    path: &str,
    result: i64,
    success: bool,
    errno: Option<i32>,
) -> Event {
    base_event(
        session,
        pid,
        instance,
        timestamp_ns,
        monotonic_ns,
        EventType::FileOpen,
        EventPayload::FileOpen {
            path: path.to_owned(),
            path_is_absolute: path.starts_with('/'),
            path_truncated: false,
            dirfd: -100,
            flags: 0,
            result,
            success,
            errno,
        },
        "syscalls/sys_exit_openat",
    )
}

#[allow(clippy::too_many_arguments)]
fn connection_event(
    session: &str,
    pid: i32,
    instance: &str,
    timestamp_ns: i64,
    monotonic_ns: u64,
    family: AddressFamily,
    destination: &str,
    port: u16,
    result: i64,
    success: bool,
    errno: Option<i32>,
) -> Event {
    base_event(
        session,
        pid,
        instance,
        timestamp_ns,
        monotonic_ns,
        EventType::NetworkConnect,
        EventPayload::NetworkConnect {
            family,
            source_address: None,
            source_port: None,
            destination_address: destination.to_owned(),
            destination_port: port,
            result,
            success,
            errno,
            established: false,
        },
        "syscalls/sys_exit_connect",
    )
}

#[test]
fn file_activity_filters_pagination_and_ordering() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("activity.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s-files")).unwrap();
    let events = vec![
        file_event(
            "s-files",
            10,
            "boot:10:1",
            1000,
            10,
            "/etc/passwd",
            3,
            true,
            None,
        ),
        file_event(
            "s-files",
            10,
            "boot:10:1",
            2000,
            20,
            "relative.txt",
            -2,
            false,
            Some(2),
        ),
        file_event(
            "s-files",
            11,
            "boot:11:2",
            3000,
            30,
            "/tmp/a",
            4,
            true,
            None,
        ),
        file_event(
            "s-files",
            11,
            "boot:11:2",
            4000,
            40,
            "/tmp/b",
            -13,
            false,
            Some(13),
        ),
    ];
    storage.insert_events("s-files", &events).unwrap();
    complete(&mut storage, "s-files", 4);
    drop(storage);

    let storage = Storage::open_read_only(&db).unwrap();
    let mut filter = ActivityFilter::new("s-files");
    filter.limit = Some(2);
    let page1 = storage.query_file_activity(&filter).unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(page1[0].path, "/etc/passwd");
    assert_eq!(page1[1].path, "relative.txt");
    filter.offset = 2;
    let page2 = storage.query_file_activity(&filter).unwrap();
    assert_eq!(page2.len(), 2);
    assert_eq!(page2[0].path, "/tmp/a");
    assert_eq!(
        storage
            .count_file_activity(&ActivityFilter::new("s-files"))
            .unwrap(),
        4
    );

    let mut failed = ActivityFilter::new("s-files");
    failed.success = Some(false);
    let failed_rows = storage.query_file_activity(&failed).unwrap();
    assert_eq!(failed_rows.len(), 2);
    assert!(failed_rows.iter().all(|row| !row.success));
    assert_eq!(storage.count_file_activity(&failed).unwrap(), 2);

    let mut pid = ActivityFilter::new("s-files");
    pid.pid = Some(11);
    assert_eq!(storage.query_file_activity(&pid).unwrap().len(), 2);

    let mut range = ActivityFilter::new("s-files");
    range.from_ns = Some(1500);
    range.to_ns = Some(3500);
    let ranged = storage.query_file_activity(&range).unwrap();
    assert_eq!(ranged.len(), 2);
    assert!(ranged
        .iter()
        .all(|row| row.timestamp_ns >= 1500 && row.timestamp_ns <= 3500));

    let mut instance = ActivityFilter::new("s-files");
    instance.process_instance_id = Some("boot:11:2".to_owned());
    assert_eq!(storage.query_file_activity(&instance).unwrap().len(), 2);

    let timeline = storage
        .query_timeline(&TimelineFilter::new("s-files"))
        .unwrap();
    assert_eq!(timeline.len(), 4);
}

#[test]
fn connection_activity_family_result_and_pagination() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("activity.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s-net")).unwrap();
    let events = vec![
        connection_event(
            "s-net",
            10,
            "boot:10:1",
            1000,
            10,
            AddressFamily::Ipv4,
            "93.184.216.34",
            443,
            0,
            true,
            None,
        ),
        connection_event(
            "s-net",
            10,
            "boot:10:1",
            2000,
            20,
            AddressFamily::Ipv4,
            "127.0.0.1",
            9,
            -111,
            false,
            Some(111),
        ),
        connection_event(
            "s-net",
            11,
            "boot:11:2",
            3000,
            30,
            AddressFamily::Ipv6,
            "2001:db8::1",
            8443,
            0,
            true,
            None,
        ),
    ];
    storage.insert_events("s-net", &events).unwrap();
    complete(&mut storage, "s-net", 3);
    drop(storage);

    let storage = Storage::open_read_only(&db).unwrap();
    assert_eq!(
        storage
            .count_connection_activity(&ActivityFilter::new("s-net"))
            .unwrap(),
        3
    );

    let mut v6 = ActivityFilter::new("s-net");
    v6.family = Some(AddressFamily::Ipv6);
    let v6_rows = storage.query_connection_activity(&v6).unwrap();
    assert_eq!(v6_rows.len(), 1);
    assert_eq!(v6_rows[0].destination_address, "2001:db8::1");
    assert_eq!(v6_rows[0].destination_port, 8443);

    let mut failed = ActivityFilter::new("s-net");
    failed.success = Some(false);
    let failed_rows = storage.query_connection_activity(&failed).unwrap();
    assert_eq!(failed_rows.len(), 1);
    assert_eq!(failed_rows[0].errno, Some(111));
    assert!(!failed_rows[0].established);

    let mut page = ActivityFilter::new("s-net");
    page.limit = Some(1);
    page.offset = 1;
    let page_rows = storage.query_connection_activity(&page).unwrap();
    assert_eq!(page_rows.len(), 1);
    assert_eq!(page_rows[0].destination_address, "127.0.0.1");
}

#[test]
fn verification_detects_inconsistent_activity_semantics() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("activity.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s-bad")).unwrap();
    storage
        .update_session_status("s-bad", SessionStatus::Recording)
        .unwrap();

    // Insert rows directly to simulate corrupt/inconsistent stored evidence that
    // would have been rejected at the validation boundary.
    let payload = r#"{"kind":"file_open","path":"/etc/shadow","path_is_absolute":true,"path_truncated":false,"dirfd":-100,"flags":0,"result":-13,"success":true,"errno":null}"#;
    storage
        .connection()
        .execute(
            "INSERT INTO events (session_id, schema_version, event_type, timestamp_ns, monotonic_ns,
                pid, tid, ppid, uid, gid, process_instance_id, comm, payload,
                raw_bpf_pid, raw_bpf_tgid, observer_pid, observer_tgid, source_tracepoint,
                wire_schema_version, attribution_method, timestamp_clock_domain, monotonic_clock_domain)
             VALUES (?1, ?2, 'file_open', ?3, ?4, ?5, ?5, 1, 1000, 1000, ?6, 'target', ?7,
                 ?5, ?5, ?5, ?5, 'sched/sched_process_exec', 2, 'syscall_pair_attributed',
                 'wall_realtime_derived', 'monotonic_boot_raw')",
            params![
                "s-bad",
                i64::from(SCHEMA_VERSION),
                1000i64,
                10i64,
                42i64,
                "boot:42:1",
                payload,
            ],
        )
        .unwrap();
    complete(&mut storage, "s-bad", 1);

    let report = storage.verify_session("s-bad").unwrap();
    let codes: Vec<&str> = report.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(
        codes.contains(&"EVENT_ACTIVITY_RESULT_INCONSISTENT"),
        "missing result finding: {codes:?}"
    );
    assert!(
        codes.contains(&"EVENT_FILE_TRACEPOINT_INCONSISTENT"),
        "missing tracepoint finding: {codes:?}"
    );
    assert!(
        codes.contains(&"EVENT_ACTIVITY_WIRE_SCHEMA_INCONSISTENT"),
        "missing wire-schema finding: {codes:?}"
    );
}

#[test]
fn verification_accepts_valid_activity_exit_tracepoints() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("activity-valid.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s-valid")).unwrap();
    storage
        .update_session_status("s-valid", SessionStatus::Recording)
        .unwrap();
    storage
        .insert_events(
            "s-valid",
            &[
                file_event(
                    "s-valid",
                    10,
                    "boot:10:1",
                    1000,
                    10,
                    "/tmp/x",
                    3,
                    true,
                    None,
                ),
                connection_event(
                    "s-valid",
                    10,
                    "boot:10:1",
                    2000,
                    20,
                    AddressFamily::Ipv4,
                    "127.0.0.1",
                    1,
                    -111,
                    false,
                    Some(111),
                ),
            ],
        )
        .unwrap();
    complete(&mut storage, "s-valid", 2);

    let report = storage.verify_session("s-valid").unwrap();
    let codes: Vec<&str> = report.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(
        !codes.contains(&"EVENT_SOURCE_TRACEPOINT_INCONSISTENT"),
        "valid activity sources were rejected: {codes:?}"
    );
    assert!(
        !codes.contains(&"EVENT_FILE_TRACEPOINT_INCONSISTENT"),
        "valid file source was rejected: {codes:?}"
    );
    assert!(
        !codes.contains(&"EVENT_NETWORK_TRACEPOINT_INCONSISTENT"),
        "valid network source was rejected: {codes:?}"
    );
}

#[test]
fn schema_v4_read_only_queries_work_and_migration_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("activity.db");
    {
        let mut storage = Storage::open(&db).unwrap();
        storage.create_session(&new_session("s-mig")).unwrap();
        storage
            .insert_events(
                "s-mig",
                &[file_event(
                    "s-mig",
                    10,
                    "boot:10:1",
                    1000,
                    10,
                    "/tmp/x",
                    5,
                    true,
                    None,
                )],
            )
            .unwrap();
        complete(&mut storage, "s-mig", 1);
        let version: i64 = storage
            .connection()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 5);
    }
    // Reopen writable: migrations are idempotent.
    let storage = Storage::open(&db).unwrap();
    assert_eq!(storage.count_events("s-mig").unwrap(), 1);
    drop(storage);
    // Read-only investigation still works.
    let storage = Storage::open_read_only(&db).unwrap();
    assert_eq!(
        storage
            .query_file_activity(&ActivityFilter::new("s-mig"))
            .unwrap()
            .len(),
        1
    );
}
