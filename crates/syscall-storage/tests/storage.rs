use std::os::unix::fs::PermissionsExt;

use syscall_core::{
    Event, EventPayload, EventType, ProcessMetadata, RecordingScope, SCHEMA_VERSION,
};
use syscall_storage::{
    EventQuery, NewSession, SessionFinish, SessionStatus, Storage, StorageError,
};

fn exec_event(session: &str, pid: i32, timestamp: i64, filename: &str) -> Event {
    Event {
        id: None,
        session_id: session.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type: EventType::ProcessExec,
        timestamp_ns: timestamp,
        monotonic_ns: timestamp as u64,
        pid,
        tid: pid,
        uid: 1000,
        gid: 1000,
        ppid: Some(1),
        comm: "sleep".to_owned(),
        process_instance_id: format!("boot:{pid}:100"),
        payload: EventPayload::ProcessExec {
            filename: filename.to_owned(),
            process: ProcessMetadata {
                ppid: Some(1),
                start_time_ticks: Some(100),
            },
            old_pid: Some(1),
        },
        provenance: None,
    }
}

fn fork_event(session: &str, parent: i32, child: i32, timestamp: i64) -> Event {
    Event {
        id: None,
        session_id: session.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type: EventType::ProcessFork,
        timestamp_ns: timestamp,
        monotonic_ns: timestamp as u64,
        pid: child,
        tid: child,
        uid: 1000,
        gid: 1000,
        ppid: Some(parent),
        comm: "child".to_owned(),
        process_instance_id: format!("boot:{child}:101"),
        payload: EventPayload::ProcessFork {
            parent_pid: parent,
            parent_tgid: Some(parent),
            child_pid: child,
            child_comm: "child".to_owned(),
            child_start_time_ticks: Some(101),
        },
        provenance: None,
    }
}

fn exit_event(session: &str, pid: i32, start_time_ticks: u64, timestamp: i64) -> Event {
    Event {
        id: None,
        session_id: session.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type: EventType::ProcessExit,
        timestamp_ns: timestamp,
        monotonic_ns: timestamp as u64,
        pid,
        tid: pid,
        uid: 1000,
        gid: 1000,
        ppid: Some(1),
        comm: "sleep".to_owned(),
        process_instance_id: format!("boot:{pid}:{start_time_ticks}"),
        payload: EventPayload::ProcessExit {
            process: ProcessMetadata {
                ppid: Some(1),
                start_time_ticks: Some(start_time_ticks),
            },
            exit_priority: 120,
        },
        provenance: None,
    }
}

fn new_session(id: &str) -> NewSession {
    NewSession {
        id: id.to_owned(),
        schema_version: SCHEMA_VERSION,
        started_at_ns: 1_700_000_000_000_000_000,
        command: "/usr/bin/sleep".to_owned(),
        arguments: vec!["5".to_owned()],
        recording_scope: RecordingScope::TargetTree,
        boot_id: Some("boot".to_owned()),
        kernel_release: Some("6.6.0-test".to_owned()),
        collector_version: Some("0.1.0".to_owned()),
    }
}

#[test]
fn sessions_and_events_round_trip() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-1")).unwrap();

    let events = vec![
        exec_event("s-1", 100, 1_000, "/usr/bin/sleep"),
        fork_event("s-1", 100, 101, 2_000),
        exit_event("s-1", 101, 101, 3_000),
        exit_event("s-1", 100, 100, 4_000),
    ];
    assert_eq!(storage.insert_events("s-1", &events).unwrap(), 4);

    let query = EventQuery::new("s-1");
    let stored = storage.query_events(&query).unwrap();
    assert_eq!(stored.len(), 4);
    assert_eq!(stored[0].event_type, EventType::ProcessExec);
    assert_eq!(stored[0].payload, events[0].payload);
    assert!(stored[0].id.is_some());
    assert_eq!(stored[3].event_type, EventType::ProcessExit);

    let summary = storage.get_session("s-1").unwrap().unwrap();
    assert_eq!(summary.event_count, 4);
    assert_eq!(summary.process_count, 2);
    assert_eq!(summary.status, SessionStatus::Starting);
    assert_eq!(summary.arguments, vec!["5"]);
    assert_eq!(summary.recording_scope, RecordingScope::TargetTree);

    let counts = storage.event_type_counts("s-1").unwrap();
    assert_eq!(
        counts,
        vec![
            (EventType::ProcessExec, 1),
            (EventType::ProcessFork, 1),
            (EventType::ProcessExit, 2),
        ]
    );
    assert_eq!(storage.count_events("s-1").unwrap(), 4);
}

#[test]
fn event_filters_and_pagination_work() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-2")).unwrap();
    let events = vec![
        exec_event("s-2", 10, 1_000, "/bin/a"),
        exec_event("s-2", 20, 2_000, "/bin/b"),
        exit_event("s-2", 20, 100, 3_000),
    ];
    storage.insert_events("s-2", &events).unwrap();

    let mut query = EventQuery::new("s-2");
    query.pid = Some(20);
    let stored = storage.query_events(&query).unwrap();
    assert_eq!(stored.len(), 2);
    assert!(stored.iter().all(|event| event.pid == 20));

    query = EventQuery::new("s-2");
    query.event_type = Some(EventType::ProcessExec);
    assert_eq!(storage.query_events(&query).unwrap().len(), 2);

    query.event_type = None;
    query.limit = 1;
    query.offset = 1;
    let page = storage.query_events(&query).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].pid, 20);
}

#[test]
fn finish_session_records_loss_and_status() {
    let storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-3")).unwrap();
    storage
        .update_session_status("s-3", SessionStatus::Recording)
        .unwrap();
    storage
        .finish_session(
            "s-3",
            &SessionFinish {
                ended_at_ns: 1_700_000_005_000_000_000,
                status: SessionStatus::Completed,
                dropped_events: 7,
                ringbuf_lost_events: 5,
                userspace_dropped_events: 2,
                malformed_events: 1,
                filtered_events: 42,
                error: None,
                termination_reason: Some("target_exit".to_owned()),
                target_exit_code: Some(0),
                target_exit_signal: None,
                recovered_from_status: None,
                recovered_at_ns: None,
                finalized_at_ns: Some(1_700_000_005_000_000_000),
                events_received: 50,
                events_decoded: 49,
                events_attributed: 7,
                events_persisted: 0,
                events_rejected_scope: 42,
                events_rejected_malformed: 1,
                events_persist_failed: 0,
                events_self_filtered: 3,
            },
        )
        .unwrap();

    let summary = storage.get_session("s-3").unwrap().unwrap();
    assert_eq!(summary.status, SessionStatus::Completed);
    assert_eq!(summary.dropped_events, 7);
    assert_eq!(summary.ringbuf_lost_events, 5);
    assert_eq!(summary.userspace_dropped_events, 2);
    assert_eq!(summary.malformed_events, 1);
    assert_eq!(summary.filtered_events, 42);
    assert_eq!(summary.events_self_filtered, 3);
    assert_eq!(summary.ended_at_ns, Some(1_700_000_005_000_000_000));
}

#[test]
fn list_sessions_is_newest_first() {
    let storage = Storage::open_in_memory().unwrap();
    let mut older = new_session("s-older");
    older.started_at_ns -= 10_000;
    storage.create_session(&older).unwrap();
    storage.create_session(&new_session("s-newer")).unwrap();

    let sessions = storage.list_sessions(10).unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].id, "s-newer");
    assert_eq!(sessions[1].id, "s-older");
}

#[test]
fn invalid_events_are_rejected() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-4")).unwrap();
    let mut event = exec_event("s-4", 100, 1_000, "/bin/a");
    event.comm.clear();
    let err = storage.insert_events("s-4", &[event]).unwrap_err();
    assert!(matches!(err, StorageError::InvalidEvent(_)));
}

#[test]
fn activity_events_persist_and_round_trip() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-5")).unwrap();
    let mut event = exec_event("s-5", 100, 1_000, "/bin/a");
    event.event_type = EventType::FileOpen;
    event.payload = EventPayload::FileOpen {
        path: "/etc/passwd".to_owned(),
        path_is_absolute: true,
        path_truncated: false,
        dirfd: -100,
        flags: 0,
        result: 5,
        success: true,
        errno: None,
    };
    storage.insert_events("s-5", &[event]).unwrap();
    let events = storage.query_events(&EventQuery::new("s-5")).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].payload, EventPayload::FileOpen { .. }));
}

#[test]
fn cross_session_batch_is_rejected() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-6")).unwrap();
    let event = exec_event("other", 100, 1_000, "/bin/a");
    assert!(storage.insert_events("s-6", &[event]).is_err());
}

#[test]
fn database_file_permissions_are_restrictive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syscall.db");
    let storage = Storage::open(&path).unwrap();
    drop(storage);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn database_reopens_and_migrates_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syscall.db");
    {
        let storage = Storage::open(&path).unwrap();
        storage.create_session(&new_session("s-7")).unwrap();
        storage
            .update_session_status("s-7", SessionStatus::Recording)
            .unwrap();
        storage
            .finish_session(
                "s-7",
                &SessionFinish {
                    ended_at_ns: 1_700_000_001_000_000_000,
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
                    finalized_at_ns: Some(1_700_000_001_000_000_000),
                    events_received: 0,
                    events_decoded: 0,
                    events_attributed: 0,
                    events_persisted: 0,
                    events_rejected_scope: 0,
                    events_rejected_malformed: 0,
                    events_persist_failed: 0,
                    events_self_filtered: 0,
                },
            )
            .unwrap();
    }
    let storage = Storage::open(&path).unwrap();
    let session = storage.get_session("s-7").unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Completed);

    let conn = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 5);
}

#[test]
fn future_schema_version_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syscall.db");
    {
        let _storage = Storage::open(&path).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
    }
    let err = Storage::open(&path).unwrap_err();
    assert!(matches!(
        err,
        StorageError::UnsupportedSchemaVersion { found: 99, .. }
    ));
}

#[test]
fn read_only_open_does_not_write_and_requires_existing_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syscall.db");
    {
        let storage = Storage::open(&path).unwrap();
        storage.create_session(&new_session("s-8")).unwrap();
        // Writable open recovers abandoned non-terminal sessions; keep one
        // finalized here so read-only inspection sees stable metadata.
        storage
            .update_session_status("s-8", SessionStatus::Recording)
            .unwrap();
        storage
            .finish_session(
                "s-8",
                &SessionFinish {
                    ended_at_ns: 1_700_000_001_000_000_000,
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
                    finalized_at_ns: Some(1_700_000_001_000_000_000),
                    events_received: 0,
                    events_decoded: 0,
                    events_attributed: 0,
                    events_persisted: 0,
                    events_rejected_scope: 0,
                    events_rejected_malformed: 0,
                    events_persist_failed: 0,
                    events_self_filtered: 0,
                },
            )
            .unwrap();
    }
    let storage = Storage::open_read_only(&path).unwrap();
    assert_eq!(storage.list_sessions(10).unwrap().len(), 1);
    let missing = dir.path().join("missing.db");
    assert!(Storage::open_read_only(&missing).is_err());
}

#[test]
fn process_summaries_separate_pid_reuse_instances() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-10")).unwrap();

    let mut first = exec_event("s-10", 42, 1_000, "/bin/first");
    first.process_instance_id = "boot:42:100".to_owned();
    let mut second = exec_event("s-10", 42, 2_000, "/bin/second");
    second.process_instance_id = "boot:42:200".to_owned();
    if let EventPayload::ProcessExec { process, .. } = &mut second.payload {
        process.start_time_ticks = Some(200);
    }

    storage.insert_events("s-10", &[first, second]).unwrap();

    let summaries = storage.process_summaries("s-10", 10).unwrap();
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].pid, 42);
    assert_ne!(
        summaries[0].process_instance_id,
        summaries[1].process_instance_id
    );
    assert!(summaries
        .iter()
        .all(|summary| summary.event_count == 1 && !summary.exited));
}

#[test]
fn corrupt_payload_is_reported_not_panicked() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-9")).unwrap();
    storage
        .connection_mut()
        .execute(
            "INSERT INTO events (
                session_id, schema_version, event_type, timestamp_ns, monotonic_ns,
                pid, tid, ppid, uid, gid, process_instance_id, comm, payload
             ) VALUES ('s-9', 1, 'process_exec', 1, 1, 10, 10, 1, 1000, 1000,
                       'boot:10:1', 'bad', '{not json}')",
            [],
        )
        .unwrap();
    let err = storage.query_events(&EventQuery::new("s-9")).unwrap_err();
    assert!(matches!(err, StorageError::Sqlite(_)));
}

#[test]
fn abandoned_starting_session_is_recovered_on_writable_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syscall.db");
    {
        let mut storage = Storage::open(&path).unwrap();
        storage.create_session(&new_session("s-abandon")).unwrap();
        storage
            .insert_events(
                "s-abandon",
                &[exec_event("s-abandon", 42, 1_000, "/bin/true")],
            )
            .unwrap();
        // simulate crash: drop without finalization while still starting
    }
    let storage = Storage::open(&path).unwrap();
    let session = storage.get_session("s-abandon").unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Recovered);
    assert_eq!(session.recovered_from_status, Some(SessionStatus::Starting));
    assert_eq!(
        session.termination_reason.as_deref(),
        Some("abnormal_termination_recovered")
    );
    assert!(session.recovered_at_ns.is_some());
    assert_eq!(storage.count_events("s-abandon").unwrap(), 1);
    // idempotent recovery
    drop(storage);
    let storage = Storage::open(&path).unwrap();
    let session = storage.get_session("s-abandon").unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Recovered);
    assert_eq!(storage.count_events("s-abandon").unwrap(), 1);
}

#[test]
fn repeated_finalization_is_idempotent_and_conflicting_outcome_rejected() {
    let storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-fin")).unwrap();
    storage
        .update_session_status("s-fin", SessionStatus::Recording)
        .unwrap();
    let finish = SessionFinish {
        ended_at_ns: 1_700_000_002_000_000_000,
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
        finalized_at_ns: Some(1_700_000_002_000_000_000),
        events_received: 1,
        events_decoded: 1,
        events_attributed: 1,
        events_persisted: 0,
        events_rejected_scope: 0,
        events_rejected_malformed: 0,
        events_persist_failed: 0,
        events_self_filtered: 0,
    };
    storage.finish_session("s-fin", &finish).unwrap();
    storage.finish_session("s-fin", &finish).unwrap(); // idempotent

    let mut conflicting = finish.clone();
    conflicting.status = SessionStatus::Failed;
    conflicting.error = Some("different".to_owned());
    let err = storage.finish_session("s-fin", &conflicting).unwrap_err();
    assert!(matches!(err, StorageError::ConflictingFinalization { .. }));
}

#[test]
fn invalid_session_transitions_are_rejected() {
    let storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-trans")).unwrap();
    storage
        .update_session_status("s-trans", SessionStatus::Recording)
        .unwrap();
    storage
        .finish_session(
            "s-trans",
            &SessionFinish {
                ended_at_ns: 1_700_000_002_000_000_000,
                status: SessionStatus::Interrupted,
                dropped_events: 0,
                ringbuf_lost_events: 0,
                userspace_dropped_events: 0,
                malformed_events: 0,
                filtered_events: 0,
                error: None,
                termination_reason: Some("interrupted".to_owned()),
                target_exit_code: None,
                target_exit_signal: Some(2),
                recovered_from_status: None,
                recovered_at_ns: None,
                finalized_at_ns: Some(1_700_000_002_000_000_000),
                events_received: 0,
                events_decoded: 0,
                events_attributed: 0,
                events_persisted: 0,
                events_rejected_scope: 0,
                events_rejected_malformed: 0,
                events_persist_failed: 0,
                events_self_filtered: 0,
            },
        )
        .unwrap();
    let err = storage
        .update_session_status("s-trans", SessionStatus::Recording)
        .unwrap_err();
    assert!(matches!(
        err,
        StorageError::InvalidTransition { .. } | StorageError::ConflictingFinalization { .. }
    ));
}

#[test]
fn migration_preserves_v1_session_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(include_str!("../migrations/001_initial.sql"))
            .unwrap();
        conn.pragma_update(None, "user_version", 1i64).unwrap();
        conn.execute(
            "INSERT INTO sessions (id, schema_version, started_at_ns, ended_at_ns, command, arguments, recording_scope, status, dropped_events, ringbuf_lost_events, userspace_dropped_events, malformed_events, filtered_events)
             VALUES ('legacy', 1, 100, 200, '/bin/true', '[]', 'target-tree', 'completed', 0, 0, 0, 0, 0)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO events (session_id, schema_version, event_type, timestamp_ns, monotonic_ns, pid, tid, ppid, uid, gid, process_instance_id, comm, payload)
             VALUES ('legacy', 1, 'process_exec', 150, 150, 10, 10, 1, 1000, 1000, 'boot:10:1', 'true', '{\"kind\":\"process_exec\",\"filename\":\"/bin/true\",\"ppid\":1,\"start_time_ticks\":1,\"old_pid\":1}')",
            [],
        ).unwrap();
    }
    let storage = Storage::open(&path).unwrap();
    let session = storage.get_session("legacy").unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Completed);
    assert_eq!(session.event_count, 1);
    assert_eq!(session.termination_reason, None); // historical row preserved as-is
    let events = storage.query_events(&EventQuery::new("legacy")).unwrap();
    assert_eq!(events.len(), 1);
    assert!(
        events[0].provenance.is_none(),
        "legacy events must not have fabricated provenance"
    );
}

#[test]
fn recovery_does_not_reclaim_actively_owned_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syscall.db");
    let _active_lock;
    {
        let mut storage = Storage::open(&path).unwrap();
        storage.create_session(&new_session("s-active")).unwrap();
        storage
            .insert_events(
                "s-active",
                &[exec_event("s-active", 42, 1_000, "/bin/true")],
            )
            .unwrap();
        // simulate active collector ownership
        _active_lock = syscall_storage::lock::acquire_exclusive(&path, "s-active").unwrap();
    }
    // another writable opener must not recover the active session
    let storage = Storage::open(&path).unwrap();
    let session = storage.get_session("s-active").unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Starting);
    assert_eq!(storage.count_events("s-active").unwrap(), 1);
    // after owner releases, recovery can reclaim
    drop(_active_lock);
    drop(storage);
    let storage = Storage::open(&path).unwrap();
    let session = storage.get_session("s-active").unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Recovered);
}

#[test]
fn recovery_reclaims_abandoned_but_skips_active_with_independent_connections() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syscall.db");
    let mut owner = Storage::open(&path).unwrap();
    owner.create_session(&new_session("s-live")).unwrap();
    owner.create_session(&new_session("s-dead")).unwrap();
    owner
        .insert_events("s-live", &[exec_event("s-live", 7, 1_000, "/bin/live")])
        .unwrap();
    owner
        .insert_events("s-dead", &[exec_event("s-dead", 8, 2_000, "/bin/dead")])
        .unwrap();
    let live_lock = syscall_storage::lock::acquire_exclusive(&path, "s-live").unwrap();

    // independent writable connection attempts recovery
    let inspector = Storage::open(&path).unwrap();
    let live = inspector.get_session("s-live").unwrap().unwrap();
    let dead = inspector.get_session("s-dead").unwrap().unwrap();
    assert_eq!(
        live.status,
        SessionStatus::Starting,
        "active session must not be recovered"
    );
    assert_eq!(
        dead.status,
        SessionStatus::Recovered,
        "abandoned session must be recovered"
    );
    assert_eq!(inspector.count_events("s-live").unwrap(), 1);
    assert_eq!(inspector.count_events("s-dead").unwrap(), 1);

    // repeated/concurrent-like recovery attempts remain idempotent and safe
    assert_eq!(inspector.recover_abandoned_sessions().unwrap(), 0);
    drop(owner);
    drop(live_lock);
    drop(inspector);
    let storage = Storage::open(&path).unwrap();
    assert_eq!(
        storage.get_session("s-live").unwrap().unwrap().status,
        SessionStatus::Recovered
    );
    assert_eq!(
        storage.get_session("s-dead").unwrap().unwrap().status,
        SessionStatus::Recovered
    );
}

#[test]
fn event_provenance_round_trips_and_legacy_rows_remain_unknown() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-prov")).unwrap();
    let mut event = exec_event("s-prov", 42, 1_000, "/bin/true");
    event.provenance = Some(syscall_core::EventProvenance {
        raw_bpf_pid: Some(9001),
        raw_bpf_tgid: Some(9001),
        observer_pid: Some(42),
        observer_tgid: Some(42),
        source_tracepoint: Some("sched/sched_process_exec".to_owned()),
        wire_schema_version: Some(2),
        attribution_method: Some("ns_tgid_correlated".to_owned()),
        timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
        monotonic_clock_domain: Some("monotonic_boot_raw".to_owned()),
    });
    storage.insert_events("s-prov", &[event.clone()]).unwrap();
    let loaded = storage.query_events(&EventQuery::new("s-prov")).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].provenance, event.provenance);
}

#[test]
fn event_queries_are_deterministically_ordered_by_time_and_id() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-order")).unwrap();
    // same timestamp_ns and monotonic_ns: insertion/id must provide stable tie-breaker
    let mut e1 = exec_event("s-order", 10, 5_000, "/bin/a");
    let mut e2 = exec_event("s-order", 11, 5_000, "/bin/b");
    e1.monotonic_ns = 100;
    e2.monotonic_ns = 100;
    storage.insert_events("s-order", &[e1, e2]).unwrap();
    let loaded = storage.query_events(&EventQuery::new("s-order")).unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].pid, 10);
    assert_eq!(loaded[1].pid, 11);
    assert!(loaded[0].id.unwrap() < loaded[1].id.unwrap());
}
