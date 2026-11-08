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
fn schema_only_events_cannot_be_persisted() {
    let mut storage = Storage::open_in_memory().unwrap();
    storage.create_session(&new_session("s-5")).unwrap();
    let mut event = exec_event("s-5", 100, 1_000, "/bin/a");
    event.event_type = EventType::FileOpen;
    event.payload = EventPayload::FileOpen {
        path: "/etc/passwd".to_owned(),
    };
    assert!(storage.insert_events("s-5", &[event]).is_err());
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
    }
    let storage = Storage::open(&path).unwrap();
    assert!(storage.get_session("s-7").unwrap().is_some());

    let conn = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1);
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
    }
    let mut storage = Storage::open_read_only(&path).unwrap();
    assert_eq!(storage.list_sessions(10).unwrap().len(), 1);
    assert!(storage.insert_events("s-8", &[]).is_ok());

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
