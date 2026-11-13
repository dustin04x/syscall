use std::fs;

use rusqlite::Connection;
use syscall_core::verify::VerificationAssessment;
use syscall_core::{
    Event, EventPayload, EventProvenance, EventType, ProcessMetadata, RecordingScope,
    SCHEMA_VERSION,
};
use syscall_storage::{NewSession, SessionFinish, SessionStatus, Storage};

fn make_session(id: &str) -> NewSession {
    NewSession {
        id: id.to_owned(),
        schema_version: SCHEMA_VERSION,
        started_at_ns: 1_700_000_000_000_000_000,
        command: "/bin/echo".to_owned(),
        arguments: vec![],
        recording_scope: RecordingScope::TargetTree,
        boot_id: Some("boot-test".to_owned()),
        kernel_release: Some("6.8.0-test".to_owned()),
        collector_version: Some("0.1.0-test".to_owned()),
    }
}

fn exec_event(session_id: &str, pid: i32, ts: i64, mono: u64) -> Event {
    Event {
        id: None,
        session_id: session_id.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type: EventType::ProcessExec,
        timestamp_ns: ts,
        monotonic_ns: mono,
        pid,
        tid: pid,
        uid: 1000,
        gid: 1000,
        ppid: Some(1),
        comm: "echo".to_owned(),
        process_instance_id: format!("boot-test:{pid}:100"),
        payload: EventPayload::ProcessExec {
            filename: "/bin/echo".to_owned(),
            process: ProcessMetadata {
                ppid: Some(1),
                start_time_ticks: Some(100),
            },
            old_pid: None,
        },
        provenance: Some(EventProvenance {
            raw_bpf_pid: Some(pid),
            raw_bpf_tgid: Some(pid),
            observer_pid: Some(pid),
            observer_tgid: Some(pid),
            source_tracepoint: Some("sched/sched_process_exec".to_owned()),
            wire_schema_version: Some(2),
            attribution_method: Some("ns_tgid_correlated".to_owned()),
            timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
            monotonic_clock_domain: Some("monotonic_boot_raw".to_owned()),
        }),
    }
}

fn complete_clean(storage: &mut Storage, session_id: &str, events: u64) {
    storage
        .finish_session(
            session_id,
            &SessionFinish {
                ended_at_ns: 1_700_000_005_000_000_000,
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
                finalized_at_ns: Some(1_700_000_005_000_000_000),
                recovered_from_status: None,
                recovered_at_ns: None,
                events_received: events,
                events_decoded: events,
                events_attributed: events,
                events_persisted: events,
                events_rejected_scope: 0,
                events_rejected_malformed: 0,
                events_persist_failed: 0,
                events_self_filtered: 0,
            },
        )
        .unwrap();
}

#[test]
fn clean_session_verifies_without_error_or_critical() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("clean.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("s1")).unwrap();
    storage
        .update_session_status("s1", SessionStatus::Recording)
        .unwrap();
    storage
        .insert_events("s1", &[exec_event("s1", 42, 1_000, 100)])
        .unwrap();
    complete_clean(&mut storage, "s1", 1);
    drop(storage);

    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("s1").unwrap();
    assert!(matches!(
        report.assessment,
        VerificationAssessment::Valid
            | VerificationAssessment::ValidButIncomplete
            | VerificationAssessment::Warning
    ));
    assert_eq!(report.severity_counts.error, 0);
    assert_eq!(report.severity_counts.critical, 0);
}

#[test]
fn legacy_session_with_null_provenance_is_not_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 1;
         CREATE TABLE sessions (
            id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, started_at_ns INTEGER NOT NULL,
            ended_at_ns INTEGER, command TEXT NOT NULL, arguments TEXT NOT NULL DEFAULT '[]',
            recording_scope TEXT NOT NULL, status TEXT NOT NULL, boot_id TEXT, kernel_release TEXT,
            collector_version TEXT, dropped_events INTEGER NOT NULL DEFAULT 0,
            ringbuf_lost_events INTEGER NOT NULL DEFAULT 0, userspace_dropped_events INTEGER NOT NULL DEFAULT 0,
            malformed_events INTEGER NOT NULL DEFAULT 0, filtered_events INTEGER NOT NULL DEFAULT 0, error TEXT
         );
         CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            schema_version INTEGER NOT NULL, event_type TEXT NOT NULL, timestamp_ns INTEGER NOT NULL,
            monotonic_ns INTEGER NOT NULL, pid INTEGER NOT NULL, tid INTEGER NOT NULL, ppid INTEGER,
            uid INTEGER, gid INTEGER, process_instance_id TEXT NOT NULL, comm TEXT NOT NULL, payload TEXT NOT NULL
         );",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO sessions (id,schema_version,started_at_ns,ended_at_ns,command,arguments,recording_scope,status)
         VALUES (?1,1,100,200,'/bin/echo','[]','target-tree','completed')",
        ["legacy"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO events (session_id,schema_version,event_type,timestamp_ns,monotonic_ns,pid,tid,ppid,uid,gid,process_instance_id,comm,payload)
         VALUES ('legacy',1,'process_exec',1000,500,42,42,1,1000,1000,'boot:42:1','echo','{\"filename\":\"/bin/echo\",\"process\":{\"ppid\":1,\"start_time_ticks\":1}}')",
        [],
    )
    .unwrap();
    drop(conn);

    // Migrate to latest via supported writable open, then verify read-only (verify itself must not migrate).
    {
        let _ = Storage::open(&path).unwrap();
    }
    let ro = Storage::open_read_only(&path).unwrap();
    let report = ro.verify_session("legacy").unwrap();
    assert_ne!(report.assessment, VerificationAssessment::Invalid);
    assert!(!report.findings.iter().any(|f| {
        f.code == "EVENT_PROVENANCE_INVALID" || f.code == "DB_INTEGRITY_CHECK_FAILED"
    }));
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "PROVENANCE_UNAVAILABLE_LEGACY"));
}

#[test]
fn recovered_session_is_warning_not_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("rec.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("srec")).unwrap();
    storage
        .update_session_status("srec", SessionStatus::Recording)
        .unwrap();
    storage
        .insert_events("srec", &[exec_event("srec", 7, 1_000, 100)])
        .unwrap();
    drop(storage);
    // writable reopen triggers recovery
    let storage = Storage::open(&db).unwrap();
    drop(storage);

    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("srec").unwrap();
    assert!(matches!(
        report.assessment,
        VerificationAssessment::ValidButIncomplete | VerificationAssessment::Warning
    ));
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "SESSION_RECOVERED"));
    assert!(!report.findings.iter().any(|f| f.severity
        == syscall_core::verify::FindingSeverity::Critical
        || f.severity == syscall_core::verify::FindingSeverity::Error));
}

#[test]
fn missing_recovery_metadata_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("badrec.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("sbad")).unwrap();
    storage
        .update_session_status("sbad", SessionStatus::Recording)
        .unwrap();
    storage
        .insert_events("sbad", &[exec_event("sbad", 7, 1_000, 100)])
        .unwrap();
    drop(storage);
    let _storage = Storage::open(&db).unwrap(); // recover
    drop(_storage);
    let conn = Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE sessions SET recovered_from_status = NULL, termination_reason = 'weird' WHERE id='sbad'",
        [],
    )
    .unwrap();
    drop(conn);

    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("sbad").unwrap();
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "SESSION_RECOVERY_METADATA_INCONSISTENT"));
    assert_eq!(report.assessment, VerificationAssessment::Invalid);
}

#[test]
fn counter_mismatch_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("count.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("sc")).unwrap();
    storage
        .update_session_status("sc", SessionStatus::Recording)
        .unwrap();
    storage
        .insert_events("sc", &[exec_event("sc", 7, 1_000, 100)])
        .unwrap();
    complete_clean(&mut storage, "sc", 1);
    drop(storage);
    let conn = Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE sessions SET events_persisted = 99 WHERE id='sc'",
        [],
    )
    .unwrap();
    drop(conn);

    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("sc").unwrap();
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "ACCOUNTING_PERSISTED_MISMATCH"));
}

#[test]
fn invalid_source_tracepoint_and_wire_schema_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("prov.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("sp")).unwrap();
    storage
        .update_session_status("sp", SessionStatus::Recording)
        .unwrap();
    storage
        .insert_events("sp", &[exec_event("sp", 7, 1_000, 100)])
        .unwrap();
    complete_clean(&mut storage, "sp", 1);
    drop(storage);
    let conn = Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE events SET source_tracepoint='sched/sched_process_fork', wire_schema_version=99 WHERE session_id='sp'",
        [],
    )
    .unwrap();
    drop(conn);

    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("sp").unwrap();
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "EVENT_SOURCE_TRACEPOINT_INCONSISTENT"));
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "EVENT_WIRE_SCHEMA_INVALID"));
}

#[test]
fn verification_is_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ro.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("sro")).unwrap();
    storage
        .update_session_status("sro", SessionStatus::Recording)
        .unwrap();
    storage
        .insert_events("sro", &[exec_event("sro", 7, 1_000, 100)])
        .unwrap();
    complete_clean(&mut storage, "sro", 1);
    drop(storage);

    let before = fs::read(&db).unwrap();
    let wal_path = {
        let mut p = db.as_os_str().to_os_string();
        p.push("-wal");
        std::path::PathBuf::from(p)
    };
    let shm_path = {
        let mut p = db.as_os_str().to_os_string();
        p.push("-shm");
        std::path::PathBuf::from(p)
    };
    let before_wal = fs::read(&wal_path).ok();
    let before_shm = fs::read(&shm_path).ok();
    let ro = Storage::open_read_only(&db).unwrap();
    let _report = ro.verify_session("sro").unwrap();
    drop(ro);
    let after = fs::read(&db).unwrap();
    assert_eq!(before, after, "database file bytes must remain unchanged");
    // WAL/SHM sidecar presence can vary by SQLite/runtime state; if present they must not gain modified content.
    if let (Some(b), Some(a)) = (before_wal, fs::read(&wal_path).ok()) {
        assert_eq!(b, a, "wal sidecar must remain unchanged when present");
    }
    if let (Some(b), Some(a)) = (before_shm, fs::read(&shm_path).ok()) {
        assert_eq!(b, a, "shm sidecar must remain unchanged when present");
    }
}

#[test]
fn unsupported_schema_cannot_be_opened_read_only_for_verification() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("future.db");
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 999; CREATE TABLE sessions(id TEXT PRIMARY KEY); CREATE TABLE events(id INTEGER PRIMARY KEY, session_id TEXT);",
    )
    .unwrap();
    drop(conn);
    // Unsupported/future schema is rejected by read-only open (no migration, no writes) so verification cannot proceed.
    assert!(Storage::open_read_only(&db).is_err());
}

use std::path::{Path as FsPath, PathBuf};
use syscall_core::verify::{verify_exit_code, FindingSeverity, VerificationAssessment as VA};

fn file_bytes(p: &FsPath) -> Option<Vec<u8>> {
    fs::read(p).ok()
}
fn meta_snapshot(p: &FsPath) -> Option<(u64, std::time::SystemTime)> {
    let m = fs::metadata(p).ok()?;
    let t = m.modified().ok()?;
    Some((m.len(), t))
}
fn sidecar(p: &FsPath, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}
struct DbSnapshot {
    db_hash: Option<Vec<u8>>,
    wal_hash: Option<Vec<u8>>,
    shm_hash: Option<Vec<u8>>,
    db_meta: Option<(u64, std::time::SystemTime)>,
    wal_meta: Option<(u64, std::time::SystemTime)>,
    shm_meta: Option<(u64, std::time::SystemTime)>,
}
fn snapshot_db(db: &FsPath) -> DbSnapshot {
    DbSnapshot {
        db_hash: file_bytes(db),
        wal_hash: file_bytes(&sidecar(db, "-wal")),
        shm_hash: file_bytes(&sidecar(db, "-shm")),
        db_meta: meta_snapshot(db),
        wal_meta: meta_snapshot(&sidecar(db, "-wal")),
        shm_meta: meta_snapshot(&sidecar(db, "-shm")),
    }
}
fn assert_unchanged(before: &DbSnapshot, db: &FsPath, ctx: &str) {
    let after = snapshot_db(db);
    assert_eq!(before.db_hash, after.db_hash, "db bytes changed: {ctx}");
    assert_eq!(before.wal_hash, after.wal_hash, "wal bytes changed: {ctx}");
    assert_eq!(before.shm_hash, after.shm_hash, "shm bytes changed: {ctx}");
    assert_eq!(before.db_meta, after.db_meta, "db metadata changed: {ctx}");
    assert_eq!(
        before.wal_meta, after.wal_meta,
        "wal metadata changed: {ctx}"
    );
    assert_eq!(
        before.shm_meta, after.shm_meta,
        "shm metadata changed: {ctx}"
    );
}
fn assert_finding(
    report: &syscall_core::verify::SessionVerificationReport,
    code: &str,
    sev: FindingSeverity,
) {
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == code && f.severity == sev),
        "expected finding {code} with severity {:?}, got {:?}",
        sev,
        report
            .findings
            .iter()
            .map(|f| (&f.code, f.severity))
            .collect::<Vec<_>>()
    );
}

fn setup_clean(db: &FsPath, sid: &str) {
    let mut storage = Storage::open(db).unwrap();
    storage.create_session(&make_session(sid)).unwrap();
    storage
        .update_session_status(sid, SessionStatus::Recording)
        .unwrap();
    storage
        .insert_events(sid, &[exec_event(sid, 42, 1_000, 100)])
        .unwrap();
    complete_clean(&mut storage, sid, 1);
}

#[test]
fn adversarial_broken_foreign_key_is_invalid_and_db_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("fk.db");
    setup_clean(&db, "sfk");
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    conn.execute("INSERT INTO events (session_id,schema_version,event_type,timestamp_ns,monotonic_ns,pid,tid,ppid,uid,gid,process_instance_id,comm,payload) VALUES ('missing_session',1,'process_exec',2000,200,1,1,1,0,0,'b:1:1','x','{}')", []).unwrap();
    drop(conn);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("sfk").unwrap();
    drop(ro);
    assert_finding(
        &report,
        "DB_FOREIGN_KEY_VIOLATION",
        FindingSeverity::Critical,
    );
    assert_eq!(report.assessment, VA::Invalid);
    assert_eq!(verify_exit_code(report.assessment), 3);
    assert_unchanged(&before, &db, "broken foreign key");
}

#[test]
fn adversarial_genuine_integrity_failure_is_invalid_and_db_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("corrupt.db");
    setup_clean(&db, "scor");
    // Create a genuine integrity-check failure by corrupting a database page.
    let mut bytes = fs::read(&db).unwrap();
    if bytes.len() > 8192 {
        for b in &mut bytes[4096..4608] {
            *b ^= 0xA5;
        }
        fs::write(&db, &bytes).unwrap();
    } else if bytes.len() > 200 {
        for b in &mut bytes[100..180] {
            *b ^= 0xA5;
        }
        fs::write(&db, &bytes).unwrap();
    }
    let before = snapshot_db(&db);
    let report_res = syscall_storage::verify::verify_session_at_path(&db, "scor");
    match report_res {
        Ok(report) => {
            assert!(report
                .findings
                .iter()
                .any(|f| f.code == "DB_INTEGRITY_CHECK_FAILED"
                    && matches!(
                        f.severity,
                        FindingSeverity::Error | FindingSeverity::Critical
                    )));
            assert_eq!(report.assessment, VA::Invalid);
            assert_eq!(verify_exit_code(report.assessment), 3);
        }
        Err(e) => {
            // If basic inspection/open is impossible, must fail clearly with categorized error and not modify DB.
            let msg = e.to_string();
            assert!(!msg.is_empty());
        }
    }
    let after = snapshot_db(&db);
    assert_eq!(before.db_hash, after.db_hash, "corrupt db bytes changed");
    assert_eq!(
        before.db_meta.as_ref().map(|m| m.0),
        after.db_meta.as_ref().map(|m| m.0),
        "corrupt db size changed"
    );
    // No pre-existing sidecars may be modified.
    if before.wal_hash.is_some() {
        assert_eq!(before.wal_hash, after.wal_hash, "pre-existing wal changed");
    }
    if before.shm_hash.is_some() {
        assert_eq!(before.shm_hash, after.shm_hash, "pre-existing shm changed");
    }
}

#[test]
fn adversarial_interrupted_starting_and_recording_sessions_are_incomplete() {
    for status in ["starting", "recording"] {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join(format!("{status}.db"));
        #[allow(unused_mut)]
        let mut storage = Storage::open(&db).unwrap();
        storage.create_session(&make_session("si")).unwrap();
        if status == "recording" {
            storage
                .update_session_status("si", SessionStatus::Recording)
                .unwrap();
        }
        drop(storage);
        let before = snapshot_db(&db);
        let ro = Storage::open_read_only(&db).unwrap();
        let report = ro.verify_session("si").unwrap();
        drop(ro);
        assert_finding(&report, "SESSION_INCOMPLETE", FindingSeverity::Warning);
        assert!(matches!(
            report.assessment,
            VA::ValidButIncomplete | VA::Warning
        ));
        assert_eq!(verify_exit_code(report.assessment), 2);
        assert_unchanged(&before, &db, status);
    }
}

#[test]
fn adversarial_nonzero_loss_counters_reported_and_db_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("loss.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("sl")).unwrap();
    storage
        .update_session_status("sl", SessionStatus::Recording)
        .unwrap();
    storage
        .insert_events("sl", &[exec_event("sl", 42, 1_000, 100)])
        .unwrap();
    storage
        .finish_session(
            "sl",
            &SessionFinish {
                ended_at_ns: 1_700_000_005_000_000_000,
                status: SessionStatus::Completed,
                dropped_events: 0,
                ringbuf_lost_events: 3,
                userspace_dropped_events: 2,
                malformed_events: 0,
                filtered_events: 0,
                error: None,
                termination_reason: Some("target_exit".to_owned()),
                target_exit_code: Some(0),
                target_exit_signal: None,
                finalized_at_ns: Some(1_700_000_005_000_000_000),
                recovered_from_status: None,
                recovered_at_ns: None,
                events_received: 1,
                events_decoded: 1,
                events_attributed: 1,
                events_persisted: 1,
                events_rejected_scope: 0,
                events_rejected_malformed: 0,
                events_persist_failed: 0,
                events_self_filtered: 0,
            },
        )
        .unwrap();
    drop(storage);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("sl").unwrap();
    drop(ro);
    assert_finding(&report, "EVIDENCE_LOSS_RINGBUF", FindingSeverity::Warning);
    assert_finding(&report, "EVIDENCE_LOSS_USERSPACE", FindingSeverity::Warning);
    assert!(matches!(
        report.assessment,
        VA::ValidButIncomplete | VA::Warning
    ));
    assert_eq!(verify_exit_code(report.assessment), 2);
    assert_unchanged(&before, &db, "loss counters");
}

#[test]
fn adversarial_invalid_status_and_timestamps_are_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("badstatus.db");
    setup_clean(&db, "sb");
    let conn = Connection::open(&db).unwrap();
    conn.execute("UPDATE sessions SET status='mystery' WHERE id='sb'", [])
        .unwrap();
    drop(conn);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("sb").unwrap();
    drop(ro);
    assert_finding(&report, "SESSION_STATUS_INVALID", FindingSeverity::Error);
    assert_eq!(report.assessment, VA::Invalid);
    assert_eq!(verify_exit_code(report.assessment), 3);
    assert_unchanged(&before, &db, "invalid status");

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("badts.db");
    setup_clean(&db, "st");
    let conn = Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE events SET timestamp_ns=-1 WHERE session_id='st'",
        [],
    )
    .unwrap();
    drop(conn);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("st").unwrap();
    drop(ro);
    assert_finding(&report, "EVENT_TIMESTAMP_INVALID", FindingSeverity::Error);
    assert_eq!(report.assessment, VA::Invalid);
    assert_eq!(verify_exit_code(report.assessment), 3);
    assert_unchanged(&before, &db, "invalid event timestamp");
}

#[test]
fn adversarial_ordering_contradiction_and_duplicate_event_identity() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("order.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("so")).unwrap();
    storage
        .update_session_status("so", SessionStatus::Recording)
        .unwrap();
    let e1 = exec_event("so", 1, 1_000, 100);
    let mut e2 = exec_event("so", 2, 2_000, 200);
    e2.process_instance_id = e1.process_instance_id.clone(); // contradictory/inconsistent identity across different pid/event row
    storage.insert_events("so", &[e1, e2]).unwrap();
    complete_clean(&mut storage, "so", 2);
    drop(storage);
    // Contradictory ordering/timeline evidence: event timestamps precede session start.
    let conn = Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE events SET timestamp_ns = 1 WHERE session_id='so'",
        [],
    )
    .unwrap();
    drop(conn);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("so").unwrap();
    drop(ro);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "EVENT_TIMESTAMP_INVALID"
            || f.code == "SESSION_EVENT_TIMESTAMP_CONTRADICTION"
            || f.code == "EVENT_PROCESS_INSTANCE_INCONSISTENT"));
    assert_eq!(report.assessment, VA::Invalid);
    assert_eq!(verify_exit_code(report.assessment), 3);
    assert_unchanged(&before, &db, "ordering/identity contradiction");
}

#[test]
fn adversarial_malformed_payload_and_invalid_wire_schema_source_type() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("badpayload.db");
    setup_clean(&db, "spay");
    let conn = Connection::open(&db).unwrap();
    conn.execute("UPDATE events SET payload='{' WHERE session_id='spay'", [])
        .unwrap();
    drop(conn);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("spay").unwrap();
    drop(ro);
    assert_finding(&report, "EVENT_PAYLOAD_INVALID", FindingSeverity::Error);
    assert_eq!(report.assessment, VA::Invalid);
    assert_eq!(verify_exit_code(report.assessment), 3);
    assert_unchanged(&before, &db, "malformed payload");

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("badprov.db");
    setup_clean(&db, "sp");
    let conn = Connection::open(&db).unwrap();
    conn.execute("UPDATE events SET source_tracepoint='sched/sched_process_fork', wire_schema_version=99, event_type='not_a_type' WHERE session_id='sp'", []).unwrap();
    drop(conn);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("sp").unwrap();
    drop(ro);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "EVENT_WIRE_SCHEMA_INVALID"));
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "EVENT_TYPE_INVALID"));
    assert_eq!(report.assessment, VA::Invalid);
    assert_eq!(verify_exit_code(report.assessment), 3);
    assert_unchanged(&before, &db, "invalid provenance/type");

    // source tracepoint contradiction for a valid event type
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("badtp.db");
    setup_clean(&db, "stp");
    let conn = Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE events SET source_tracepoint='sched/sched_process_fork' WHERE session_id='stp'",
        [],
    )
    .unwrap();
    drop(conn);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("stp").unwrap();
    drop(ro);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "EVENT_SOURCE_TRACEPOINT_INCONSISTENT"));
    assert_eq!(report.assessment, VA::Invalid);
    assert_eq!(verify_exit_code(report.assessment), 3);
    assert_unchanged(&before, &db, "invalid source tracepoint");
}

#[test]
fn adversarial_unresolved_fork_identity_not_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("fork.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("sf")).unwrap();
    storage
        .update_session_status("sf", SessionStatus::Recording)
        .unwrap();
    let mut ev = exec_event("sf", 42, 1_000, 100);
    ev.event_type = EventType::ProcessFork;
    ev.provenance = Some(EventProvenance {
        raw_bpf_pid: Some(7),
        raw_bpf_tgid: None,
        observer_pid: None,
        observer_tgid: None,
        source_tracepoint: Some("sched/sched_process_fork".to_owned()),
        wire_schema_version: Some(2),
        attribution_method: Some("unresolved_fork".to_owned()),
        timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
        monotonic_clock_domain: Some("monotonic_boot_raw".to_owned()),
    });
    ev.payload = EventPayload::ProcessFork {
        child_pid: 99,
        child_start_time_ticks: None,
        parent_pid: 42,
        parent_tgid: Some(42),
        child_comm: "child".to_owned(),
    };
    storage.insert_events("sf", &[ev]).unwrap();
    complete_clean(&mut storage, "sf", 1);
    drop(storage);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("sf").unwrap();
    drop(ro);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "FORK_IDENTITY_UNRESOLVED" || f.code == "PROVENANCE_UNAVAILABLE"));
    assert_ne!(report.assessment, VA::Invalid);
    assert_eq!(verify_exit_code(report.assessment), 2);
    assert_unchanged(&before, &db, "unresolved fork");
}

#[test]
fn unsupported_schema_readable_yields_unable_to_verify_report() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("future.db");
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch("PRAGMA user_version = 999; CREATE TABLE sessions(id TEXT PRIMARY KEY); CREATE TABLE events(id INTEGER PRIMARY KEY, session_id TEXT);").unwrap();
    drop(conn);
    let before = snapshot_db(&db);
    let report = syscall_storage::verify::verify_session_at_path(&db, "any").unwrap();
    assert_finding(&report, "DB_SCHEMA_UNSUPPORTED", FindingSeverity::Error);
    assert_eq!(report.assessment, VA::UnableToVerify);
    assert_eq!(verify_exit_code(report.assessment), 4);
    assert_eq!(report.database_schema_version, 999);
    assert_unchanged(&before, &db, "unsupported schema");
}

#[test]
fn large_session_bounded_scan_reports_without_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("large.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&make_session("slg")).unwrap();
    storage
        .update_session_status("slg", SessionStatus::Recording)
        .unwrap();
    let mut events = Vec::new();
    for i in 0..2500i64 {
        events.push(exec_event("slg", 42, 1_000 + i, (100 + i) as u64));
        if events.len() == 500 {
            storage.insert_events("slg", &events).unwrap();
            events.clear();
        }
    }
    if !events.is_empty() {
        storage.insert_events("slg", &events).unwrap();
    }
    complete_clean(&mut storage, "slg", 2500);
    drop(storage);
    let before = snapshot_db(&db);
    let ro = Storage::open_read_only(&db).unwrap();
    let report = ro.verify_session("slg").unwrap();
    drop(ro);
    assert_ne!(report.assessment, VA::Invalid);
    assert_eq!(report.severity_counts.critical, 0);
    assert!(report
        .findings
        .iter()
        .all(|f| f.code != "DB_INTEGRITY_CHECK_FAILED"));
    // If findings are bounded/truncated that must be explicit, but absence of corruption is required.
    assert_unchanged(&before, &db, "large session");
}

#[test]
fn verification_in_read_only_directory_when_permitted() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("rod.db");
    setup_clean(&db, "srod");
    // make directory read-only; SQLite may still need sidecars in some modes, but rollback journal DB should be verifiable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let before = snapshot_db(&db);
        let res = syscall_storage::verify::verify_session_at_path(&db, "srod");
        // restore perms for cleanup
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        match res {
            Ok(report) => {
                assert_ne!(report.assessment, VA::Invalid);
                assert_unchanged(&before, &db, "ro dir");
            }
            Err(e) => {
                // must fail clearly if required sidecars cannot be created/read; no writes occurred
                let msg = e.to_string();
                assert!(!msg.is_empty(), "clear structured failure required");
                assert_unchanged(&before, &db, "ro dir failure");
            }
        }
    }
}
