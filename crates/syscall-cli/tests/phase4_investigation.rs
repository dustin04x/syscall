use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};
use syscall_core::{
    Event, EventPayload, EventProvenance, EventType, ProcessMetadata, RecordingScope,
    SCHEMA_VERSION,
};
use syscall_storage::{
    EventQuery, NewSession, SessionFinish, SessionStatus, Storage, TimelineFilter,
};
use tempfile::TempDir;

fn new_session(id: &str, redact_args: bool) -> NewSession {
    NewSession {
        id: id.to_owned(),
        schema_version: SCHEMA_VERSION,
        started_at_ns: 1_700_000_000_000_000_000,
        command: "/usr/bin/target".to_owned(),
        arguments: if redact_args {
            vec!["<redacted>".to_owned()]
        } else {
            vec!["--flag".to_owned(), "secretish".to_owned()]
        },
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
    id_pid: i32,
    inst: &str,
    ts: i64,
    mono: u64,
    et: EventType,
    comm: &str,
    ppid: Option<i32>,
    payload: EventPayload,
) -> Event {
    Event {
        id: None,
        session_id: session.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type: et,
        timestamp_ns: ts,
        monotonic_ns: mono,
        pid: id_pid,
        tid: id_pid,
        uid: 1000,
        gid: 1000,
        ppid,
        comm: comm.to_owned(),
        process_instance_id: inst.to_owned(),
        payload,
        provenance: Some(EventProvenance {
            raw_bpf_pid: Some(id_pid),
            raw_bpf_tgid: Some(id_pid),
            observer_pid: Some(id_pid),
            observer_tgid: Some(id_pid),
            source_tracepoint: Some(match et {
                EventType::ProcessExec => "sched/sched_process_exec".to_owned(),
                EventType::ProcessFork => "sched/sched_process_fork".to_owned(),
                EventType::ProcessExit => "sched/sched_process_exit".to_owned(),
                _ => "unknown".to_owned(),
            }),
            wire_schema_version: Some(2),
            attribution_method: Some("observed".to_owned()),
            timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
            monotonic_clock_domain: Some("monotonic_boot".to_owned()),
        }),
    }
}

fn exec_ev(
    session: &str,
    pid: i32,
    inst: &str,
    ts: i64,
    mono: u64,
    filename: &str,
    ppid: Option<i32>,
) -> Event {
    base_event(
        session,
        pid,
        inst,
        ts,
        mono,
        EventType::ProcessExec,
        "proc",
        ppid,
        EventPayload::ProcessExec {
            filename: filename.to_owned(),
            process: ProcessMetadata {
                ppid,
                start_time_ticks: Some(100),
            },
            old_pid: None,
        },
    )
}
#[allow(clippy::too_many_arguments)]
fn fork_ev(
    session: &str,
    parent_pid: i32,
    child_pid: i32,
    child_inst: &str,
    ts: i64,
    mono: u64,
    child_comm: &str,
    child_start: Option<u64>,
) -> Event {
    base_event(
        session,
        child_pid,
        child_inst,
        ts,
        mono,
        EventType::ProcessFork,
        child_comm,
        Some(parent_pid),
        EventPayload::ProcessFork {
            parent_pid,
            parent_tgid: Some(parent_pid),
            child_pid,
            child_comm: child_comm.to_owned(),
            child_start_time_ticks: child_start,
        },
    )
}
fn exit_ev(session: &str, pid: i32, inst: &str, ts: i64, mono: u64, ppid: Option<i32>) -> Event {
    base_event(
        session,
        pid,
        inst,
        ts,
        mono,
        EventType::ProcessExit,
        "proc",
        ppid,
        EventPayload::ProcessExit {
            process: ProcessMetadata {
                ppid,
                start_time_ticks: Some(100),
            },
            exit_priority: 120,
        },
    )
}

fn file_hashes(path: &Path) -> (Vec<u8>, u64) {
    let bytes = fs::read(path).unwrap();
    let meta = fs::metadata(path).unwrap();
    (bytes, meta.len())
}

#[test]
fn process_listing_and_tree_basic_with_json() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("t.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s1", false)).unwrap();
    // root exec, fork child, child exec/exit, root exit
    let root = "boot:100:1";
    let child = "boot:101:2";
    let events = vec![
        exec_ev("s1", 100, root, 1000, 10, "/usr/bin/target", Some(1)),
        fork_ev("s1", 100, 101, child, 2000, 20, "child", Some(2)),
        exec_ev("s1", 101, child, 3000, 30, "/bin/child", Some(100)),
        exit_ev("s1", 101, child, 4000, 40, Some(100)),
        exit_ev("s1", 100, root, 5000, 50, Some(1)),
    ];
    storage.insert_events("s1", &events).unwrap();
    complete(&mut storage, "s1", 5);
    drop(storage);
    let storage = Storage::open_read_only(&db).unwrap();
    let procs = storage.list_process_instances("s1").unwrap();
    assert_eq!(procs.len(), 2);
    assert!(procs
        .iter()
        .any(|p| p.pid == 100 && p.executable.as_deref() == Some("/usr/bin/target")));
    assert!(procs.iter().any(|p| p.pid == 101 && p.exit_observed));
    let child_p = procs
        .iter()
        .find(|p| p.process_instance_id == child)
        .unwrap();
    assert_eq!(child_p.parent_pid, Some(100));
    assert_eq!(child_p.parent_process_instance_id.as_deref(), Some(root));

    let session = storage.get_session("s1").unwrap().unwrap();
    let text = syscall_cli::render::render_processes("s1", &procs, &session);
    assert!(text.contains("PROCESS INSTANCE"));
    assert!(text.contains(child));
    let json = syscall_cli::render::render_processes_json("s1", &procs, &session).unwrap();
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["process_instances"].as_array().unwrap().len(), 2);

    let tree_text = syscall_cli::render::render_tree("s1", &procs);
    assert!(tree_text.contains("pid=100"));
    assert!(tree_text.contains("pid=101"));
    let tree_json = syscall_cli::render::render_tree_json("s1", &procs).unwrap();
    let tv: Value = serde_json::from_str(&tree_json).unwrap();
    assert!(tv["tree"].is_array());
}

#[test]
fn pid_reuse_missing_parent_unresolved_fork_and_cycle_prevention() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("t.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s2", false)).unwrap();
    let inst_a = "boot:200:10"; // earlier
    let inst_b = "boot:200:20"; // reuse
    let child1 = "boot:201:11";
    let child_unresolved = "boot:202:unknown-999";
    let orphan = "boot:300:30"; // claims parent pid not present
    let cyc1 = "boot:400:40";
    let cyc2 = "boot:401:41";
    let events = vec![
        exec_ev("s2", 200, inst_a, 1000, 10, "/bin/a", Some(1)),
        exit_ev("s2", 200, inst_a, 1500, 15, Some(1)),
        exec_ev("s2", 200, inst_b, 2000, 20, "/bin/b", Some(1)), // pid reused
        fork_ev("s2", 200, 201, child1, 2500, 25, "c1", Some(11)),
        fork_ev("s2", 200, 202, child_unresolved, 2600, 26, "cu", None),
        exec_ev("s2", 300, orphan, 3000, 30, "/bin/orphan", Some(9999)),
        fork_ev("s2", 401, 400, cyc1, 4000, 40, "cy1", Some(40)),
        fork_ev("s2", 400, 401, cyc2, 4100, 41, "cy2", Some(41)),
    ];
    storage.insert_events("s2", &events).unwrap();
    complete(&mut storage, "s2", events.len() as u64);
    drop(storage);
    let storage = Storage::open_read_only(&db).unwrap();
    let procs = storage.list_process_instances("s2").unwrap();
    let c1 = procs
        .iter()
        .find(|p| p.process_instance_id == child1)
        .unwrap();
    assert_eq!(c1.parent_pid, Some(200));
    // The earlier pid-200 instance exited before the fork; the later one was
    // alive when the fork was observed, so ancestry resolves to it.
    assert_eq!(c1.parent_process_instance_id.as_deref(), Some(inst_b));
    assert!(!c1.ancestry_unresolved);
    let cu = procs
        .iter()
        .find(|p| p.process_instance_id == child_unresolved)
        .unwrap();
    assert!(cu.identity_unresolved);
    assert!(cu.ancestry_unresolved);
    let o = procs
        .iter()
        .find(|p| p.process_instance_id == orphan)
        .unwrap();
    assert_eq!(o.parent_pid, Some(9999));
    assert!(o.parent_process_instance_id.is_none());
    assert!(o.ancestry_unresolved);
    let tree = syscall_cli::render::render_tree("s2", &procs);
    assert!(tree.contains("pid=400"));
    assert!(tree.contains("pid=401"));
    assert!(
        tree.contains("[CYCLE]") || tree.contains("cycle detected"),
        "cycle must be handled explicitly: {tree}"
    );
    let tree_json = syscall_cli::render::render_tree_json("s2", &procs).unwrap();
    let tv: Value = serde_json::from_str(&tree_json).unwrap();
    let s = tv.to_string();
    assert!(s.contains("cycle") || s.contains("CYCLE"));
}

#[test]
fn timeline_ordering_filters_pagination_and_json() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("t.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s3", false)).unwrap();
    let a = "boot:1:1";
    let b = "boot:2:2";
    let events = vec![
        exec_ev("s3", 1, a, 1000, 10, "/bin/a", Some(0)),
        exec_ev("s3", 2, b, 1000, 20, "/bin/b", Some(0)),
        fork_ev("s3", 1, 3, "boot:3:3", 2000, 30, "c", Some(3)),
        exit_ev("s3", 2, b, 3000, 40, Some(0)),
    ];
    storage.insert_events("s3", &events).unwrap();
    complete(&mut storage, "s3", 4);
    drop(storage);
    let storage = Storage::open_read_only(&db).unwrap();

    let mut f = TimelineFilter::new("s3");
    f.limit = Some(2);
    f.offset = 0;
    let page1 = storage.query_timeline(&f).unwrap();
    assert_eq!(page1.len(), 2);
    assert!(page1[0].timestamp_ns <= page1[1].timestamp_ns);
    f.offset = 2;
    let page2 = storage.query_timeline(&f).unwrap();
    assert_eq!(page2.len(), 2);

    let mut f = TimelineFilter::new("s3");
    f.event_type = Some(EventType::ProcessExec);
    let execs = storage.query_timeline(&f).unwrap();
    assert_eq!(execs.len(), 2);
    assert!(execs.iter().all(|e| e.event_type == EventType::ProcessExec));

    let mut f = TimelineFilter::new("s3");
    f.pid = Some(2);
    let pid2 = storage.query_timeline(&f).unwrap();
    assert!(pid2.iter().all(|e| e.pid == 2));

    let mut f = TimelineFilter::new("s3");
    f.process_instance_id = Some(b.to_owned());
    let inst = storage.query_timeline(&f).unwrap();
    assert!(inst.iter().all(|e| e.process_instance_id == b));

    let mut f = TimelineFilter::new("s3");
    f.from_ns = Some(1500);
    f.to_ns = Some(2500);
    let range = storage.query_timeline(&f).unwrap();
    assert!(range
        .iter()
        .all(|e| e.timestamp_ns >= 1500 && e.timestamp_ns <= 2500));

    let total = storage.count_timeline(&TimelineFilter::new("s3")).unwrap();
    assert_eq!(total, 4);
    let json = syscall_cli::render::render_timeline_json(
        &page1,
        "s3",
        &TimelineFilter::new("s3"),
        Some(total),
    )
    .unwrap();
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["ordering"], "timestamp_ns ASC, monotonic_ns ASC, id ASC");
    assert_eq!(v["matched_total"], 4);
}

#[test]
fn stats_reports_counters_losses_termination_and_unresolved() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("t.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s4", false)).unwrap();
    let events = vec![
        exec_ev("s4", 1, "boot:1:unknown-1", 1000, 10, "/bin/a", Some(0)),
        fork_ev("s4", 1, 2, "boot:2:2", 2000, 20, "b", Some(2)),
    ];
    storage.insert_events("s4", &events).unwrap();
    storage
        .update_session_status("s4", SessionStatus::Recording)
        .unwrap();
    storage
        .finish_session(
            "s4",
            &SessionFinish {
                ended_at_ns: 5_000,
                status: SessionStatus::Completed,
                dropped_events: 3,
                ringbuf_lost_events: 2,
                userspace_dropped_events: 1,
                malformed_events: 1,
                filtered_events: 4,
                error: None,
                termination_reason: Some("target_exit".to_owned()),
                target_exit_code: Some(0),
                target_exit_signal: None,
                recovered_from_status: None,
                recovered_at_ns: None,
                finalized_at_ns: Some(5_000),
                events_received: 10,
                events_decoded: 9,
                events_attributed: 6,
                events_persisted: 2,
                events_rejected_scope: 4,
                events_rejected_malformed: 1,
                events_persist_failed: 0,
                events_self_filtered: 0,
            },
        )
        .unwrap();
    drop(storage);
    let storage = Storage::open_read_only(&db).unwrap();
    let stats = storage.session_stats("s4").unwrap().unwrap();
    assert_eq!(stats.ringbuf_lost_events, 2);
    assert_eq!(stats.userspace_dropped_events, 1);
    assert_eq!(stats.unresolved_identity_count, 1);
    assert!(stats.evidence_may_be_incomplete);
    assert_eq!(stats.termination_reason.as_deref(), Some("target_exit"));
    let text = syscall_cli::render::render_stats(&stats, None);
    assert!(text.contains("Evidence may be incomplete"));
    let json = syscall_cli::render::render_stats_json(&stats, None).unwrap();
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["stats"]["ringbuf_lost_events"], 2);
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn export_is_deterministic_has_manifest_db_unchanged_and_atomic_protections() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("t.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s5", true)).unwrap();
    let events = vec![
        exec_ev("s5", 1, "boot:1:1", 1000, 10, "/bin/a", Some(0)),
        exit_ev("s5", 1, "boot:1:1", 2000, 20, Some(0)),
    ];
    storage.insert_events("s5", &events).unwrap();
    complete(&mut storage, "s5", 2);
    drop(storage);

    let (db_before, db_len_before) = file_hashes(&db);
    let storage = Storage::open_read_only(&db).unwrap();
    let out1 = dir.path().join("e1.json");
    let r1 = syscall_cli::export::export_json(
        &storage,
        syscall_cli::export::ExportRequest {
            session_id: "s5".to_owned(),
            output: out1.clone(),
            force: false,
            database_path: db.clone(),
        },
    )
    .unwrap();
    let bytes1 = fs::read(&out1).unwrap();
    let out2 = dir.path().join("e2.json");
    let r2 = syscall_cli::export::export_json(
        &storage,
        syscall_cli::export::ExportRequest {
            session_id: "s5".to_owned(),
            output: out2.clone(),
            force: false,
            database_path: db.clone(),
        },
    )
    .unwrap();
    let bytes2 = fs::read(&out2).unwrap();
    let v1: Value = serde_json::from_slice(&bytes1).unwrap();
    let v2: Value = serde_json::from_slice(&bytes2).unwrap();
    for comp in ["session", "process_instances", "events", "verification"] {
        assert_eq!(
            v1[comp], v2[comp],
            "evidence component {comp} must be deterministic"
        );
        let b = serde_json::to_string_pretty(&v1[comp]).unwrap() + "\n";
        let h = sha256_hex(b.as_bytes());
        let entry = v1["manifest"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["component"] == comp)
            .unwrap();
        assert_eq!(
            entry["sha256"], h,
            "manifest hash must match component bytes for {comp}"
        );
        assert_eq!(entry["byte_length"], b.len());
    }
    // manifest integrity semantics: components are hashed, but the manifest is not self-hashed
    assert!(v1["manifest"]["hash_algorithm"] == "sha256");
    assert!(!v1["manifest"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["component"] == "manifest"));
    assert!(v1["manifest"]["note"]
        .as_str()
        .unwrap_or("")
        .contains("post-export integrity checking"));
    let verification = syscall_cli::export::verify_export_json(&out1).unwrap();
    assert!(verification.valid, "export must verify: {verification:?}");
    assert!(verification
        .components
        .iter()
        .all(|component| component.component != "manifest"));

    let mut tampered = v1.clone();
    tampered["session"]["command"] = Value::String("/bin/tampered".to_owned());
    let tampered_path = dir.path().join("tampered.json");
    fs::write(
        &tampered_path,
        serde_json::to_string_pretty(&tampered).unwrap() + "\n",
    )
    .unwrap();
    let tampered_verification = syscall_cli::export::verify_export_json(&tampered_path).unwrap();
    assert!(!tampered_verification.valid);
    assert!(tampered_verification
        .errors
        .iter()
        .any(|error| error.contains("session")));

    let args = v1["session"]["arguments"].as_array().unwrap();
    assert!(args.iter().any(|a| a == "<redacted>"));
    assert!(!v1.to_string().contains("secretish"));

    let mode = fs::metadata(&out1).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let err = syscall_cli::export::export_json(
        &storage,
        syscall_cli::export::ExportRequest {
            session_id: "s5".to_owned(),
            output: out1.clone(),
            force: false,
            database_path: db.clone(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("already exists"));

    syscall_cli::export::export_json(
        &storage,
        syscall_cli::export::ExportRequest {
            session_id: "s5".to_owned(),
            output: out1.clone(),
            force: true,
            database_path: db.clone(),
        },
    )
    .unwrap();

    drop(storage);
    let (db_after, db_len_after) = file_hashes(&db);
    assert_eq!(db_before, db_after);
    assert_eq!(db_len_before, db_len_after);

    assert_eq!(
        r1.format_version,
        syscall_cli::export::EXPORT_FORMAT_VERSION
    );
    assert!(r2.bytes_written > 0);
    let _ = bytes2;
}

#[test]
fn export_handles_legacy_unavailable_provenance_and_preserves_verification_outcome() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("t.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s6", false)).unwrap();
    let mut e = exec_ev("s6", 1, "boot:1:1", 1000, 10, "/bin/a", Some(0));
    e.provenance = None; // legacy/unavailable
    storage.insert_events("s6", &[e]).unwrap();
    // leave counters/loss to show honest accounting if present
    storage
        .update_session_status("s6", SessionStatus::Recording)
        .unwrap();
    storage
        .finish_session(
            "s6",
            &SessionFinish {
                ended_at_ns: 2_000,
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
                finalized_at_ns: Some(2_000),
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
    let storage = Storage::open_read_only(&db).unwrap();
    let out = dir.path().join("e.json");
    syscall_cli::export::export_json(
        &storage,
        syscall_cli::export::ExportRequest {
            session_id: "s6".to_owned(),
            output: out.clone(),
            force: false,
            database_path: db.clone(),
        },
    )
    .unwrap();
    let v: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert!(v["events"][0]["provenance"].is_null());
    let lims = v["metadata"]["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap_or("").to_string())
        .collect::<Vec<_>>();
    assert!(
        lims.iter().any(|l| l.to_lowercase().contains("provenance")
            && (l.to_lowercase().contains("legacy") || l.to_lowercase().contains("unavailable"))),
        "limitations must mention legacy/unavailable provenance: {lims:?}"
    );
    // verification included and outcome preserved (not silently treated as unreported)
    assert!(v.get("verification").is_some());
    assert!(v["verification"]["assessment"].is_string() || v["verification"]["status"].is_string());
}

#[test]
fn terminal_escape_sanitization_in_text_outputs_and_json_valid() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("t.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s7", false)).unwrap();
    let mut e = exec_ev(
        "s7",
        1,
        "boot:1:1",
        1000,
        10,
        "/bin/\x1b[31mevil\x07",
        Some(0),
    );
    e.comm = "e\x1bvil".to_owned();
    storage.insert_events("s7", &[e]).unwrap();
    complete(&mut storage, "s7", 1);
    drop(storage);
    let storage = Storage::open_read_only(&db).unwrap();
    let procs = storage.list_process_instances("s7").unwrap();
    let session = storage.get_session("s7").unwrap().unwrap();
    let text = syscall_cli::render::render_processes("s7", &procs, &session);
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains('\u{07}'));
    let events = storage.query_events(&EventQuery::new("s7")).unwrap();
    let t2 = syscall_cli::render::render_timeline(&events, "s7", 0, 10, Some(1));
    assert!(!t2.contains('\u{1b}'));
    let j = syscall_cli::render::render_timeline_json(
        &events,
        "s7",
        &TimelineFilter::new("s7"),
        Some(1),
    )
    .unwrap();
    let _: Value = serde_json::from_str(&j).unwrap();
}

#[test]
fn export_failure_handling_does_not_clobber_target() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("t.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s8", false)).unwrap();
    storage
        .insert_events(
            "s8",
            &[exec_ev("s8", 1, "boot:1:1", 1000, 10, "/bin/a", Some(0))],
        )
        .unwrap();
    complete(&mut storage, "s8", 1);
    drop(storage);
    let storage = Storage::open_read_only(&db).unwrap();
    let bad = dir.path().join("missing").join("out.json");
    let err = syscall_cli::export::export_json(
        &storage,
        syscall_cli::export::ExportRequest {
            session_id: "s8".to_owned(),
            output: bad,
            force: false,
            database_path: db,
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("directory")
            || err.to_string().contains("failed")
            || err.to_string().contains("No such file")
    );
}
