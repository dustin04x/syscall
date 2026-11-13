use clap::Parser;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use syscall_cli::cli::{Cli, Command, ResultFilter};
use syscall_core::{
    AddressFamily, Event, EventPayload, EventProvenance, EventType, RecordingScope, SCHEMA_VERSION,
};
use syscall_storage::{ActivityFilter, NewSession, SessionFinish, SessionStatus, Storage};
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

fn event(
    session: &str,
    pid: i32,
    event_type: EventType,
    payload: EventPayload,
    tracepoint: &str,
    timestamp_ns: i64,
) -> Event {
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
        comm: "target".to_owned(),
        process_instance_id: format!("boot:{pid}:1"),
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

#[test]
fn files_and_connections_render_text_and_json() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("activity.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s-render")).unwrap();
    let events = vec![
        event(
            "s-render",
            10,
            EventType::FileOpen,
            EventPayload::FileOpen {
                path: "/etc/\u{1b}[31mpasswd".to_owned(),
                path_is_absolute: true,
                path_truncated: false,
                dirfd: -100,
                flags: 0,
                result: 5,
                success: true,
                errno: None,
            },
            "syscalls/sys_exit_openat",
            1000,
        ),
        event(
            "s-render",
            10,
            EventType::NetworkConnect,
            EventPayload::NetworkConnect {
                family: AddressFamily::Ipv4,
                source_address: None,
                source_port: None,
                destination_address: "93.184.216.34".to_owned(),
                destination_port: 443,
                result: 0,
                success: true,
                errno: None,
                established: false,
            },
            "syscalls/sys_exit_connect",
            2000,
        ),
    ];
    storage.insert_events("s-render", &events).unwrap();
    complete(&mut storage, "s-render", 2);
    drop(storage);

    let storage = Storage::open_read_only(&db).unwrap();
    let files = storage
        .query_file_activity(&ActivityFilter::new("s-render"))
        .unwrap();
    let text = syscall_cli::render::render_files("s-render", &files, 1);
    assert!(text.contains("/etc/"));
    assert!(
        !text.contains('\u{1b}'),
        "terminal escape must be sanitized"
    );
    let json = syscall_cli::render::render_files_json("s-render", &files, 1).unwrap();
    let value: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["matched_total"], 1);
    assert_eq!(value["file_opens"][0]["path"], "/etc/\u{1b}[31mpasswd");

    let connections = storage
        .query_connection_activity(&ActivityFilter::new("s-render"))
        .unwrap();
    let text = syscall_cli::render::render_connections("s-render", &connections, 1);
    assert!(text.contains("93.184.216.34:443"));
    let json = syscall_cli::render::render_connections_json("s-render", &connections, 1).unwrap();
    let value: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["connections"][0]["destination_port"], 443);
    assert_eq!(value["connections"][0]["established"], false);
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn export_includes_activity_events_with_stable_manifest_hash() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("export.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&new_session("s-export")).unwrap();
    let events = vec![
        event(
            "s-export",
            10,
            EventType::FileOpen,
            EventPayload::FileOpen {
                path: "/etc/hostname".to_owned(),
                path_is_absolute: true,
                path_truncated: false,
                dirfd: -100,
                flags: 0,
                result: 5,
                success: true,
                errno: None,
            },
            "syscalls/sys_exit_openat",
            1000,
        ),
        event(
            "s-export",
            10,
            EventType::NetworkConnect,
            EventPayload::NetworkConnect {
                family: AddressFamily::Ipv6,
                source_address: None,
                source_port: None,
                destination_address: "2001:db8::1".to_owned(),
                destination_port: 443,
                result: -111,
                success: false,
                errno: Some(111),
                established: false,
            },
            "syscalls/sys_exit_connect",
            2000,
        ),
    ];
    storage.insert_events("s-export", &events).unwrap();
    complete(&mut storage, "s-export", 2);
    drop(storage);

    let storage = Storage::open_read_only(&db).unwrap();
    let out1 = dir.path().join("e1.json");
    let out2 = dir.path().join("e2.json");
    for output in [&out1, &out2] {
        syscall_cli::export::export_json(
            &storage,
            syscall_cli::export::ExportRequest {
                session_id: "s-export".to_owned(),
                output: output.clone(),
                force: false,
                database_path: db.clone(),
            },
        )
        .unwrap();
    }
    let v1: Value = serde_json::from_slice(&fs::read(&out1).unwrap()).unwrap();
    let v2: Value = serde_json::from_slice(&fs::read(&out2).unwrap()).unwrap();
    assert_eq!(
        v1["events"], v2["events"],
        "exported events must be deterministic"
    );
    assert_eq!(
        v1["analysis"], v2["analysis"],
        "exported analysis must be deterministic"
    );
    assert_eq!(v1["analysis"]["schema_version"], "syscall-analysis/v1");
    assert!(v1["analysis"]["findings"].is_array());
    let analysis_bytes = serde_json::to_string_pretty(&v1["analysis"]).unwrap() + "\n";
    let analysis_entry = v1["manifest"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["component"] == "analysis")
        .expect("analysis component must be in the manifest");
    assert_eq!(
        analysis_entry["sha256"],
        sha256_hex(analysis_bytes.as_bytes())
    );
    assert_eq!(analysis_entry["version"], "syscall-analysis/v1");
    let exported = v1["events"].as_array().unwrap();
    assert_eq!(exported.len(), 2);
    let kinds: Vec<&str> = exported
        .iter()
        .map(|event| event["event_type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["file_open", "network_connect"]);
    assert_eq!(exported[0]["payload"]["path"], "/etc/hostname");
    assert_eq!(exported[1]["payload"]["destination_address"], "2001:db8::1");
    assert_eq!(exported[1]["payload"]["established"], false);

    let bytes = serde_json::to_string_pretty(&v1["events"]).unwrap() + "\n";
    let expected = sha256_hex(bytes.as_bytes());
    let entry = v1["manifest"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["component"] == "events")
        .unwrap();
    assert_eq!(entry["sha256"], expected);
    assert_eq!(entry["byte_length"], bytes.len());
}

#[test]
fn cli_parses_activity_filters() {
    let cli = Cli::try_parse_from([
        "syscall", "files", "s1", "--pid", "10", "--result", "failure", "--limit", "5",
    ])
    .unwrap();
    match cli.command {
        Command::Files {
            pid, result, limit, ..
        } => {
            assert_eq!(pid, Some(10));
            assert_eq!(result, Some(ResultFilter::Failure));
            assert_eq!(limit, 5);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "syscall",
        "connections",
        "s1",
        "--family",
        "ipv6",
        "--result",
        "success",
    ])
    .unwrap();
    match cli.command {
        Command::Connections { family, result, .. } => {
            assert_eq!(family, Some(AddressFamily::Ipv6));
            assert_eq!(result, Some(ResultFilter::Success));
        }
        other => panic!("unexpected command: {other:?}"),
    }

    assert!(Cli::try_parse_from(["syscall", "connections", "s1", "--family", "unix"]).is_err());
}
