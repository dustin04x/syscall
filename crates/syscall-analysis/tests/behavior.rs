//! End-to-end rule tests against real temporary SQLite databases.

use syscall_analysis::{
    analyze, AnalysisConfig, AnalysisOptions, RULE_FS_NET_CORRELATION, RULE_REPEATED_CONNECT,
    RULE_SENSITIVE_OPEN, RULE_SHELL_CHAIN, RULE_SHORT_LIVED_NET, RULE_TEMP_EXEC,
};
use syscall_core::{
    AddressFamily, AnalysisConfidence, AnalysisSeverity, Event, EventPayload, EventProvenance,
    EventType, ProcessMetadata, RecordingScope, SCHEMA_VERSION,
};
use syscall_storage::{NewSession, SessionFinish, SessionStatus, Storage};
use tempfile::TempDir;

fn session(id: &str) -> NewSession {
    NewSession {
        id: id.to_owned(),
        schema_version: SCHEMA_VERSION,
        started_at_ns: 1_700_000_000_000_000_000,
        command: "/bin/bash".to_owned(),
        arguments: vec![],
        recording_scope: RecordingScope::TargetTree,
        boot_id: Some("boot".to_owned()),
        kernel_release: Some("6.6.0".to_owned()),
        collector_version: Some("0.1.0".to_owned()),
    }
}

fn finish(storage: &mut Storage, id: &str, persisted: u64, lost: u64) {
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
                ringbuf_lost_events: lost,
                userspace_dropped_events: 0,
                malformed_events: 0,
                filtered_events: 0,
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
    session_id: &str,
    pid: i32,
    instance: &str,
    timestamp_ns: i64,
    event_type: EventType,
    comm: &str,
    ppid: Option<i32>,
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
        session_id: session_id.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type,
        timestamp_ns,
        monotonic_ns: u64::try_from(timestamp_ns).unwrap_or(0),
        pid,
        tid: pid,
        uid: 1000,
        gid: 1000,
        ppid,
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
            attribution_method: Some(if tracepoint.starts_with("syscalls/") {
                "syscall_pair_attributed".to_owned()
            } else {
                "observed".to_owned()
            }),
            timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
            monotonic_clock_domain: Some("monotonic_boot_raw".to_owned()),
        }),
    }
}

fn exec(
    session_id: &str,
    pid: i32,
    instance: &str,
    ts: i64,
    filename: &str,
    comm: &str,
    ppid: Option<i32>,
) -> Event {
    base_event(
        session_id,
        pid,
        instance,
        ts,
        EventType::ProcessExec,
        comm,
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
fn fork(
    session_id: &str,
    parent_pid: i32,
    child_pid: i32,
    child_instance: &str,
    ts: i64,
    child_comm: &str,
) -> Event {
    base_event(
        session_id,
        child_pid,
        child_instance,
        ts,
        EventType::ProcessFork,
        child_comm,
        Some(parent_pid),
        EventPayload::ProcessFork {
            parent_pid,
            parent_tgid: Some(parent_pid),
            child_pid,
            child_comm: child_comm.to_owned(),
            child_start_time_ticks: Some(200),
        },
    )
}

fn exit(
    session_id: &str,
    pid: i32,
    instance: &str,
    ts: i64,
    comm: &str,
    ppid: Option<i32>,
) -> Event {
    base_event(
        session_id,
        pid,
        instance,
        ts,
        EventType::ProcessExit,
        comm,
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

fn open(
    session_id: &str,
    pid: i32,
    instance: &str,
    ts: i64,
    path: &str,
    absolute: bool,
    success: bool,
) -> Event {
    base_event(
        session_id,
        pid,
        instance,
        ts,
        EventType::FileOpen,
        "target",
        Some(1),
        EventPayload::FileOpen {
            path: path.to_owned(),
            path_is_absolute: absolute,
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
    session_id: &str,
    pid: i32,
    instance: &str,
    ts: i64,
    destination: &str,
    port: u16,
    success: bool,
) -> Event {
    base_event(
        session_id,
        pid,
        instance,
        ts,
        EventType::NetworkConnect,
        "target",
        Some(1),
        EventPayload::NetworkConnect {
            family: AddressFamily::Ipv4,
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

fn run(
    id: &str,
    events: Vec<Event>,
    lost: u64,
    rule: Option<&str>,
    config: AnalysisConfig,
) -> syscall_core::AnalysisReport {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("analysis.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&session(id)).unwrap();
    let count = events.len() as u64;
    storage.insert_events(id, &events).unwrap();
    finish(&mut storage, id, count, lost);
    analyze(
        &storage,
        id,
        AnalysisOptions {
            config,
            rule: rule.map(str::to_owned),
            min_severity: None,
            min_confidence: None,
        },
    )
    .unwrap()
}

fn shell_chain_events(id: &str) -> Vec<Event> {
    let root = "boot:100:1";
    let child = "boot:101:2";
    let grandchild = "boot:102:3";
    vec![
        exec(id, 100, root, 1_000, "/bin/bash", "bash", Some(1)),
        fork(id, 100, 101, child, 1_100, "make"),
        exec(id, 101, child, 1_200, "/usr/bin/make", "make", Some(100)),
        fork(id, 101, 102, grandchild, 1_300, "sh"),
        exec(id, 102, grandchild, 1_400, "/bin/sh", "sh", Some(101)),
        exit(id, 102, grandchild, 1_500, "sh", Some(101)),
        exit(id, 101, child, 1_600, "make", Some(100)),
        exit(id, 100, root, 1_700, "bash", Some(1)),
    ]
}

#[test]
fn shell_chain_positive_and_single_child_negative() {
    let report = run(
        "s-shell-positive",
        shell_chain_events("s-shell-positive"),
        0,
        Some(RULE_SHELL_CHAIN),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");
    let finding = &report.findings[0];
    assert_eq!(finding.rule_id, RULE_SHELL_CHAIN);
    assert!(finding.process_instance_ids.len() >= 3);
    assert!(finding.event_ids.iter().all(|id| *id > 0));
    assert!(finding.explanation.contains("descendant"));

    let id = "s-shell-negative";
    let root = "boot:100:1";
    let child = "boot:101:2";
    let report = run(
        id,
        vec![
            exec(id, 100, root, 1_000, "/bin/bash", "bash", Some(1)),
            fork(id, 100, 101, child, 1_100, "sleep"),
            exec(id, 101, child, 1_200, "/usr/bin/sleep", "sleep", Some(100)),
            exit(id, 101, child, 1_300, "sleep", Some(100)),
            exit(id, 100, root, 1_400, "bash", Some(1)),
        ],
        0,
        Some(RULE_SHELL_CHAIN),
        AnalysisConfig::default(),
    );
    assert!(report.findings.is_empty(), "{report:?}");
}

#[test]
fn shell_chain_confidence_drops_when_descendant_ancestry_is_unresolved() {
    let id = "s-shell-unresolved";
    let mut events = shell_chain_events(id);
    let EventPayload::ProcessFork {
        child_start_time_ticks,
        ..
    } = &mut events[1].payload
    else {
        panic!("expected a fork event");
    };
    *child_start_time_ticks = None;

    let report = run(
        id,
        events,
        0,
        Some(RULE_SHELL_CHAIN),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");
    assert_eq!(
        report.findings[0].confidence,
        AnalysisConfidence::Medium,
        "{report:?}"
    );
    assert!(report.findings[0]
        .limitations
        .iter()
        .any(|limit| limit.contains("descendant's process ancestry")));
}

#[test]
fn temporary_execution_is_component_aware_and_does_not_guess_missing_paths() {
    let id = "s-temp";
    let instance = "boot:200:1";
    let report = run(
        id,
        vec![exec(
            id,
            200,
            instance,
            1_000,
            "/tmp/../tmp/payload",
            "payload",
            Some(1),
        )],
        0,
        Some(RULE_TEMP_EXEC),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");
    assert_eq!(report.findings[0].severity, AnalysisSeverity::Medium);

    for (session_id, path) in [
        ("s-temp-prefix", "/tmpfoo/payload"),
        ("s-temp-relative", "tmp/payload"),
        ("s-temp-benign", "/usr/bin/payload"),
    ] {
        let inst = "boot:200:1";
        let report = run(
            session_id,
            vec![exec(session_id, 200, inst, 1_000, path, "payload", Some(1))],
            0,
            Some(RULE_TEMP_EXEC),
            AnalysisConfig::default(),
        );
        assert!(report.findings.is_empty(), "{session_id}: {report:?}");
    }
}

#[test]
fn sensitive_paths_distinguish_success_failure_and_unresolved_relative_paths() {
    let id = "s-sensitive";
    let instance = "boot:300:1";
    let report = run(
        id,
        vec![
            exec(id, 300, instance, 1_000, "/usr/bin/tool", "tool", Some(1)),
            open(id, 300, instance, 1_100, "/etc/shadow", true, true),
            open(id, 300, instance, 1_200, "/etc/sudoers", true, false),
            open(id, 300, instance, 1_300, "shadow", false, true),
            open(id, 300, instance, 1_400, "/etc/hostname", true, true),
        ],
        0,
        Some(RULE_SENSITIVE_OPEN),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 3, "{report:?}");
    let high = report
        .findings
        .iter()
        .find(|f| f.title.contains("/etc/shadow") && f.severity == AnalysisSeverity::High)
        .expect("successful shadow open must be high severity");
    assert_eq!(high.confidence, AnalysisConfidence::High);
    assert!(report
        .findings
        .iter()
        .any(|f| f.severity == AnalysisSeverity::Low && f.title.contains("sudoers")));
    assert!(report
        .findings
        .iter()
        .any(|f| f.severity == AnalysisSeverity::Informational && f.correlation == "same_process"));

    let id = "s-sensitive-truncated";
    let instance = "boot:301:1";
    let mut truncated = open(id, 301, instance, 1_100, "/etc/shadow", true, true);
    let EventPayload::FileOpen { path_truncated, .. } = &mut truncated.payload else {
        panic!("expected file_open payload");
    };
    *path_truncated = true;
    let report = run(
        id,
        vec![
            exec(id, 301, instance, 1_000, "/usr/bin/tool", "tool", Some(1)),
            truncated,
        ],
        0,
        Some(RULE_SENSITIVE_OPEN),
        AnalysisConfig::default(),
    );
    assert!(report.findings.is_empty(), "{report:?}");
    assert!(report
        .limitations
        .iter()
        .any(|limit| limit.contains("truncated paths")));

    let id = "s-sensitive-incomplete";
    let instance = "boot:302:1";
    let report = run(
        id,
        vec![
            exec(id, 302, instance, 1_000, "/usr/bin/tool", "tool", Some(1)),
            open(id, 302, instance, 1_100, "/etc/shadow", true, true),
        ],
        1,
        Some(RULE_SENSITIVE_OPEN),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");
    assert_eq!(report.findings[0].confidence, AnalysisConfidence::Medium);
}

#[test]
fn repeated_failures_require_threshold_window_and_failure_result() {
    let id = "s-repeat";
    let instance = "boot:400:1";
    let report = run(
        id,
        vec![
            exec(
                id,
                400,
                instance,
                1_000,
                "/usr/bin/client",
                "client",
                Some(1),
            ),
            connect(id, 400, instance, 1_100, "127.0.0.1", 9, false),
            connect(id, 400, instance, 1_200, "127.0.0.1", 9, false),
            connect(id, 400, instance, 1_300, "127.0.0.1", 9, false),
        ],
        0,
        Some(RULE_REPEATED_CONNECT),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");
    assert_eq!(report.findings[0].event_ids.len(), 3);

    let single = "s-repeat-single";
    let instance = "boot:401:1";
    let report = run(
        single,
        vec![
            exec(
                single,
                401,
                instance,
                1_000,
                "/usr/bin/client",
                "client",
                Some(1),
            ),
            connect(single, 401, instance, 1_100, "127.0.0.1", 9, false),
            connect(single, 401, instance, 1_200, "127.0.0.1", 9, false),
        ],
        0,
        Some(RULE_REPEATED_CONNECT),
        AnalysisConfig::default(),
    );
    assert!(report.findings.is_empty(), "{report:?}");

    let success = "s-repeat-success";
    let instance = "boot:402:1";
    let report = run(
        success,
        vec![
            exec(
                success,
                402,
                instance,
                1_000,
                "/usr/bin/client",
                "client",
                Some(1),
            ),
            connect(success, 402, instance, 1_100, "127.0.0.1", 9, true),
            connect(success, 402, instance, 1_200, "127.0.0.1", 9, true),
            connect(success, 402, instance, 1_300, "127.0.0.1", 9, true),
        ],
        0,
        Some(RULE_REPEATED_CONNECT),
        AnalysisConfig::default(),
    );
    assert!(report.findings.is_empty(), "{report:?}");

    let outside = "s-repeat-window";
    let instance = "boot:403:1";
    let report = run(
        outside,
        vec![
            exec(
                outside,
                403,
                instance,
                1_000_000_000,
                "/usr/bin/client",
                "client",
                Some(1),
            ),
            connect(outside, 403, instance, 2_000_000_000, "127.0.0.1", 9, false),
            connect(
                outside,
                403,
                instance,
                63_000_000_000,
                "127.0.0.1",
                9,
                false,
            ),
            connect(
                outside,
                403,
                instance,
                124_000_000_000,
                "127.0.0.1",
                9,
                false,
            ),
        ],
        0,
        Some(RULE_REPEATED_CONNECT),
        AnalysisConfig::default(),
    );
    assert!(report.findings.is_empty(), "{report:?}");
}

#[test]
fn filesystem_network_correlation_is_separate_for_same_process_and_tree() {
    let id = "s-correlation";
    let instance = "boot:500:1";
    let report = run(
        id,
        vec![
            exec(id, 500, instance, 1_000, "/usr/bin/app", "app", Some(1)),
            open(id, 500, instance, 1_100, "/etc/config", true, true),
            connect(id, 500, instance, 1_200, "192.0.2.10", 443, true),
        ],
        0,
        Some(RULE_FS_NET_CORRELATION),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");
    assert_eq!(report.findings[0].correlation, "same_process");
    assert!(!report.findings[0].explanation.contains("exfiltrat"));

    let tree = "s-correlation-tree";
    let parent = "boot:600:1";
    let child = "boot:601:2";
    let report = run(
        tree,
        vec![
            exec(
                tree,
                600,
                parent,
                1_000,
                "/usr/bin/parent",
                "parent",
                Some(1),
            ),
            open(tree, 600, parent, 1_100, "/etc/config", true, true),
            fork(tree, 600, 601, child, 1_150, "child"),
            exec(
                tree,
                601,
                child,
                1_200,
                "/usr/bin/child",
                "child",
                Some(600),
            ),
            connect(tree, 601, child, 1_300, "192.0.2.10", 443, false),
        ],
        0,
        Some(RULE_FS_NET_CORRELATION),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");
    assert_eq!(report.findings[0].correlation, "process_tree");

    let outside = "s-correlation-window";
    let instance = "boot:700:1";
    let report = run(
        outside,
        vec![
            exec(
                outside,
                700,
                instance,
                1_000_000_000,
                "/usr/bin/app",
                "app",
                Some(1),
            ),
            open(
                outside,
                700,
                instance,
                2_000_000_000,
                "/etc/config",
                true,
                true,
            ),
            connect(
                outside,
                700,
                instance,
                63_000_000_000,
                "192.0.2.10",
                443,
                false,
            ),
        ],
        0,
        Some(RULE_FS_NET_CORRELATION),
        AnalysisConfig::default(),
    );
    assert!(report.findings.is_empty(), "{report:?}");
}

#[test]
fn short_lived_network_requires_exit_and_respects_window() {
    let id = "s-short";
    let instance = "boot:800:1";
    let report = run(
        id,
        vec![
            exec(
                id,
                800,
                instance,
                1_000_000_000,
                "/usr/bin/check",
                "check",
                Some(1),
            ),
            connect(id, 800, instance, 1_500_000_000, "192.0.2.20", 80, false),
            exit(id, 800, instance, 2_000_000_000, "check", Some(1)),
        ],
        0,
        Some(RULE_SHORT_LIVED_NET),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");

    let missing = "s-short-missing-exit";
    let instance = "boot:801:1";
    let report = run(
        missing,
        vec![
            exec(
                missing,
                801,
                instance,
                1_000_000_000,
                "/usr/bin/check",
                "check",
                Some(1),
            ),
            connect(
                missing,
                801,
                instance,
                1_500_000_000,
                "192.0.2.20",
                80,
                false,
            ),
        ],
        0,
        Some(RULE_SHORT_LIVED_NET),
        AnalysisConfig::default(),
    );
    assert!(report.findings.is_empty(), "{report:?}");
    assert!(report
        .limitations
        .iter()
        .any(|l| l.contains("no recorded exit")));

    let long = "s-short-long";
    let instance = "boot:802:1";
    let report = run(
        long,
        vec![
            exec(
                long,
                802,
                instance,
                1_000_000_000,
                "/usr/bin/server",
                "server",
                Some(1),
            ),
            connect(long, 802, instance, 2_000_000_000, "192.0.2.20", 80, true),
            exit(long, 802, instance, 30_000_000_000, "server", Some(1)),
        ],
        0,
        Some(RULE_SHORT_LIVED_NET),
        AnalysisConfig::default(),
    );
    assert!(report.findings.is_empty(), "{report:?}");
}

#[test]
fn ambiguous_parent_pid_prevents_process_tree_correlation() {
    let id = "s-pid-reuse";
    let first = "boot:900:1";
    let second = "boot:900:2";
    let child = "boot:901:3";
    let report = run(
        id,
        vec![
            exec(id, 900, first, 500, "/usr/bin/old", "old", Some(1)),
            exec(id, 900, second, 600, "/usr/bin/new", "new", Some(1)),
            open(id, 900, first, 700, "/etc/config", true, true),
            fork(id, 900, 901, child, 800, "child"),
            exec(id, 901, child, 900, "/usr/bin/child", "child", Some(900)),
            connect(id, 901, child, 1_000, "192.0.2.30", 443, false),
        ],
        0,
        Some(RULE_FS_NET_CORRELATION),
        AnalysisConfig::default(),
    );
    assert!(report.findings.is_empty(), "{report:?}");
    assert!(report.limitations.iter().any(|l| l.contains("unresolved")));
}

#[test]
fn losses_downgrade_confidence_and_disable_rules_are_respected() {
    let id = "s-incomplete";
    let instance = "boot:950:1";
    let report = run(
        id,
        vec![exec(
            id,
            950,
            instance,
            1_000,
            "/tmp/payload",
            "payload",
            Some(1),
        )],
        2,
        Some(RULE_TEMP_EXEC),
        AnalysisConfig::default(),
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");
    assert_eq!(report.findings[0].confidence, AnalysisConfidence::Medium);
    assert!(report.evidence.may_be_incomplete);

    let config = AnalysisConfig {
        disabled_rules: vec![RULE_TEMP_EXEC.to_owned()],
        ..Default::default()
    };
    let id = "s-disabled";
    let instance = "boot:951:1";
    let report = run(
        id,
        vec![exec(
            id,
            951,
            instance,
            1_000,
            "/tmp/payload",
            "payload",
            Some(1),
        )],
        0,
        None,
        config.clone(),
    );
    assert!(report.findings.is_empty(), "{report:?}");
    let report = run(
        id,
        vec![exec(
            id,
            951,
            instance,
            1_000,
            "/tmp/payload",
            "payload",
            Some(1),
        )],
        0,
        Some(RULE_TEMP_EXEC),
        config,
    );
    assert_eq!(
        report.findings.len(),
        1,
        "explicit rule must override disabled default"
    );
}

#[test]
fn severity_and_confidence_filters_are_inclusive() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("filters.db");
    let mut storage = Storage::open(&db).unwrap();
    let id = "s-filters";
    storage.create_session(&session(id)).unwrap();
    let instance = "boot:960:1";
    let events = vec![exec(
        id,
        960,
        instance,
        1_000,
        "/tmp/payload",
        "payload",
        Some(1),
    )];
    storage.insert_events(id, &events).unwrap();
    finish(&mut storage, id, 1, 0);

    let run_with = |severity, confidence| {
        analyze(
            &storage,
            id,
            AnalysisOptions {
                config: AnalysisConfig::default(),
                rule: Some(RULE_TEMP_EXEC.to_owned()),
                min_severity: severity,
                min_confidence: confidence,
            },
        )
        .unwrap()
    };
    assert_eq!(run_with(None, None).findings.len(), 1);
    assert_eq!(
        run_with(Some(AnalysisSeverity::High), None).findings.len(),
        0
    );
    let high_confidence = run_with(None, Some(AnalysisConfidence::High));
    assert_eq!(
        high_confidence.findings.len(),
        1,
        "base confidence should be high for a complete session: {high_confidence:?}"
    );
}

#[test]
fn output_is_deterministic_and_analysis_is_read_only() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("deterministic.db");
    let mut storage = Storage::open(&db).unwrap();
    storage.create_session(&session("s-deterministic")).unwrap();
    let events = shell_chain_events("s-deterministic");
    let count = events.len() as u64;
    storage.insert_events("s-deterministic", &events).unwrap();
    finish(&mut storage, "s-deterministic", count, 0);
    let before = std::fs::read(&db).unwrap();
    let read_only = Storage::open_read_only(&db).unwrap();
    let options = || AnalysisOptions::default();
    let first = analyze(&read_only, "s-deterministic", options()).unwrap();
    let second = analyze(&read_only, "s-deterministic", options()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.schema_version, syscall_core::ANALYSIS_SCHEMA_VERSION);
    drop(read_only);
    let after = std::fs::read(&db).unwrap();
    assert_eq!(
        before, after,
        "analysis must not modify the recording database"
    );

    let json1 = serde_json::to_string_pretty(&serde_json::to_value(&first).unwrap()).unwrap();
    let json2 = serde_json::to_string_pretty(&serde_json::to_value(&second).unwrap()).unwrap();
    assert_eq!(json1, json2);

    for finding in &first.findings {
        for event_id in &finding.event_ids {
            assert!(*event_id > 0);
        }
        for support in &finding.supporting_events {
            assert!(finding.event_ids.contains(&support.event_id));
        }
    }
}
