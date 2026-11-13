import type {
  AnalysisReport,
  AnalysisRuleMetadata,
  AppInfo,
  EventPayload,
  EventType,
  EventView,
  ExportResult,
  FindingCounts,
  OverviewResponse,
  ProcessTreeResponse,
  ProcessView,
  SessionDetail,
  SessionVerificationReport,
  SessionView,
  VerificationSummary
} from "../types/contracts";

const BASE_ONE = Date.UTC(2026, 10, 10, 19, 18, 1, 508) * 1_000_000;
const BASE_TWO = Date.UTC(2026, 10, 10, 19, 18, 3, 138) * 1_000_000;

const emptyFindings: FindingCounts = {
  informational: 0,
  low: 0,
  medium: 0,
  high: 0,
  critical: 0,
  total: 0
};

function verification(
  assessment: VerificationSummary["assessment"],
  counts: VerificationSummary["counts"],
  limitations: string[]
): VerificationSummary {
  return {
    assessment,
    counts,
    totalFindings: counts.info + counts.warning + counts.error + counts.critical,
    limitations
  };
}

function provenance(sourceTracepoint: string): EventView["provenance"] {
  return {
    rawBpfPid: null,
    rawBpfTgid: null,
    observerPid: null,
    observerTgid: null,
    sourceTracepoint,
    wireSchemaVersion: 1,
    attributionMethod: "process_instance",
    timestampClockDomain: "realtime",
    monotonicClockDomain: "monotonic"
  };
}

function makeEvent(
  _sessionEvents: EventView[],
  args: {
    eventType: EventType;
    timestampNs: number;
    offsetNs: number;
    pid: number;
    comm: string;
    processInstanceId: string;
    ppid: number | null;
    payload: EventPayload;
    tracepoint: string;
  }
): EventView {
  return {
    id: 0,
    eventType: args.eventType,
    timestampNs: args.timestampNs + args.offsetNs,
    monotonicNs: 9_000_000_000 + args.offsetNs,
    pid: args.pid,
    tid: args.pid,
    uid: 1000,
    gid: 1000,
    ppid: args.ppid,
    comm: args.comm,
    processInstanceId: args.processInstanceId,
    payload: args.payload,
    provenance: provenance(args.tracepoint)
  };
}

function filePayload(path: string, index: number): EventPayload {
  const failed = index === 7;
  return {
    kind: "file_open",
    path,
    pathIsAbsolute: true,
    pathTruncated: false,
    dirfd: -100,
    flags: 524288,
    result: failed ? -1 : 3,
    success: !failed,
    errno: failed ? 2 : null
  };
}

const normalPaths = [
  "/etc/ld.so.cache",
  "/lib/x86_64-linux-gnu/libc.so.6",
  "/etc/ld.so.preload",
  "/usr/lib/locale/locale-archive",
  "/etc/nsswitch.conf",
  "/etc/passwd",
  "/etc/group",
  "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache",
  "/proc/self/maps",
  "/proc/self/status",
  "/etc/host.conf",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/usr/share/locale/en/LC_MESSAGES/libc.mo",
  "/dev/null",
  "/proc/26440/cmdline",
  "/proc/26441/cmdline",
  "/proc/26442/cmdline",
  "/usr/lib/x86_64-linux-gnu/libm.so.6",
  "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
  "/usr/lib/x86_64-linux-gnu/libdl.so.2",
  "/usr/lib/x86_64-linux-gnu/librt.so.1",
  "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
  "/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
  "/usr/lib/x86_64-linux-gnu/libz.so.1",
  "/etc/ssl/certs/ca-certificates.crt",
  "/etc/localtime",
  "/etc/timezone",
  "/sys/devices/system/cpu/online",
  "/proc/meminfo",
  "/proc/loadavg",
  "/etc/environment",
  "/etc/profile",
  "/etc/bash.bashrc",
  "/dev/tty"
];

const interruptedPaths = [
  "/etc/ld.so.cache",
  "/lib/x86_64-linux-gnu/libc.so.6",
  "/usr/lib/locale/locale-archive",
  "/etc/nsswitch.conf",
  "/etc/passwd",
  "/etc/group",
  "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache",
  "/proc/self/maps",
  "/proc/self/status",
  "/etc/host.conf",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/dev/null",
  "/usr/lib/x86_64-linux-gnu/libm.so.6",
  "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
  "/usr/lib/x86_64-linux-gnu/libdl.so.2",
  "/usr/lib/x86_64-linux-gnu/librt.so.1",
  "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
  "/usr/lib/x86_64-linux-gnu/libz.so.1",
  "/etc/localtime",
  "/etc/timezone",
  "/sys/devices/system/cpu/online",
  "/proc/meminfo",
  "/proc/loadavg",
  "/etc/environment",
  "/proc/23944/cmdline",
  "/dev/tty",
  "/proc/self/stat",
  "/proc/self/mountinfo",
  "/usr/share/locale/en/LC_MESSAGES/libc.mo"
];

const normalEvents: EventView[] = [];
const sh = "mock-26440";
const sleep = "mock-26441";
const truth = "mock-26442";

normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_exec",
    timestampNs: BASE_ONE,
    offsetNs: 0,
    pid: 26440,
    comm: "sh",
    processInstanceId: sh,
    ppid: 26439,
    payload: {
      kind: "process_exec",
      filename: "/bin/sh",
      ppid: 26439,
      startTimeTicks: 9182341,
      oldPid: null
    },
    tracepoint: "sched_process_exec"
  })
);
normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_fork",
    timestampNs: BASE_ONE,
    offsetNs: 2_000_000,
    pid: 26440,
    comm: "sh",
    processInstanceId: sh,
    ppid: 26439,
    payload: {
      kind: "process_fork",
      parentPid: 26440,
      parentTgid: 26440,
      childPid: 26441,
      childComm: "sleep",
      childStartTimeTicks: 9182402
    },
    tracepoint: "sched_process_fork"
  })
);
normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_fork",
    timestampNs: BASE_ONE,
    offsetNs: 2_400_000,
    pid: 26440,
    comm: "sh",
    processInstanceId: sh,
    ppid: 26439,
    payload: {
      kind: "process_fork",
      parentPid: 26440,
      parentTgid: 26440,
      childPid: 26442,
      childComm: "true",
      childStartTimeTicks: 9182403
    },
    tracepoint: "sched_process_fork"
  })
);
normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_exec",
    timestampNs: BASE_ONE,
    offsetNs: 3_000_000,
    pid: 26441,
    comm: "sleep",
    processInstanceId: sleep,
    ppid: 26440,
    payload: {
      kind: "process_exec",
      filename: "/bin/sleep",
      ppid: 26440,
      startTimeTicks: 9182402,
      oldPid: null
    },
    tracepoint: "sched_process_exec"
  })
);
normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_exec",
    timestampNs: BASE_ONE,
    offsetNs: 3_400_000,
    pid: 26442,
    comm: "true",
    processInstanceId: truth,
    ppid: 26440,
    payload: {
      kind: "process_exec",
      filename: "/bin/true",
      ppid: 26440,
      startTimeTicks: 9182403,
      oldPid: null
    },
    tracepoint: "sched_process_exec"
  })
);

normalPaths.forEach((path, index) => {
  const owner = index % 3 === 1 ? sleep : index % 3 === 2 ? truth : sh;
  const pid = owner === sleep ? 26441 : owner === truth ? 26442 : 26440;
  const comm = owner === sleep ? "sleep" : owner === truth ? "true" : "sh";
  normalEvents.push(
    makeEvent(normalEvents, {
      eventType: "file_open",
      timestampNs: BASE_ONE,
      offsetNs: 4_000_000 + index * 12_000_000,
      pid,
      comm,
      processInstanceId: owner,
      ppid: owner === sh ? 26439 : 26440,
      payload: filePayload(path, index),
      tracepoint: "sys_enter_openat"
    })
  );
});

normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_exit",
    timestampNs: BASE_ONE,
    offsetNs: 900_000_000,
    pid: 26441,
    comm: "sleep",
    processInstanceId: sleep,
    ppid: 26440,
    payload: {
      kind: "process_exit",
      ppid: 26440,
      startTimeTicks: 9182402,
      exitPriority: 0
    },
    tracepoint: "sched_process_exit"
  }),
  makeEvent(normalEvents, {
    eventType: "process_exit",
    timestampNs: BASE_ONE,
    offsetNs: 920_000_000,
    pid: 26442,
    comm: "true",
    processInstanceId: truth,
    ppid: 26440,
    payload: {
      kind: "process_exit",
      ppid: 26440,
      startTimeTicks: 9182403,
      exitPriority: 0
    },
    tracepoint: "sched_process_exit"
  }),
  makeEvent(normalEvents, {
    eventType: "process_exit",
    timestampNs: BASE_ONE,
    offsetNs: 1_066_000_000,
    pid: 26440,
    comm: "sh",
    processInstanceId: sh,
    ppid: 26439,
    payload: {
      kind: "process_exit",
      ppid: 26439,
      startTimeTicks: 9182341,
      exitPriority: 0
    },
    tracepoint: "sched_process_exit"
  })
);

const interruptedEvents: EventView[] = [];
const sleeper = "mock-23944";
interruptedEvents.push(
  makeEvent(interruptedEvents, {
    eventType: "process_exec",
    timestampNs: BASE_TWO,
    offsetNs: 0,
    pid: 23944,
    comm: "sleep",
    processInstanceId: sleeper,
    ppid: 23943,
    payload: {
      kind: "process_exec",
      filename: "/bin/sleep",
      ppid: 23943,
      startTimeTicks: 9184410,
      oldPid: null
    },
    tracepoint: "sched_process_exec"
  })
);

interruptedPaths.forEach((path, index) => {
  interruptedEvents.push(
    makeEvent(interruptedEvents, {
      eventType: "file_open",
      timestampNs: BASE_TWO,
      offsetNs: 3_000_000 + index * 20_000_000,
      pid: 23944,
      comm: "sleep",
      processInstanceId: sleeper,
      ppid: 23943,
      payload: filePayload(path, index),
      tracepoint: "sys_enter_openat"
    })
  );
});

interruptedEvents.push(
  makeEvent(interruptedEvents, {
    eventType: "process_exit",
    timestampNs: BASE_TWO,
    offsetNs: 33_500_000_000,
    pid: 23944,
    comm: "sleep",
    processInstanceId: sleeper,
    ppid: 23943,
    payload: {
      kind: "process_exit",
      ppid: 23943,
      startTimeTicks: 9184410,
      exitPriority: 0
    },
    tracepoint: "sched_process_exit"
  })
);

export const appInfo: AppInfo = {
  contractVersion: "ui-preview",
  appVersion: "0.1.0",
  databasePath: "/mock/evidence/workbench-preview.db",
  databaseExists: true,
  readOnly: true,
  exportDirectory: "/mock/evidence/exports",
  recordingSupported: false
};

export const sessions: SessionView[] = [
  {
    id: "mock-normal-001",
    status: "completed",
    command: "/bin/sh",
    arguments: ["-c", "/bin/sleep 0.2 && /bin/true; wait"],
    commandDisplay: "/bin/sh -c /bin/sleep 0.2 && /bin/true; wait",
    recordingScope: "target-tree",
    startedAtNs: BASE_ONE,
    endedAtNs: BASE_ONE + 1_066_000_000,
    durationNs: 1_066_000_000,
    processCount: 3,
    eventCount: normalEvents.length,
    droppedEvents: 0,
    ringbufLostEvents: 0,
    userspaceDroppedEvents: 0,
    malformedEvents: 0,
    filteredEvents: 14,
    persistFailedEvents: 0,
    evidenceIncomplete: false,
    targetExitCode: 0,
    targetExitSignal: null,
    terminationReason: "target_exit",
    error: null,
    kernelRelease: "6.6.87.2-microsoft-standard-WSL2",
    collectorVersion: "0.1.0",
    verification: verification("valid", { info: 0, warning: 0, error: 0, critical: 0 }, []),
    findingCounts: emptyFindings,
    intelligenceError: null
  },
  {
    id: "mock-interrupt-002",
    status: "interrupted",
    command: "/bin/sleep",
    arguments: ["30"],
    commandDisplay: "/bin/sleep 30",
    recordingScope: "target-tree",
    startedAtNs: BASE_TWO,
    endedAtNs: BASE_TWO + 33_500_000_000,
    durationNs: 33_500_000_000,
    processCount: 1,
    eventCount: interruptedEvents.length,
    droppedEvents: 0,
    ringbufLostEvents: 0,
    userspaceDroppedEvents: 0,
    malformedEvents: 0,
    filteredEvents: 7,
    persistFailedEvents: 0,
    evidenceIncomplete: false,
    targetExitCode: null,
    targetExitSignal: null,
    terminationReason: "interrupted",
    error: null,
    kernelRelease: "6.6.87.2-microsoft-standard-WSL2",
    collectorVersion: "0.1.0",
    verification: verification(
      "valid_but_incomplete",
      { info: 0, warning: 1, error: 0, critical: 0 },
      ["The session was interrupted before the target completed."]
    ),
    findingCounts: {
      informational: 0,
      low: 1,
      medium: 0,
      high: 0,
      critical: 0,
      total: 1
    },
    intelligenceError: null
  }
];

normalEvents.forEach((event, index) => {
  event.id = index + 1;
});
interruptedEvents.forEach((event, index) => {
  event.id = index + 1;
});

const eventsBySession: Record<string, EventView[]> = {
  "mock-normal-001": normalEvents,
  "mock-interrupt-002": interruptedEvents
};

const trees: Record<string, ProcessTreeResponse> = {
  "mock-normal-001": {
    processes: [
      {
        processInstanceId: sh,
        pid: 26440,
        comm: "sh",
        executable: "/bin/sh",
        commandLine: "/bin/sh -c /bin/sleep 0.2 && /bin/true; wait",
        firstSeenNs: BASE_ONE,
        lastSeenNs: BASE_ONE + 1_066_000_000,
        eventCount: 15,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 26439,
        parentProcessInstanceId: null,
        identityUnresolved: false,
        ancestryUnresolved: true,
        notes: ["Parent pid 26439 was outside the recorded target tree."],
        childInstanceIds: [sleep, truth],
        relationship: "root"
      },
      {
        processInstanceId: sleep,
        pid: 26441,
        comm: "sleep",
        executable: "/bin/sleep",
        commandLine: "/bin/sleep 0.2",
        firstSeenNs: BASE_ONE + 2_000_000,
        lastSeenNs: BASE_ONE + 900_000_000,
        eventCount: 13,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 26440,
        parentProcessInstanceId: sh,
        identityUnresolved: false,
        ancestryUnresolved: false,
        notes: [],
        childInstanceIds: [],
        relationship: "observed"
      },
      {
        processInstanceId: truth,
        pid: 26442,
        comm: "true",
        executable: "/bin/true",
        commandLine: "/bin/true",
        firstSeenNs: BASE_ONE + 2_400_000,
        lastSeenNs: BASE_ONE + 920_000_000,
        eventCount: 13,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 26440,
        parentProcessInstanceId: sh,
        identityUnresolved: false,
        ancestryUnresolved: false,
        notes: [],
        childInstanceIds: [],
        relationship: "observed"
      }
    ],
    roots: [sh],
    unresolvedAncestryCount: 1,
    identityUnresolvedCount: 0,
    notes: ["One ancestry link terminates outside the recorded target tree."]
  },
  "mock-interrupt-002": {
    processes: [
      {
        processInstanceId: sleeper,
        pid: 23944,
        comm: "sleep",
        executable: "/bin/sleep",
        commandLine: "/bin/sleep 30",
        firstSeenNs: BASE_TWO,
        lastSeenNs: BASE_TWO + 33_500_000_000,
        eventCount: 32,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 23943,
        parentProcessInstanceId: null,
        identityUnresolved: false,
        ancestryUnresolved: true,
        notes: ["The recorded process was terminated when capture stopped."],
        childInstanceIds: [],
        relationship: "root"
      }
    ],
    roots: [sleeper],
    unresolvedAncestryCount: 1,
    identityUnresolvedCount: 0,
    notes: []
  }
};

const rules: AnalysisRuleMetadata[] = [
  {
    rule_id: "NET-001",
    version: 1,
    title: "Network connect from a short-lived process",
    description: "A process initiated an outbound connection during a short observed lifetime.",
    conditions: ["A network_connect event belongs to the process instance."],
    required_evidence: ["network_connect event", "process instance"],
    exclusions: [],
    known_false_positives: ["Package managers and health checks."],
    severity_rationale: "Low severity because outbound access is common.",
    confidence_rationale: "High confidence in the observation, not intent.",
    default_severity: "low",
    default_confidence: "high"
  },
  {
    rule_id: "PROC-002",
    version: 1,
    title: "Observed process without a complete lifetime",
    description: "Process activity exists but the full process lifetime was not observed.",
    conditions: ["A process instance was observed without both entry and exit ancestry."],
    required_evidence: ["process instance", "session boundary"],
    exclusions: [],
    known_false_positives: ["Capture interruptions and intentionally long-running targets."],
    severity_rationale: "Low severity because this is a coverage limitation.",
    confidence_rationale: "High confidence in the recorded boundary.",
    default_severity: "low",
    default_confidence: "high"
  },
  {
    rule_id: "FILE-003",
    version: 1,
    title: "Library file opened by a short-lived process",
    description: "A process loaded shared libraries during startup.",
    conditions: ["A file_open event points at a shared-library path."],
    required_evidence: ["file_open event"],
    exclusions: [],
    known_false_positives: ["Normal dynamic linking."],
    severity_rationale: "Informational; this is expected runtime behavior.",
    confidence_rationale: "High confidence in the recorded path.",
    default_severity: "informational",
    default_confidence: "high"
  },
  {
    rule_id: "EXEC-004",
    version: 1,
    title: "Executable replaced during process transition",
    description: "An exec transition was observed for a forked process.",
    conditions: ["A process_fork event is followed by an exec for the child pid."],
    required_evidence: ["process_fork event", "process_exec event"],
    exclusions: [],
    known_false_positives: ["Shell command execution."],
    severity_rationale: "Informational; common shell behavior.",
    confidence_rationale: "Medium confidence because event ordering is bounded by persistence.",
    default_severity: "informational",
    default_confidence: "medium"
  }
];

function analysisFor(sessionId: string): AnalysisReport {
  const session = sessions.find((item) => item.id === sessionId) ?? sessions[0];
  if (!session) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };
  const interrupted = session.id === "mock-interrupt-002";
  return {
    schema_version: "syscall-analysis/v1",
    session_id: session.id,
    session_command: session.commandDisplay,
    session_scope: session.recordingScope,
    session_started_at_ns: session.startedAtNs,
    session_ended_at_ns: session.endedAtNs,
    evidence: {
      status: interrupted ? "interrupted" : "complete",
      session_status: session.status,
      event_count: session.eventCount,
      process_count: session.processCount,
      ringbuf_lost_events: 0,
      userspace_dropped_events: 0,
      malformed_events: 0,
      filtered_events: session.filteredEvents,
      events_persist_failed: 0,
      unresolved_identity_count: interrupted ? 1 : 0,
      verification_assessment: session.verification?.assessment ?? null,
      may_be_incomplete: interrupted,
      notes: interrupted
        ? ["The target did not complete before capture ended.", "1 process ancestry link is unresolved."]
        : ["Evidence completeness is qualified by target-tree attribution."]
    },
    rules_evaluated: rules,
    findings: interrupted
      ? [
          {
            finding_id: "mock-finding-001",
            rule_id: "PROC-002",
            rule_version: 1,
            severity: "low",
            confidence: "high",
            title: "Process remained observable without a complete lifetime",
            explanation:
              "The target process was observed for 33.5 seconds before the capture boundary terminated it.",
            significance:
              "The missing post-boundary behavior qualifies the completeness of this session without implying evidence loss.",
            event_ids: [1, 32],
            process_instance_ids: [sleeper],
            pids: [23944],
            time_range: {
              start_ns: BASE_TWO,
              end_ns: BASE_TWO + 33_500_000_000
            },
            related_findings: [],
            limitations: ["The process may have continued after capture stopped."],
            next_steps: ["Review the session termination reason and target command line."],
            supporting_events: [
              {
                event_id: 1,
                timestamp_ns: BASE_TWO,
                monotonic_ns: 9_000_000_000,
                event_type: "process_exec",
                pid: 23944,
                process_instance_id: sleeper,
                comm: "sleep",
                summary: "/bin/sleep"
              }
            ],
            related_processes: [
              {
                process_instance_id: sleeper,
                pid: 23944,
                comm: "sleep",
                executable: "/bin/sleep",
                parent_process_instance_id: null,
                exit_observed: true
              }
            ],
            correlation: "single_process"
          }
        ]
      : [],
    limitations: [
      "Analysis is limited to persisted evidence.",
      "A finding is an observation, not a verdict."
    ],
    truncated: false
  };
}

function verificationFor(sessionId: string): SessionVerificationReport {
  const session = sessions.find((item) => item.id === sessionId) ?? sessions[0];
  if (!session) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };
  const interrupted = session.id === "mock-interrupt-002";
  return {
    session_id: session.id,
    verification_timestamp_ns: BASE_ONE + 24_000_000_000,
    database_schema_version: 5,
    session_status: session.status,
    assessment: interrupted ? "valid_but_incomplete" : "valid",
    severity_counts: interrupted
      ? { info: 0, warning: 1, error: 0, critical: 0 }
      : { info: 0, warning: 0, error: 0, critical: 0 },
    findings: interrupted
      ? [
          {
            code: "VER-COMPLETENESS",
            severity: "warning",
            title: "Capture ended before the target completed",
            detail:
              "The session is structurally valid, but the target lifetime was cut short by the capture boundary.",
            session_id: session.id,
            event_id: 32,
            process_instance_id: sleeper,
            evidence: ["session status: interrupted", "process instance mock-23944"],
            recommendation: "Treat post-boundary behavior as unobserved."
          }
        ]
      : [],
    limitations: ["Verification does not prove authenticity or complete collection."]
  };
}

export function sessionDetail(sessionId: string): SessionDetail {
  const session = sessions.find((item) => item.id === sessionId);
  if (!session) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };
  const events = eventsBySession[session.id] ?? [];
  const counts = new Map<EventType, number>();
  for (const event of events) {
    counts.set(event.eventType, (counts.get(event.eventType) ?? 0) + 1);
  }
  return {
    session,
    stats: {
      eventCount: events.length,
      processCount: session.processCount,
      eventsPersisted: events.length,
      eventsByType: [...counts.entries()].map(([eventType, count]) => ({ eventType, count })),
      ringbufLostEvents: 0,
      userspaceDroppedEvents: 0,
      droppedEventsTotal: 0,
      malformedEvents: 0,
      filteredEvents: session.filteredEvents,
      eventsSelfFiltered: 0,
      eventsPersistFailed: 0,
      unresolvedIdentityCount: session.id === "mock-interrupt-002" ? 1 : 0,
      evidenceMayBeIncomplete: session.status === "interrupted",
      terminationReason: session.terminationReason,
      targetExitCode: session.targetExitCode,
      targetExitSignal: session.targetExitSignal
    }
  };
}

export function processTree(sessionId: string): ProcessTreeResponse {
  const tree = trees[sessionId];
  if (!tree) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };
  return tree;
}

export function sessionEvents(sessionId: string): EventView[] {
  return eventsBySession[sessionId] ?? [];
}

export function overview(recentLimit: number): OverviewResponse {
  return {
    totalSessions: sessions.length,
    activeSessions: 0,
    completedSessions: 1,
    interruptedSessions: 1,
    recoveredSessions: 0,
    failedSessions: 0,
    sessionsWithLoss: 0,
    recentSessions: sessions.slice(0, recentLimit),
    recentFindingCounts: {
      informational: 0,
      low: 1,
      medium: 0,
      high: 0,
      critical: 0,
      total: 1
    },
    latestVerification: sessions[1]?.verification ?? null
  };
}

export { analysisFor, verificationFor };

export function exportFor(sessionId: string): ExportResult {
  const session = sessions.find((item) => item.id === sessionId);
  if (!session) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };
  return {
    sessionId: session.id,
    outputPath: `/mock/evidence/exports/${session.id}.json`,
    formatVersion: "syscall-export/v1",
    bytesWritten: 64_138,
    manifest: [
      {
        component: "analysis",
        format: "application/json",
        version: "syscall-analysis/v1",
        sha256: "87bdb0b871a038d20c979ff152a",
        byteLength: 9_603
      },
      {
        component: "events",
        format: "application/json",
        version: "1",
        sha256: "3c8dcb59497f10d4f7f9525057",
        byteLength: 44_763
      },
      {
        component: "manifest",
        format: "application/json",
        version: "1",
        sha256: "0871cbf767819413c686c9925",
        byteLength: 1_378
      },
      {
        component: "metadata",
        format: "application/json",
        version: "1",
        sha256: "f2bc1647c0e7969687af8ba5a8",
        byteLength: 839
      },
      {
        component: "process_instances",
        format: "application/json",
        version: "1",
        sha256: "4de7ae3656018dcf5f45da02",
        byteLength: 1_789
      },
      {
        component: "session",
        format: "application/json",
        version: "1",
        sha256: "4030ba5be888f2b14137a253",
        byteLength: 1_033
      },
      {
        component: "verification",
        format: "application/json",
        version: "1",
        sha256: "00cfb4f507f0bc43a46a65af",
        byteLength: 311
      }
    ],
    status: "exported"
  };
}

export function processFor(sessionId: string, processInstanceId: string): ProcessView | null {
  return trees[sessionId]?.processes.find((item) => item.processInstanceId === processInstanceId) ?? null;
}
