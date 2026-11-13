import type {
  AnalysisReport,
  AppInfo,
  EventView,
  ExportResult,
  ProcessTreeResponse,
  SessionDetail,
  SessionVerificationReport,
  SessionView,
  TimelineResponse
} from "../types/contracts";

export const appInfo: AppInfo = {
  contractVersion: "2",
  appVersion: "0.1.0",
  databasePath: "/home/investigator/.local/share/syscall/syscall.db",
  databaseExists: true,
  readOnly: true,
  exportDirectory: "/home/investigator/.local/share/syscall/exports",
  recordingSupported: false
};

export const session: SessionView = {
  id: "phase7-session-001",
  status: "completed",
  command: "/usr/bin/curl",
  arguments: ["--silent", "https://example.test"],
  commandDisplay: "/usr/bin/curl --silent https://example.test",
  recordingScope: "target-tree",
  startedAtNs: 1_760_000_000_000_000_000,
  endedAtNs: 1_760_000_001_500_000_000,
  durationNs: 1_500_000_000,
  processCount: 2,
  eventCount: 3,
  droppedEvents: 0,
  ringbufLostEvents: 0,
  userspaceDroppedEvents: 0,
  malformedEvents: 0,
  filteredEvents: 0,
  persistFailedEvents: 0,
  evidenceIncomplete: false,
  targetExitCode: 0,
  targetExitSignal: null,
  terminationReason: "target exited",
  error: null,
  kernelRelease: "6.6.87.2-microsoft-standard-WSL2",
  collectorVersion: "0.1.0",
  verification: {
    assessment: "valid_but_incomplete",
    counts: { info: 1, warning: 1, error: 0, critical: 0 },
    totalFindings: 2,
    limitations: ["Only persisted events can be verified."]
  },
  findingCounts: {
    informational: 0,
    low: 1,
    medium: 0,
    high: 0,
    critical: 0,
    total: 1
  },
  intelligenceError: null
};

export const sessionDetail: SessionDetail = {
  session,
  stats: {
    eventCount: 3,
    processCount: 2,
    eventsPersisted: 3,
    eventsByType: [
      { eventType: "process_exec", count: 1 },
      { eventType: "file_open", count: 1 },
      { eventType: "network_connect", count: 1 }
    ],
    ringbufLostEvents: 0,
    userspaceDroppedEvents: 0,
    droppedEventsTotal: 0,
    malformedEvents: 0,
    filteredEvents: 0,
    eventsPersistFailed: 0,
    eventsSelfFiltered: 0,
    unresolvedIdentityCount: 0,
    evidenceMayBeIncomplete: false,
    terminationReason: "target exited",
    targetExitCode: 0,
    targetExitSignal: null
  }
};

export const event: EventView = {
  id: 42,
  eventType: "file_open",
  timestampNs: 1_760_000_000_500_000_000,
  monotonicNs: 9_000_000_000,
  pid: 4100,
  tid: 4100,
  uid: 1000,
  gid: 1000,
  ppid: 4000,
  comm: "curl",
  processInstanceId: "proc-4100",
  payload: {
    kind: "file_open",
    path: "/etc/ssl/certs/ca-certificates.crt",
    pathIsAbsolute: true,
    pathTruncated: false,
    dirfd: -100,
    flags: 524288,
    result: 3,
    success: true,
    errno: null
  },
  provenance: {
    rawBpfPid: 4100,
    rawBpfTgid: 4100,
    observerPid: 4000,
    observerTgid: 4000,
    sourceTracepoint: "sys_enter_openat",
    wireSchemaVersion: 1,
    attributionMethod: "process_instance",
    timestampClockDomain: "realtime",
    monotonicClockDomain: "monotonic"
  }
};

export const processTree: ProcessTreeResponse = {
  processes: [
    {
      processInstanceId: "proc-4000",
      pid: 4000,
      comm: "curl",
      executable: "/usr/bin/curl",
      commandLine: "/usr/bin/curl --silent https://example.test",
      firstSeenNs: 1_760_000_000_000_000_000,
      lastSeenNs: 1_760_000_001_400_000_000,
      eventCount: 2,
      exitObserved: false,
      exitPriority: null,
      parentPid: null,
      parentProcessInstanceId: null,
      identityUnresolved: false,
      ancestryUnresolved: false,
      notes: [],
      childInstanceIds: ["proc-4100"],
      relationship: "root"
    },
    {
      processInstanceId: "proc-4100",
      pid: 4100,
      comm: "sh",
      executable: "/usr/bin/dash",
      commandLine: "/bin/sh -c true",
      firstSeenNs: 1_760_000_000_400_000_000,
      lastSeenNs: 1_760_000_001_000_000_000,
      eventCount: 1,
      exitObserved: true,
      exitPriority: 0,
      parentPid: 4000,
      parentProcessInstanceId: "proc-4000",
      identityUnresolved: false,
      ancestryUnresolved: false,
      notes: [],
      childInstanceIds: [],
      relationship: "observed"
    }
  ],
  roots: ["proc-4000"],
  unresolvedAncestryCount: 0,
  identityUnresolvedCount: 0,
  notes: []
};

export const timeline: TimelineResponse = {
  events: [event],
  total: 1,
  limit: 100,
  offset: 0,
  hasMore: false,
  evidenceIncomplete: false
};

export const analysisReport: AnalysisReport = {
  schema_version: "syscall-analysis/v1",
  session_id: session.id,
  session_command: session.commandDisplay,
  session_scope: "target-tree",
  session_started_at_ns: session.startedAtNs,
  session_ended_at_ns: session.endedAtNs,
  evidence: {
    status: "complete",
    session_status: "completed",
    event_count: 3,
    process_count: 2,
    ringbuf_lost_events: 0,
    userspace_dropped_events: 0,
    malformed_events: 0,
    filtered_events: 0,
    events_persist_failed: 0,
    unresolved_identity_count: 0,
    verification_assessment: "valid_but_incomplete",
    may_be_incomplete: false,
    notes: []
  },
  rules_evaluated: [
    {
      rule_id: "NET-001",
      version: 1,
      title: "Network connect from short-lived process",
      description: "A process initiated an outbound connection during a short observed lifetime.",
      conditions: ["A network_connect event is attributed to the process instance."],
      required_evidence: ["network_connect event", "process instance"],
      exclusions: [],
      known_false_positives: ["Package managers and health checks."],
      severity_rationale: "Low severity because the behavior is common.",
      confidence_rationale: "High confidence in the observation, not intent.",
      default_severity: "low",
      default_confidence: "high"
    }
  ],
  findings: [
    {
      finding_id: "finding-001",
      rule_id: "NET-001",
      rule_version: 1,
      severity: "low",
      confidence: "high",
      title: "Outbound connection from short-lived curl process",
      explanation: "curl attempted an outbound connection during its observed lifetime.",
      significance: "Outbound access is expected behavior for a network client but should be correlated.",
      event_ids: [42],
      process_instance_ids: ["proc-4100"],
      pids: [4100],
      time_range: {
        start_ns: 1_760_000_000_500_000_000,
        end_ns: 1_760_000_000_900_000_000
      },
      related_findings: [],
      limitations: ["The connection attempt does not prove data transfer."],
      next_steps: ["Review the destination and process command line."],
      supporting_events: [
        {
          event_id: 42,
          timestamp_ns: 1_760_000_000_500_000_000,
          monotonic_ns: 9_000_000_000,
          event_type: "file_open",
          pid: 4100,
          process_instance_id: "proc-4100",
          comm: "curl",
          summary: "/etc/ssl/certs/ca-certificates.crt"
        }
      ],
      related_processes: [
        {
          process_instance_id: "proc-4100",
          pid: 4100,
          comm: "curl",
          executable: "/usr/bin/curl",
          parent_process_instance_id: "proc-4000",
          exit_observed: true
        }
      ],
      correlation: "single_event"
    }
  ],
  limitations: ["Analysis is limited to persisted evidence."],
  truncated: false
};

export const verificationReport: SessionVerificationReport = {
  session_id: session.id,
  verification_timestamp_ns: 1_760_000_002_000_000_000,
  database_schema_version: 5,
  session_status: "completed",
  assessment: "valid_but_incomplete",
  severity_counts: { info: 1, warning: 1, error: 0, critical: 0 },
  findings: [
    {
      code: "VER-COMPLETENESS",
      severity: "warning",
      title: "Evidence coverage is incomplete",
      detail: "The session did not observe a complete process lifetime.",
      session_id: session.id,
      event_id: 42,
      process_instance_id: "proc-4100",
      evidence: ["event 42"],
      recommendation: "Review the session scope and evidence loss counters."
    }
  ],
  limitations: ["Verification does not prove authenticity."]
};

export const exportResult: ExportResult = {
  sessionId: session.id,
  outputPath: `/home/investigator/.local/share/syscall/exports/${session.id}.json`,
  formatVersion: "syscall-export/v2",
  bytesWritten: 8192,
  manifest: [
    {
      component: "events",
      format: "application/json",
      version: "1",
      sha256: "a".repeat(64),
      byteLength: 4096
    }
  ],
  status: "exported"
};
