export type SessionStatus =
  | "starting"
  | "recording"
  | "completed"
  | "interrupted"
  | "failed"
  | "recovered"
  | "unknown";

export type VerificationAssessment =
  | "valid"
  | "valid_but_incomplete"
  | "warning"
  | "invalid"
  | "unable_to_verify";

export type AnalysisSeverity =
  | "informational"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type AnalysisConfidence = "low" | "medium" | "high";
export type EventType =
  | "process_exec"
  | "process_fork"
  | "process_exit"
  | "file_open"
  | "network_connect";
export type FindingSeverity = "info" | "warning" | "error" | "critical";

export interface AppInfo {
  contractVersion: string;
  appVersion: string;
  databasePath: string;
  databaseExists: boolean;
  readOnly: boolean;
  exportDirectory: string;
  recordingSupported: boolean;
}

export interface SeverityCounts {
  info: number;
  warning: number;
  error: number;
  critical: number;
}

export interface FindingCounts {
  informational: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
  total: number;
}

export interface VerificationSummary {
  assessment: VerificationAssessment;
  counts: SeverityCounts;
  totalFindings: number;
  limitations: string[];
}

export interface SessionView {
  id: string;
  status: SessionStatus;
  command: string;
  arguments: string[];
  commandDisplay: string;
  recordingScope: "target-tree" | "system";
  startedAtNs: number;
  endedAtNs: number | null;
  durationNs: number | null;
  processCount: number;
  eventCount: number;
  droppedEvents: number;
  ringbufLostEvents: number;
  userspaceDroppedEvents: number;
  malformedEvents: number;
  filteredEvents: number;
  persistFailedEvents: number;
  evidenceIncomplete: boolean;
  targetExitCode: number | null;
  targetExitSignal: number | null;
  terminationReason: string | null;
  error: string | null;
  kernelRelease: string | null;
  collectorVersion: string | null;
  verification: VerificationSummary | null;
  findingCounts: FindingCounts | null;
  intelligenceError: string | null;
}

export interface SessionListResponse {
  sessions: SessionView[];
  totalMatched: number;
  intelligenceLimited: boolean;
}

export interface OverviewResponse {
  totalSessions: number;
  activeSessions: number;
  completedSessions: number;
  interruptedSessions: number;
  recoveredSessions: number;
  failedSessions: number;
  sessionsWithLoss: number;
  recentSessions: SessionView[];
  recentFindingCounts: FindingCounts;
  latestVerification: VerificationSummary | null;
}

export interface EventTypeCount {
  eventType: EventType;
  count: number;
}

export interface SessionStats {
  eventCount: number;
  processCount: number;
  eventsPersisted: number;
  eventsByType: EventTypeCount[];
  ringbufLostEvents: number;
  userspaceDroppedEvents: number;
  droppedEventsTotal: number;
  malformedEvents: number;
  filteredEvents: number;
  eventsSelfFiltered: number;
  eventsPersistFailed: number;
  unresolvedIdentityCount: number;
  evidenceMayBeIncomplete: boolean;
  terminationReason: string | null;
  targetExitCode: number | null;
  targetExitSignal: number | null;
}

export interface SessionDetail {
  session: SessionView;
  stats: SessionStats;
}

export interface ProcessView {
  processInstanceId: string;
  pid: number;
  comm: string;
  executable: string | null;
  commandLine: string | null;
  firstSeenNs: number;
  lastSeenNs: number;
  eventCount: number;
  exitObserved: boolean;
  exitPriority: number | null;
  parentPid: number | null;
  parentProcessInstanceId: string | null;
  identityUnresolved: boolean;
  ancestryUnresolved: boolean;
  notes: string[];
  childInstanceIds: string[];
  relationship: "observed" | "unresolved" | "root";
}

export interface ProcessTreeResponse {
  processes: ProcessView[];
  roots: string[];
  unresolvedAncestryCount: number;
  identityUnresolvedCount: number;
  notes: string[];
}

export interface ProvenanceView {
  rawBpfPid: number | null;
  rawBpfTgid: number | null;
  observerPid: number | null;
  observerTgid: number | null;
  sourceTracepoint: string | null;
  wireSchemaVersion: number | null;
  attributionMethod: string | null;
  timestampClockDomain: string | null;
  monotonicClockDomain: string | null;
}

export type EventPayload =
  | {
      kind: "process_exec";
      filename: string;
      ppid: number | null;
      startTimeTicks: number | null;
      oldPid: number | null;
    }
  | {
      kind: "process_fork";
      parentPid: number;
      parentTgid: number | null;
      childPid: number;
      childComm: string;
      childStartTimeTicks: number | null;
    }
  | {
      kind: "process_exit";
      ppid: number | null;
      startTimeTicks: number | null;
      exitPriority: number;
    }
  | {
      kind: "file_open";
      path: string;
      pathIsAbsolute: boolean;
      pathTruncated: boolean;
      dirfd: number;
      flags: number;
      result: number;
      success: boolean;
      errno: number | null;
    }
  | {
      kind: "network_connect";
      family: "ipv4" | "ipv6";
      sourceAddress: string | null;
      sourcePort: number | null;
      destinationAddress: string;
      destinationPort: number;
      result: number;
      success: boolean;
      errno: number | null;
      established: boolean;
    };

export interface EventView {
  id: number;
  eventType: EventType;
  timestampNs: number;
  monotonicNs: number;
  pid: number;
  tid: number;
  uid: number;
  gid: number;
  ppid: number | null;
  comm: string;
  processInstanceId: string;
  payload: EventPayload;
  provenance: ProvenanceView | null;
}

export interface TimelineResponse {
  events: EventView[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
  evidenceIncomplete: boolean;
}

export interface FileActivityView {
  eventId: number;
  timestampNs: number;
  pid: number;
  processInstanceId: string;
  comm: string;
  path: string;
  pathIsAbsolute: boolean;
  pathTruncated: boolean;
  dirfd: number;
  flags: number;
  result: number;
  success: boolean;
  errno: number | null;
}

export interface FileActivityResponse {
  files: FileActivityView[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
  evidenceIncomplete: boolean;
}

export interface ConnectionView {
  eventId: number;
  timestampNs: number;
  pid: number;
  processInstanceId: string;
  comm: string;
  family: "ipv4" | "ipv6";
  sourceAddress: string | null;
  sourcePort: number | null;
  destinationAddress: string;
  destinationPort: number;
  result: number;
  success: boolean;
  errno: number | null;
  established: boolean;
}

export interface ConnectionResponse {
  connections: ConnectionView[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
  evidenceIncomplete: boolean;
}

export interface EvidenceDetail {
  event: EventView;
}

export interface EvidenceCompleteness {
  status: string;
  session_status: string;
  event_count: number;
  process_count: number;
  ringbuf_lost_events: number;
  userspace_dropped_events: number;
  malformed_events: number;
  filtered_events: number;
  events_persist_failed: number;
  unresolved_identity_count: number;
  verification_assessment: string | null;
  may_be_incomplete: boolean;
  notes: string[];
}

export interface AnalysisTimeRange {
  start_ns: number;
  end_ns: number;
}

export interface SupportingEvent {
  event_id: number;
  timestamp_ns: number;
  monotonic_ns: number;
  event_type: EventType;
  pid: number;
  process_instance_id: string;
  comm: string;
  summary: string;
}

export interface AnalysisProcessRef {
  process_instance_id: string;
  pid: number;
  comm: string;
  executable: string | null;
  parent_process_instance_id: string | null;
  exit_observed: boolean;
}

export interface AnalysisFinding {
  finding_id: string;
  rule_id: string;
  rule_version: number;
  severity: AnalysisSeverity;
  confidence: AnalysisConfidence;
  title: string;
  explanation: string;
  significance: string;
  event_ids: number[];
  process_instance_ids: string[];
  pids: number[];
  time_range: AnalysisTimeRange;
  related_findings: string[];
  limitations: string[];
  next_steps: string[];
  supporting_events: SupportingEvent[];
  related_processes: AnalysisProcessRef[];
  correlation: string;
}

export interface AnalysisRuleMetadata {
  rule_id: string;
  version: number;
  title: string;
  description: string;
  conditions: string[];
  required_evidence: string[];
  exclusions: string[];
  known_false_positives: string[];
  severity_rationale: string;
  confidence_rationale: string;
  default_severity: AnalysisSeverity;
  default_confidence: AnalysisConfidence;
}

export interface AnalysisReport {
  schema_version: string;
  session_id: string;
  session_command: string;
  session_scope: string;
  session_started_at_ns: number;
  session_ended_at_ns: number | null;
  evidence: EvidenceCompleteness;
  rules_evaluated: AnalysisRuleMetadata[];
  findings: AnalysisFinding[];
  limitations: string[];
  truncated: boolean;
}

export interface VerificationFinding {
  code: string;
  severity: FindingSeverity;
  title: string;
  detail: string;
  session_id: string | null;
  event_id: number | null;
  process_instance_id: string | null;
  evidence: string[];
  recommendation: string;
}

export interface SessionVerificationReport {
  session_id: string;
  verification_timestamp_ns: number;
  database_schema_version: number;
  session_status: string | null;
  assessment: VerificationAssessment;
  severity_counts: SeverityCounts;
  findings: VerificationFinding[];
  limitations: string[];
}

export interface ExportManifestEntry {
  component: string;
  format: string;
  version: string;
  sha256: string;
  byteLength: number;
}

export interface ExportResult {
  sessionId: string;
  outputPath: string;
  formatVersion: string;
  bytesWritten: number;
  manifest: ExportManifestEntry[];
  status: "exported";
}

export interface ApiError {
  code: string;
  message: string;
}
