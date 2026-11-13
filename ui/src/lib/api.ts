import type {
  AnalysisReport,
  ApiError,
  AppInfo,
  ConnectionResponse,
  EventType,
  EventView,
  EvidenceDetail,
  ExportResult,
  FileActivityResponse,
  OverviewResponse,
  ProcessTreeResponse,
  SessionDetail,
  SessionListResponse,
  SessionVerificationReport,
  TimelineResponse
} from "../types/contracts";
import {
  analysisFor,
  appInfo,
  exportFor,
  overview,
  processTree,
  sessionDetail,
  sessionEvents,
  sessions,
  verificationFor
} from "../mock/data";

/*
 * Standalone UI adapter.
 *
 * This file is the only data boundary in the preview application. It returns
 * deterministic in-memory evidence so the interface can run with plain Vite.
 * The production workstation uses desktop/src/lib/api.ts, which calls Tauri
 * commands instead. When this UI is returned, only this adapter needs to be
 * replaced (or its methods pointed at the real IPC layer).
 */

export interface SessionQuery {
  limit?: number;
  search?: string;
  status?: string;
  sortBy?: "started" | "status" | "events" | "processes" | "findings" | "verification";
  sortDirection?: "asc" | "desc";
  includeIntelligence?: boolean;
}

export interface TimelineQuery {
  sessionId: string;
  eventType?: EventType;
  pid?: number;
  processInstanceId?: string;
  fromNs?: number;
  toNs?: number;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface ActivityQuery {
  sessionId: string;
  pid?: number;
  processInstanceId?: string;
  fromNs?: number;
  toNs?: number;
  success?: boolean;
  family?: "ipv4" | "ipv6";
  search?: string;
  limit?: number;
  offset?: number;
}

export function isApiError(value: unknown): value is ApiError {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as ApiError).code === "string" &&
    typeof (value as ApiError).message === "string"
  );
}

export function errorMessage(value: unknown): string {
  if (isApiError(value)) return value.message;
  if (value instanceof Error) return value.message;
  if (typeof value === "string") return value;
  return "The preview adapter returned an unexpected error.";
}

function resolve<T>(value: T, delay = 110): Promise<T> {
  return new Promise((done) => window.setTimeout(() => done(value), delay));
}

function eventSummary(event: EventView): string {
  switch (event.payload.kind) {
    case "file_open":
      return event.payload.path;
    case "network_connect":
      return `${event.payload.destinationAddress}:${event.payload.destinationPort}`;
    case "process_exec":
      return event.payload.filename;
    case "process_fork":
      return `${event.payload.childComm} (pid ${event.payload.childPid})`;
    case "process_exit":
      return `exit ${event.payload.exitPriority}`;
    default:
      return event.eventType;
  }
}

function matchesEvent(event: EventView, query: TimelineQuery): boolean {
  if (query.eventType && event.eventType !== query.eventType) return false;
  if (query.pid !== undefined && event.pid !== query.pid) return false;
  if (query.processInstanceId && event.processInstanceId !== query.processInstanceId) return false;
  if (query.fromNs !== undefined && event.timestampNs < query.fromNs) return false;
  if (query.toNs !== undefined && event.timestampNs > query.toNs) return false;
  if (query.search) {
    const needle = query.search.toLowerCase();
    const haystack = `${event.comm} ${event.eventType} ${eventSummary(event)} ${JSON.stringify(
      event.payload
    )}`.toLowerCase();
    if (!haystack.includes(needle)) return false;
  }
  return true;
}

function matchingEvents(query: TimelineQuery): EventView[] {
  return sessionEvents(query.sessionId).filter((event) => matchesEvent(event, query));
}

export const api = {
  appInfo: () => resolve(appInfo, 40),

  overview: (recentLimit = 8) => resolve<OverviewResponse>(overview(recentLimit)),

  listSessions: (query: SessionQuery = {}) => {
    const needle = query.search?.trim().toLowerCase() ?? "";
    let rows = sessions.filter((session) => {
      if (query.status && session.status !== query.status) return false;
      if (!needle) return true;
      return `${session.id} ${session.commandDisplay}`.toLowerCase().includes(needle);
    });

    const direction = query.sortDirection === "asc" ? 1 : -1;
    const sortBy = query.sortBy ?? "started";
    rows = [...rows].sort((left, right) => {
      switch (sortBy) {
        case "status":
          return left.status.localeCompare(right.status) * direction;
        case "events":
          return (left.eventCount - right.eventCount) * direction;
        case "processes":
          return (left.processCount - right.processCount) * direction;
        case "findings":
          return ((left.findingCounts?.total ?? 0) - (right.findingCounts?.total ?? 0)) * direction;
        case "verification":
          return (
            (left.verification?.assessment ?? "").localeCompare(
              right.verification?.assessment ?? ""
            ) * direction
          );
        case "started":
        default:
          return (left.startedAtNs - right.startedAtNs) * direction;
      }
    });

    const limited = rows.slice(0, query.limit ?? 100);
    return resolve<SessionListResponse>({
      sessions: limited,
      totalMatched: rows.length,
      intelligenceLimited: false
    });
  },

  getSession: (sessionId: string) => resolve<SessionDetail>(sessionDetail(sessionId)),

  listProcesses: (sessionId: string) => resolve<ProcessTreeResponse>(processTree(sessionId)),

  timeline: (query: TimelineQuery) => {
    const all = matchingEvents(query);
    const offset = query.offset ?? 0;
    const limit = query.limit ?? 100;
    const page = all.slice(offset, offset + limit);
    return resolve<TimelineResponse>({
      events: page,
      total: all.length,
      limit,
      offset,
      hasMore: offset + page.length < all.length,
      evidenceIncomplete: query.sessionId === "mock-interrupt-002"
    });
  },

  filesystem: (query: ActivityQuery) => {
    const all = matchingEvents(query)
      .filter((event) => event.payload.kind === "file_open")
      .map((event) => {
        if (event.payload.kind !== "file_open") throw new Error("unreachable");
        return {
          eventId: event.id,
          timestampNs: event.timestampNs,
          pid: event.pid,
          processInstanceId: event.processInstanceId,
          comm: event.comm,
          path: event.payload.path,
          pathIsAbsolute: event.payload.pathIsAbsolute,
          pathTruncated: event.payload.pathTruncated,
          dirfd: event.payload.dirfd,
          flags: event.payload.flags,
          result: event.payload.result,
          success: event.payload.success,
          errno: event.payload.errno
        };
      })
      .filter((row) => query.success === undefined || row.success === query.success);
    const offset = query.offset ?? 0;
    const limit = query.limit ?? 100;
    const page = all.slice(offset, offset + limit);
    return resolve<FileActivityResponse>({
      files: page,
      total: all.length,
      limit,
      offset,
      hasMore: offset + page.length < all.length,
      evidenceIncomplete: query.sessionId === "mock-interrupt-002"
    });
  },

  network: (query: ActivityQuery) => {
    const all = matchingEvents(query)
      .filter((event) => event.payload.kind === "network_connect")
      .map((event) => {
        if (event.payload.kind !== "network_connect") throw new Error("unreachable");
        return {
          eventId: event.id,
          timestampNs: event.timestampNs,
          pid: event.pid,
          processInstanceId: event.processInstanceId,
          comm: event.comm,
          family: event.payload.family,
          sourceAddress: event.payload.sourceAddress,
          sourcePort: event.payload.sourcePort,
          destinationAddress: event.payload.destinationAddress,
          destinationPort: event.payload.destinationPort,
          result: event.payload.result,
          success: event.payload.success,
          errno: event.payload.errno,
          established: event.payload.established
        };
      })
      .filter((row) => query.family === undefined || row.family === query.family)
      .filter((row) => query.success === undefined || row.success === query.success);
    const offset = query.offset ?? 0;
    const limit = query.limit ?? 100;
    const page = all.slice(offset, offset + limit);
    return resolve<ConnectionResponse>({
      connections: page,
      total: all.length,
      limit,
      offset,
      hasMore: offset + page.length < all.length,
      evidenceIncomplete: query.sessionId === "mock-interrupt-002"
    });
  },

  event: (sessionId: string, eventId: number) => {
    const found = sessionEvents(sessionId).find((event) => event.id === eventId);
    if (!found) {
      return Promise.reject<EvidenceDetail>({
        code: "EVENT_NOT_FOUND",
        message: "The selected event is not present in mock evidence."
      });
    }
    return resolve<EvidenceDetail>({ event: found });
  },

  analysis: (sessionId: string) => resolve<AnalysisReport>(analysisFor(sessionId), 240),

  verification: (sessionId: string) =>
    resolve<SessionVerificationReport>(verificationFor(sessionId), 200),

  exportSession: (sessionId: string, _force = false) =>
    resolve<ExportResult>(exportFor(sessionId), 650)
};
