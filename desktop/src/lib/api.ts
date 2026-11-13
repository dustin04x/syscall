import { invoke } from "@tauri-apps/api/core";

import type {
  AnalysisReport,
  ApiError,
  AppInfo,
  ConnectionResponse,
  EventType,
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
  return "The backend returned an unexpected error.";
}

export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw isApiError(error) ? error : { code: "IPC_ERROR", message: errorMessage(error) };
  }
}

export const api = {
  appInfo: () => call<AppInfo>("app_info"),

  overview: (recentLimit = 8) =>
    call<OverviewResponse>("get_overview", { request: { recentLimit } }),

  listSessions: (query: SessionQuery = {}) =>
    call<SessionListResponse>("list_sessions", { request: query }),

  getSession: (sessionId: string) =>
    call<SessionDetail>("get_session", { request: { sessionId } }),

  listProcesses: (sessionId: string) =>
    call<ProcessTreeResponse>("list_processes", { request: { sessionId } }),

  timeline: (query: TimelineQuery) =>
    call<TimelineResponse>("query_timeline", { request: query }),

  filesystem: (query: ActivityQuery) =>
    call<FileActivityResponse>("query_filesystem", { request: query }),

  network: (query: ActivityQuery) =>
    call<ConnectionResponse>("query_network", { request: query }),

  event: (sessionId: string, eventId: number) =>
    call<EvidenceDetail>("get_event", { request: { sessionId, eventId } }),

  analysis: (sessionId: string) =>
    call<AnalysisReport>("run_analysis", { request: { sessionId } }),

  verification: (sessionId: string) =>
    call<SessionVerificationReport>("run_verification", { request: { sessionId } }),

  exportSession: (sessionId: string, force = false) =>
    call<ExportResult>("export_session", { request: { sessionId, force } })
};
