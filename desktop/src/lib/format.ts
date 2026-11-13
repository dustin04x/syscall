import type {
  AnalysisConfidence,
  AnalysisSeverity,
  FindingSeverity,
  SessionStatus,
  VerificationAssessment
} from "../types/contracts";

export function formatTimestamp(ns: number | null | undefined): string {
  if (ns == null) return "—";
  const date = new Date(ns / 1_000_000);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toISOString().replace("T", " ").replace("Z", "")} UTC`;
}

export function formatTimestampShort(ns: number | null | undefined): string {
  if (ns == null) return "—";
  const date = new Date(ns / 1_000_000);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toISOString().replace("T", " ").slice(0, 23);
}

export function formatDuration(ns: number | null | undefined): string {
  if (ns == null) return "—";
  if (ns < 1_000) return `${ns}ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)}µs`;
  if (ns < 1_000_000_000) return `${(ns / 1_000_000).toFixed(2)}ms`;
  const seconds = ns / 1_000_000_000;
  if (seconds < 60) return `${seconds.toFixed(2)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatFlags(flags: number): string {
  return `0x${flags.toString(16).padStart(8, "0")}`;
}

export function truncateMiddle(value: string, max = 56): string {
  if (value.length <= max) return value;
  const half = Math.floor((max - 1) / 2);
  return `${value.slice(0, half)}…${value.slice(-half)}`;
}

export function parseUtcInput(value: string): number | null {
  if (!value) return null;
  const normalized = value.length === 16 ? `${value}:00Z` : `${value}Z`;
  const millis = Date.parse(normalized);
  return Number.isNaN(millis) ? null : millis * 1_000_000;
}

export function statusLabel(status: SessionStatus): string {
  switch (status) {
    case "starting":
      return "Starting";
    case "recording":
      return "Recording";
    case "completed":
      return "Completed";
    case "interrupted":
      return "Interrupted";
    case "failed":
      return "Failed";
    case "recovered":
      return "Recovered";
    default:
      return "Unknown";
  }
}

export function assessmentLabel(assessment: VerificationAssessment): string {
  switch (assessment) {
    case "valid":
      return "Valid";
    case "valid_but_incomplete":
      return "Valid, incomplete";
    case "warning":
      return "Warning";
    case "invalid":
      return "Invalid";
    default:
      return "Unable to verify";
  }
}

export function severityLabel(severity: AnalysisSeverity | FindingSeverity): string {
  if (severity === "informational") return "Informational";
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

export function confidenceLabel(confidence: AnalysisConfidence): string {
  return confidence.charAt(0).toUpperCase() + confidence.slice(1);
}

export function verificationRank(assessment: VerificationAssessment): number {
  switch (assessment) {
    case "invalid":
      return 4;
    case "unable_to_verify":
      return 3;
    case "warning":
      return 2;
    case "valid_but_incomplete":
      return 1;
    case "valid":
      return 0;
  }
}
