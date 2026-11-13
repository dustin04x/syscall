import type { ReactNode } from "react";

import type {
  AnalysisConfidence,
  AnalysisSeverity,
  FindingSeverity,
  SessionStatus,
  VerificationAssessment
} from "../../types/contracts";
import {
  assessmentLabel,
  confidenceLabel,
  severityLabel,
  statusLabel
} from "../../lib/format";

/* Status is a glyph and a word — never a pill. The glyph carries the tone. */
export function Mark({
  tone,
  children,
  className = ""
}: {
  tone: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span className={`mark ${className}`.trim()} data-tone={tone}>
      <span className="mark-glyph" aria-hidden="true" />
      {children}
    </span>
  );
}

export function StatusBadge({ status }: { status: SessionStatus }) {
  return <Mark tone={status}>{statusLabel(status)}</Mark>;
}

export function AssessmentBadge({ assessment }: { assessment: VerificationAssessment }) {
  return <Mark tone={assessment}>{assessmentLabel(assessment)}</Mark>;
}

export function SeverityBadge({ severity }: { severity: AnalysisSeverity | FindingSeverity }) {
  return <Mark tone={severity}>{severityLabel(severity)}</Mark>;
}

export function ConfidenceBadge({ confidence }: { confidence: AnalysisConfidence }) {
  return <span className="tag">{confidenceLabel(confidence)} confidence</span>;
}

export function Tag({
  tone,
  children
}: {
  tone?: "accent" | "warning" | "error" | "ok";
  children: ReactNode;
}) {
  return <span className={`tag ${tone ? `tag-${tone}` : ""}`.trim()}>{children}</span>;
}
