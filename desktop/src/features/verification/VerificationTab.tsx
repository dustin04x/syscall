import { useMemo, useState, type CSSProperties } from "react";
import { ChevronRight } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { api } from "../../lib/api";
import { assessmentLabel, formatNumber, formatTimestamp } from "../../lib/format";
import { investigationPath } from "../../lib/routes";
import type { FindingSeverity, VerificationFinding } from "../../types/contracts";
import { SeverityBadge, Tag } from "../../components/ui/Badges";
import { SelectField } from "../../components/ui/Fields";
import { ErrorState, LoadingState, Notice } from "../../components/ui/States";

export function VerificationTab({
  sessionId,
  navigate
}: {
  sessionId: string;
  navigate: (path: string) => void;
}) {
  const state = useAsync(() => api.verification(sessionId), [sessionId]);
  const [severity, setSeverity] = useState("");

  const findings = useMemo(() => {
    const report = state.data;
    if (!report) return [];
    return report.findings.filter((finding) => !severity || finding.severity === severity);
  }, [state.data, severity]);

  if (state.loading && !state.data) {
    return (
      <div className="panel" style={{ "--i": 0 } as CSSProperties}>
        <LoadingState label="Verifying schema and evidence chain" />
      </div>
    );
  }

  if (state.error || !state.data) {
    return (
      <div className="panel" style={{ "--i": 0 } as CSSProperties}>
        <ErrorState
          message={state.error ?? "No verification report was returned."}
          code="VERIFICATION_FAILED"
          onRetry={state.reload}
        />
      </div>
    );
  }

  const report = state.data;

  const assessmentNote =
    report.assessment === "valid"
      ? "Structural integrity checks passed. This does not prove the evidence is complete or that all activity was observed."
      : report.assessment === "valid_but_incomplete"
        ? "The evidence store is structurally valid, but collection counters or coverage gaps make the record incomplete."
        : report.assessment === "warning"
          ? "Verification completed with warnings. Review each finding before relying on this evidence."
          : report.assessment === "invalid"
            ? "At least one integrity check failed. Evidence should not be treated as trustworthy until the failure is explained."
            : "Verification could not reach a conclusion for this session. Treat confidence as limited.";

  return (
    <div className="stack">
      <section className="verdict stagger" data-tone={report.assessment} style={{ "--i": 0 } as CSSProperties}>
        <div className="verdict-label">verification assessment</div>
        <div className="verdict-word">{assessmentLabel(report.assessment)}</div>
        <p className="verdict-note">{assessmentNote}</p>
        <div className="verdict-facts">
          <div>
            <span>findings</span>
            <strong>{formatNumber(report.findings.length)}</strong>
          </div>
          <div>
            <span>error / critical</span>
            <strong>{report.severity_counts.error + report.severity_counts.critical}</strong>
          </div>
          <div>
            <span>warnings</span>
            <strong>{report.severity_counts.warning}</strong>
          </div>
          <div>
            <span>session status</span>
            <strong>{report.session_status ?? "unknown"}</strong>
          </div>
          <div>
            <span>db schema</span>
            <strong>{report.database_schema_version}</strong>
          </div>
          <div>
            <span>verified at</span>
            <strong>{formatTimestamp(report.verification_timestamp_ns).slice(11, 19)}</strong>
          </div>
        </div>
      </section>

      {report.assessment === "valid_but_incomplete" ||
      report.assessment === "warning" ||
      report.assessment === "invalid" ? (
        <Notice
          tone={report.assessment === "invalid" ? "critical" : "warning"}
          title={
            report.assessment === "invalid" ? "Integrity failure" : "Evidence is not fully reliable"
          }
        >
          {assessmentNote}
        </Notice>
      ) : null}

      <div className="ver-layout stagger">
        <section className="ver-findings" aria-label="Verification findings">
          <div className="panel-head">
            <h2 className="panel-title">verification findings</h2>
            <div style={{ width: 160 }}>
              <SelectField
                id="verification-severity"
                label="Severity"
                options={[
                  { value: "", label: "All findings" },
                  { value: "critical", label: "Critical" },
                  { value: "error", label: "Error" },
                  { value: "warning", label: "Warning" },
                  { value: "info", label: "Info" }
                ]}
                value={severity}
                onChange={(event) => setSeverity(event.target.value)}
              />
            </div>
          </div>
          {findings.length === 0 ? (
            <div className="state-block">
              <div className="state-title">
                {report.findings.length === 0 ? "No verification findings" : "No matches"}
              </div>
              <p className="state-body">
                {report.findings.length === 0
                  ? "This run found no schema, chain, or completeness issues in the persisted evidence."
                  : "Clear the severity filter to see the complete verification report."}
              </p>
            </div>
          ) : (
            findings.map((finding) => (
              <VerificationFindingRow
                key={`${finding.code}-${finding.event_id ?? finding.process_instance_id ?? finding.title}`}
                finding={finding}
                onEvent={(eventId) => navigate(investigationPath(sessionId, "timeline", eventId))}
                onProcess={(processId) =>
                  navigate(investigationPath(sessionId, "processes", null, processId))
                }
              />
            ))
          )}
          <div className="panel-note">
            Verification checks the stored record, not the truth of the underlying events.
            Collection loss and kernel visibility remain separate limitations.
          </div>
        </section>

        <aside className="ver-side" aria-label="Interpretation">
          <div className="ver-side-block">
            <div className="section-label" style={{ marginBottom: 10 }}>
              finding distribution
            </div>
            <div className="integrity-lines">
              <div className="integrity-line">
                <span className="integrity-dot bad" aria-hidden="true" />
                <span className="integrity-label">Critical</span>
                <span className="integrity-value">{report.severity_counts.critical}</span>
              </div>
              <div className="integrity-line">
                <span className="integrity-dot bad" aria-hidden="true" />
                <span className="integrity-label">Error</span>
                <span className="integrity-value">{report.severity_counts.error}</span>
              </div>
              <div className="integrity-line">
                <span className="integrity-dot warn" aria-hidden="true" />
                <span className="integrity-label">Warning</span>
                <span className="integrity-value">{report.severity_counts.warning}</span>
              </div>
              <div className="integrity-line">
                <span className="integrity-dot ok" aria-hidden="true" />
                <span className="integrity-label">Info</span>
                <span className="integrity-value">{report.severity_counts.info}</span>
              </div>
            </div>
          </div>
          <div className="ver-side-block">
            <div className="section-label" style={{ marginBottom: 10 }}>
              interpretation
            </div>
            <ul className="dotted-list">
              <li>
                <strong style={{ color: "var(--text)", fontWeight: 500 }}>Valid</strong> means
                structural checks passed, not that the session captured all activity.
              </li>
              <li>
                <strong style={{ color: "var(--text)", fontWeight: 500 }}>Valid but incomplete</strong>{" "}
                means storage integrity is intact while evidence coverage is not.
              </li>
              <li>
                <strong style={{ color: "var(--text)", fontWeight: 500 }}>Invalid</strong> indicates
                an integrity failure that requires investigation before reliance.
              </li>
              <li>Findings link to recorded events or process instances where available.</li>
            </ul>
          </div>
          {report.limitations.length > 0 ? (
            <div className="ver-side-block">
              <div className="section-label" style={{ marginBottom: 10 }}>
                report limitations
              </div>
              <ul className="dotted-list">
                {report.limitations.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </aside>
      </div>
    </div>
  );
}

function VerificationFindingRow({
  finding,
  onEvent,
  onProcess
}: {
  finding: VerificationFinding;
  onEvent: (eventId: number) => void;
  onProcess: (processId: string) => void;
}) {
  return (
    <article className="ver-finding">
      <div className="ver-finding-head">
        <SeverityBadge severity={finding.severity as FindingSeverity} />
        <div className="ver-finding-title">{finding.title}</div>
        <span className="ver-finding-code">{finding.code}</span>
      </div>
      <p className="ver-finding-detail">{finding.detail}</p>
      {finding.evidence.length > 0 ? (
        <div className="ver-evidence-tags">
          {finding.evidence.map((entry) => (
            <Tag key={entry}>{entry}</Tag>
          ))}
        </div>
      ) : null}
      <p className="ver-finding-detail">
        <span className="faint">Recommendation: </span>
        {finding.recommendation}
      </p>
      {finding.event_id != null || finding.process_instance_id ? (
        <div className="ver-actions">
          {finding.event_id != null ? (
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => onEvent(finding.event_id!)}>
              Inspect event #{finding.event_id} <ChevronRight size={10} aria-hidden="true" />
            </button>
          ) : null}
          {finding.process_instance_id ? (
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => onProcess(finding.process_instance_id!)}>
              Inspect process <ChevronRight size={10} aria-hidden="true" />
            </button>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}
