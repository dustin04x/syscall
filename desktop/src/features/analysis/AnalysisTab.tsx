import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { ChevronRight, Fingerprint } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { api } from "../../lib/api";
import { formatNumber, formatTimestampShort, severityLabel } from "../../lib/format";
import { investigationPath } from "../../lib/routes";
import type { AnalysisFinding, AnalysisReport } from "../../types/contracts";
import { ConfidenceBadge, SeverityBadge, Tag } from "../../components/ui/Badges";
import { SearchInput, SelectField } from "../../components/ui/Fields";
import { EmptyState, ErrorState, LoadingState, Notice } from "../../components/ui/States";

export function AnalysisTab({
  sessionId,
  navigate
}: {
  sessionId: string;
  navigate: (path: string) => void;
}) {
  const state = useAsync(() => api.analysis(sessionId), [sessionId]);
  const [severity, setSeverity] = useState("");
  const [confidence, setConfidence] = useState("");
  const [rule, setRule] = useState("");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const findings = useMemo(() => {
    const report = state.data;
    if (!report) return [];
    const query = search.trim().toLowerCase();
    return report.findings.filter(
      (finding) =>
        (!severity || finding.severity === severity) &&
        (!confidence || finding.confidence === confidence) &&
        (!rule || finding.rule_id === rule) &&
        (!query ||
          finding.title.toLowerCase().includes(query) ||
          finding.rule_id.toLowerCase().includes(query) ||
          finding.explanation.toLowerCase().includes(query))
    );
  }, [state.data, severity, confidence, rule, search]);

  useEffect(() => {
    if (findings.length === 0) {
      setSelectedId(null);
      return;
    }
    if (!selectedId || !findings.some((finding) => finding.finding_id === selectedId)) {
      setSelectedId(findings[0]?.finding_id ?? null);
    }
  }, [findings, selectedId]);

  const selected = findings.find((finding) => finding.finding_id === selectedId) ?? null;

  if (state.loading && !state.data) {
    return (
      <div className="panel" style={{ "--i": 0 } as CSSProperties}>
        <LoadingState label="Evaluating behavioral rules against recorded evidence" />
      </div>
    );
  }

  if (state.error || !state.data) {
    return (
      <div className="panel" style={{ "--i": 0 } as CSSProperties}>
        <ErrorState
          message={state.error ?? "No analysis report was returned."}
          code="ANALYSIS_FAILED"
          onRetry={state.reload}
        />
      </div>
    );
  }

  const report = state.data;
  const highCount = report.findings.filter(
    (finding) => finding.severity === "high" || finding.severity === "critical"
  ).length;

  return (
    <div className="stack">
      {report.evidence.may_be_incomplete ? (
        <Notice tone="warning" title="Analysis is bounded by incomplete evidence">
          Evidence completeness is qualified for this session. Rules can only evaluate persisted
          events; missing behavior may change the result. {report.evidence.notes[0] ?? ""}
        </Notice>
      ) : null}

      {report.truncated ? (
        <Notice tone="warning" title="Analysis output was truncated">
          The report exceeded its evidence bound. Review the full export and limitations before
          drawing conclusions from the finding list.
        </Notice>
      ) : null}

      <div className="report-band stagger" style={{ "--i": 1 } as CSSProperties} aria-label="Report summary">
        <div className="report-band-cell">
          <span className="micro">findings</span>
          <strong className="num">{formatNumber(report.findings.length)}</strong>
          <span>{report.rules_evaluated.length} rules evaluated</span>
        </div>
        <div className="report-band-cell">
          <span className="micro">high / critical</span>
          <strong className="num" style={highCount > 0 ? { color: "var(--error)" } : undefined}>
            {formatNumber(highCount)}
          </strong>
          <span>{highCount > 0 ? "requires investigator review" : "no high-severity matches"}</span>
        </div>
        <div className="report-band-cell">
          <span className="micro">evidence status</span>
          <strong style={report.evidence.may_be_incomplete ? { color: "var(--warning)" } : undefined}>
            {report.evidence.may_be_incomplete ? "incomplete" : "complete"}
          </strong>
          <span>
            {report.evidence.event_count} events · {report.evidence.process_count} processes
          </span>
        </div>
        <div className="report-band-cell">
          <span className="micro">verification</span>
          <strong>
            {report.evidence.verification_assessment
              ? report.evidence.verification_assessment.replaceAll("_", " ")
              : "not run"}
          </strong>
          <span>integrity posture supplied with this report</span>
        </div>
      </div>

      <div className="an-layout stagger" style={{ "--i": 2 } as CSSProperties}>
        <section className="an-list" aria-label="Behavioral findings">
          <div className="an-filters">
            <SearchInput
              id="finding-search"
              label="Search findings"
              placeholder="Search title, rule, or explanation…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <div className="row" style={{ gap: 8 }}>
              <SelectField
                id="severity-filter"
                label="Severity"
                options={[
                  { value: "", label: "All severity" },
                  { value: "critical", label: "Critical" },
                  { value: "high", label: "High" },
                  { value: "medium", label: "Medium" },
                  { value: "low", label: "Low" },
                  { value: "informational", label: "Informational" }
                ]}
                value={severity}
                onChange={(event) => setSeverity(event.target.value)}
              />
              <SelectField
                id="confidence-filter"
                label="Confidence"
                options={[
                  { value: "", label: "All confidence" },
                  { value: "high", label: "High" },
                  { value: "medium", label: "Medium" },
                  { value: "low", label: "Low" }
                ]}
                value={confidence}
                onChange={(event) => setConfidence(event.target.value)}
              />
            </div>
            <SelectField
              id="rule-filter"
              label="Rule"
              options={[
                { value: "", label: "All rules" },
                ...report.rules_evaluated.map((item) => ({
                  value: item.rule_id,
                  label: `${item.rule_id} · ${item.title}`
                }))
              ]}
              value={rule}
              onChange={(event) => setRule(event.target.value)}
            />
          </div>
          <div className="an-list-scroll">
            {findings.length === 0 ? (
              <EmptyState
                compact
                title={report.findings.length === 0 ? "No findings" : "No matches"}
                message={
                  report.findings.length === 0
                    ? "The current rule set matched no behavior in the persisted evidence."
                    : "Clear one or more finding filters to widen the result set."
                }
              />
            ) : (
              findings.map((finding) => (
                <button
                  type="button"
                  key={finding.finding_id}
                  className={`an-item ${selectedId === finding.finding_id ? "selected" : ""}`.trim()}
                  data-active={selectedId === finding.finding_id ? "true" : "false"}
                  onClick={() => setSelectedId(finding.finding_id)}
                >
                  <div className="an-item-top">
                    <SeverityBadge severity={finding.severity} />
                    <span className="mono faint" style={{ fontSize: 9 }}>
                      {finding.confidence}
                    </span>
                  </div>
                  <div className="an-item-title">{finding.title}</div>
                  <div className="an-item-meta">
                    {finding.rule_id} · {finding.event_ids.length} events
                    {finding.process_instance_ids.length > 0
                      ? ` · ${finding.process_instance_ids.length} procs`
                      : ""}
                  </div>
                </button>
              ))
            )}
          </div>
          <div className="panel-note">Findings are observations, not verdicts.</div>
        </section>

        {selected ? (
          <FindingDossier
            finding={selected}
            report={report}
            sessionId={sessionId}
            navigate={navigate}
          />
        ) : (
          <section className="an-dossier">
            <EmptyState
              icon={<Fingerprint size={14} />}
              title="No finding selected"
              message="Select a finding to inspect its explanation, evidence, related processes, and rule metadata."
            />
          </section>
        )}
      </div>

      <section aria-label="Evaluated rules" style={{ "--i": 3 } as CSSProperties}>
        <div className="section-label">evaluated rules</div>
        <div className="rule-grid stagger">
          {report.rules_evaluated.map((item) => (
            <article className="rule-card" key={item.rule_id}>
              <div className="row-between">
                <span className="rule-id">{item.rule_id}</span>
                <Tag>v{item.version}</Tag>
              </div>
              <div className="rule-title">{item.title}</div>
              <p className="rule-desc">{item.description}</p>
              <details className="rule-details">
                <summary>Rule conditions and limitations</summary>
                <ul className="dotted-list" style={{ marginTop: 7 }}>
                  {item.conditions.map((condition) => (
                    <li key={condition}>{condition}</li>
                  ))}
                  {item.known_false_positives.map((entry) => (
                    <li key={entry}>False positive: {entry}</li>
                  ))}
                </ul>
              </details>
            </article>
          ))}
        </div>
      </section>

      {report.limitations.length > 0 ? (
        <section className="panel" style={{ "--i": 4 } as CSSProperties}>
          <div className="panel-head">
            <h2 className="panel-title">report limitations</h2>
          </div>
          <div style={{ padding: "12px 14px" }}>
            <ul className="dotted-list">
              {report.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </div>
        </section>
      ) : null}
    </div>
  );
}

function FindingDossier({
  finding,
  report,
  sessionId,
  navigate
}: {
  finding: AnalysisFinding;
  report: AnalysisReport;
  sessionId: string;
  navigate: (path: string) => void;
}) {
  const rule = report.rules_evaluated.find((item) => item.rule_id === finding.rule_id);

  return (
    <article className="an-dossier" aria-label="Finding detail">
      <div className="an-dossier-head">
        <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
          <SeverityBadge severity={finding.severity} />
          <ConfidenceBadge confidence={finding.confidence} />
          <Tag>{finding.correlation.replaceAll("_", " ")}</Tag>
        </div>
        <h2 className="an-dossier-title">{finding.title}</h2>
        <div className="an-dossier-id">
          {finding.finding_id} · rule {finding.rule_id} v{finding.rule_version}
        </div>
      </div>

      <div className="detail-section" style={{ borderTop: 0 }}>
        <div className="detail-section-label">what was observed</div>
        <p className="an-text">{finding.explanation}</p>
      </div>

      <div className="detail-section">
        <div className="detail-section-label">why it matters</div>
        <p className="an-text">{finding.significance}</p>
      </div>

      <div className="detail-section">
        <div className="detail-section-label">supporting events</div>
        {finding.supporting_events.length === 0 ? (
          <p className="an-text">
            Supporting event summaries were not retained in this bounded report. Use the event IDs
            below to inspect the evidence.
          </p>
        ) : (
          <div className="supporting-stack">
            {finding.supporting_events.map((event) => (
              <button
                type="button"
                className="supporting-event"
                key={event.event_id}
                onClick={() => navigate(investigationPath(sessionId, "timeline", event.event_id))}
              >
                <span className="supporting-event-id">#{event.event_id}</span>
                <span className="supporting-event-summary">{event.summary}</span>
                <span className="supporting-event-time">
                  {formatTimestampShort(event.timestamp_ns)}
                </span>
              </button>
            ))}
          </div>
        )}
        <div style={{ marginTop: 10, display: "flex", flexWrap: "wrap", gap: 4 }}>
          {finding.event_ids.slice(0, 24).map((id) => (
            <Tag key={id}>event {id}</Tag>
          ))}
          {finding.event_ids.length > 24 ? <Tag>+{finding.event_ids.length - 24} more</Tag> : null}
        </div>
        <div className="code-block" style={{ marginTop: 10 }}>
          Observed {formatTimestampShort(finding.time_range.start_ns)} —{" "}
          {formatTimestampShort(finding.time_range.end_ns)}
        </div>
      </div>

      {finding.related_processes.length > 0 ? (
        <div className="detail-section">
          <div className="detail-section-label">related processes</div>
          <div className="stack-sm">
            {finding.related_processes.map((process) => (
              <button
                type="button"
                className="process-ref"
                key={process.process_instance_id}
                onClick={() =>
                  navigate(investigationPath(sessionId, "processes", null, process.process_instance_id))
                }
              >
                <Fingerprint size={11} aria-hidden="true" />
                <span>{process.comm}</span>
                <span className="pid">pid {process.pid}</span>
                <ChevronRight size={11} className="chev" aria-hidden="true" />
              </button>
            ))}
          </div>
        </div>
      ) : null}

      <div className="detail-section">
        <div className="detail-section-label">investigator next steps</div>
        {finding.next_steps.length === 0 ? (
          <p className="an-text">No rule-specific next steps were supplied.</p>
        ) : (
          <ol className="dotted-list" style={{ gap: 6 }}>
            {finding.next_steps.map((step, index) => (
              <li key={step}>
                <span className="mono faint" style={{ marginRight: 6 }}>
                  {index + 1}.
                </span>
                {step}
              </li>
            ))}
          </ol>
        )}
      </div>

      {finding.limitations.length > 0 ? (
        <div className="detail-section">
          <div className="detail-section-label">limitations</div>
          <Notice tone="warning">
            <ul className="dotted-list">
              {finding.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </Notice>
        </div>
      ) : null}

      {finding.related_findings.length > 0 ? (
        <div className="detail-section">
          <div className="detail-section-label">related findings</div>
          <div className="row" style={{ flexWrap: "wrap", gap: 4 }}>
            {finding.related_findings.map((id) => (
              <Tag key={id}>{id}</Tag>
            ))}
          </div>
        </div>
      ) : null}

      {rule ? (
        <div className="detail-section">
          <div className="detail-section-label">rule metadata</div>
          <div className="code-block">
            {rule.rule_id} v{rule.version} · default severity {severityLabel(rule.default_severity)}
            {"\n"}
            {rule.severity_rationale}
            {"\n"}
            {rule.confidence_rationale}
          </div>
        </div>
      ) : null}
    </article>
  );
}
