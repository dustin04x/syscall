import { ArrowRight, Waypoints } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { api } from "../../lib/api";
import {
  assessmentLabel,
  formatDuration,
  formatNumber,
  formatTimestamp,
  severityLabel
} from "../../lib/format";
import { investigationPath, type InvestigationTab } from "../../lib/routes";
import type { CSSProperties } from "react";
import type { SessionDetail } from "../../types/contracts";
import { AssessmentBadge, ConfidenceBadge, SeverityBadge, Tag } from "../../components/ui/Badges";
import { Button } from "../../components/ui/Button";
import { ErrorState, LoadingState, Notice } from "../../components/ui/States";
import { eventTypeLabel } from "../evidence/eventDisplay";

export function SummaryTab({
  detail,
  navigate
}: {
  detail: SessionDetail;
  navigate: (path: string) => void;
}) {
  const analysis = useAsync(() => api.analysis(detail.session.id), [detail.session.id]);
  const session = detail.session;
  const stats = detail.stats;
  const maxTypeCount = Math.max(1, ...stats.eventsByType.map((item) => item.count));
  const findings = analysis.data?.findings ?? [];

  function open(tab: InvestigationTab) {
    navigate(investigationPath(session.id, tab));
  }

  return (
    <div className="stack">
      {stats.evidenceMayBeIncomplete ? (
        <Notice tone="warning" title="Evidence completeness is qualified">
          Analysis and verification can only speak to persisted events. Counters show{" "}
          {stats.droppedEventsTotal} dropped, {stats.ringbufLostEvents} ring-buffer lost,{" "}
          {stats.malformedEvents} malformed, {stats.eventsPersistFailed} persist failures, and{" "}
          {stats.unresolvedIdentityCount} unresolved identity{" "}
          {stats.unresolvedIdentityCount === 1 ? "instance" : "instances"}. Missing activity cannot
          be reconstructed.
        </Notice>
      ) : null}

      <div
        className="summary-canvas stagger"
        style={{ "--i": 1 } as CSSProperties}
      >
        <section className="summary-main-cell" aria-label="Evidence composition">
          <div className="section-label" style={{ marginBottom: 12 }}>
            evidence composition
          </div>
          {stats.eventsByType.length === 0 ? (
            <p className="state-body" style={{ marginTop: 0 }}>
              No typed events are present in this session.
            </p>
          ) : (
            <div className="evidence-bars">
              {stats.eventsByType.map((item) => (
                <div className="evidence-bar-row" key={item.eventType}>
                  <span className="evidence-bar-label">{eventTypeLabel(item.eventType)}</span>
                  <span className="evidence-bar-track">
                    <span
                      className={`evidence-bar-fill t-${item.eventType}`}
                      style={{ width: `${(item.count / maxTypeCount) * 100}%` }}
                    />
                  </span>
                  <span className="evidence-bar-count">{formatNumber(item.count)}</span>
                </div>
              ))}
            </div>
          )}
          <p className="verify-note" style={{ marginTop: 12 }}>
            Counts are derived from persisted events only. Empty categories mean no matching event
            was recorded, not that the activity did not occur.
          </p>

          <div className="detail-section" style={{ marginTop: 14 }}>
            <div className="detail-section-label">collection accounting</div>
            <div className="accounting-grid">
              <div className="accounting-cell">
                <dt>Ring-buffer lost</dt>
                <dd>{stats.ringbufLostEvents}</dd>
              </div>
              <div className="accounting-cell">
                <dt>Userspace dropped</dt>
                <dd>{stats.userspaceDroppedEvents}</dd>
              </div>
              <div className="accounting-cell">
                <dt>Malformed records</dt>
                <dd>{stats.malformedEvents}</dd>
              </div>
              <div className="accounting-cell">
                <dt>Filtered by scope</dt>
                <dd>{stats.filteredEvents}</dd>
              </div>
              <div className="accounting-cell">
                <dt>Collector self-filtered</dt>
                <dd>{stats.eventsSelfFiltered}</dd>
              </div>
              <div className="accounting-cell">
                <dt>Persist failures</dt>
                <dd>{stats.eventsPersistFailed}</dd>
              </div>
              <div className="accounting-cell">
                <dt>Termination</dt>
                <dd>
                  {stats.terminationReason ?? "not recorded"}
                  {stats.targetExitCode != null ? ` · exit ${stats.targetExitCode}` : ""}
                  {stats.targetExitSignal != null ? ` · signal ${stats.targetExitSignal}` : ""}
                </dd>
              </div>
            </div>
          </div>
        </section>

        <aside className="summary-side-cell" aria-label="Session context and verification">
          <div className="section-label" style={{ marginBottom: 10 }}>
            verification
          </div>
          {session.verification ? (
            <>
              <div className="row-between" style={{ marginBottom: 10 }}>
                <span className="micro">assessment</span>
                <AssessmentBadge assessment={session.verification.assessment} />
              </div>
              <div className="integrity-lines">
                <div className="integrity-line">
                  <span className="integrity-dot bad" aria-hidden="true" />
                  <span className="integrity-label">Error / critical</span>
                  <span className="integrity-value">
                    {session.verification.counts.error + session.verification.counts.critical}
                  </span>
                </div>
                <div className="integrity-line">
                  <span className="integrity-dot warn" aria-hidden="true" />
                  <span className="integrity-label">Warning</span>
                  <span className="integrity-value">{session.verification.counts.warning}</span>
                </div>
                <div className="integrity-line">
                  <span className="integrity-dot ok" aria-hidden="true" />
                  <span className="integrity-label">Info</span>
                  <span className="integrity-value">{session.verification.counts.info}</span>
                </div>
              </div>
              {session.verification.limitations.length > 0 ? (
                <div style={{ marginTop: 10 }}>
                  <Notice tone="warning">
                    <span>{session.verification.limitations[0]}</span>
                  </Notice>
                </div>
              ) : null}
              <div style={{ marginTop: 12 }}>
                <Button size="sm" variant="ghost" onClick={() => open("verification")}>
                  Inspect verification <ArrowRight size={10} />
                </Button>
              </div>
            </>
          ) : (
            <p className="verify-note" style={{ marginTop: 0 }}>
              Verification has not been run for this session. It evaluates schema, chain integrity,
              and evidence completeness.
            </p>
          )}

          <div className="section-label" style={{ margin: "18px 0 10px" }}>
            collection context
          </div>
          <div className="integrity-lines">
            <div className="integrity-line">
              <span className="integrity-label">Started</span>
              <span className="integrity-value mono" style={{ fontSize: 9.5 }}>
                {formatTimestamp(session.startedAtNs)}
              </span>
            </div>
            <div className="integrity-line">
              <span className="integrity-label">Ended</span>
              <span className="integrity-value mono" style={{ fontSize: 9.5 }}>
                {formatTimestamp(session.endedAtNs)}
              </span>
            </div>
            <div className="integrity-line">
              <span className="integrity-label">Duration</span>
              <span className="integrity-value">{formatDuration(session.durationNs)}</span>
            </div>
            <div className="integrity-line">
              <span className="integrity-label">Scope</span>
              <span className="integrity-value">
                {session.recordingScope === "system" ? "system-wide" : "target tree"}
              </span>
            </div>
            <div className="integrity-line">
              <span className="integrity-label">Kernel</span>
              <span className="integrity-value mono" style={{ fontSize: 9.5 }}>
                {session.kernelRelease ?? "not recorded"}
              </span>
            </div>
            <div className="integrity-line">
              <span className="integrity-label">Collector</span>
              <span className="integrity-value">{session.collectorVersion ?? "not recorded"}</span>
            </div>
          </div>
          {session.error ? (
            <div style={{ marginTop: 12 }}>
              <Notice tone="critical" title="Recorded collection error">
                {session.error}
              </Notice>
            </div>
          ) : null}
        </aside>
      </div>

      <section className="panel" aria-label="Behavioral findings" style={{ "--i": 2 } as CSSProperties}>
        <div className="panel-head">
          <h2 className="panel-title">behavioral findings</h2>
          <div className="row" style={{ gap: 8 }}>
            <Tag>{findings.length} reported</Tag>
            {analysis.data ? (
              <Button variant="ghost" size="sm" onClick={() => open("analysis")}>
                Full analysis <ArrowRight size={10} />
              </Button>
            ) : null}
          </div>
        </div>
        {analysis.loading ? (
          <LoadingState label="Evaluating behavioral rules" />
        ) : analysis.error ? (
          <ErrorState compact message={analysis.error} onRetry={analysis.reload} />
        ) : findings.length === 0 ? (
          <div className="state-block">
            <div className="state-title">No behavioral findings</div>
            <p className="state-body">
              The current rules matched no behavior in persisted evidence. Absence of findings is
              not proof of benign activity.
            </p>
          </div>
        ) : (
          <div style={{ padding: "6px 14px 10px" }}>
            {findings.slice(0, 6).map((finding) => (
              <div className="summary-finding" key={finding.finding_id}>
                <span className={`summary-finding-mark ${finding.severity}`} aria-hidden="true" />
                <div style={{ minWidth: 0 }}>
                  <div className="summary-finding-title">{finding.title}</div>
                  <div className="summary-finding-meta">
                    {finding.rule_id} · {severityLabel(finding.severity)}
                  </div>
                </div>
                <ConfidenceBadge confidence={finding.confidence} />
              </div>
            ))}
            <div className="table-foot" style={{ border: 0, padding: "8px 0 0" }}>
              <span>findings are observations, not verdicts</span>
              <span>{analysis.data ? "from the current deterministic rule set" : ""}</span>
            </div>
          </div>
        )}
      </section>

      <section className="panel" aria-label="Continue investigation" style={{ "--i": 3 } as CSSProperties}>
        <div className="panel-head">
          <h2 className="panel-title">
            <Waypoints size={12} aria-hidden="true" /> continue investigation
          </h2>
        </div>
        <div style={{ padding: 14 }}>
          <div className="continue-grid">
            <Button onClick={() => open("processes")}>Process graph</Button>
            <Button onClick={() => open("timeline")}>Event timeline</Button>
            <Button onClick={() => open("filesystem")}>Filesystem</Button>
            <Button onClick={() => open("network")}>Network</Button>
            <Button onClick={() => open("export")}>Export evidence</Button>
          </div>
        </div>
      </section>
    </div>
  );
}
