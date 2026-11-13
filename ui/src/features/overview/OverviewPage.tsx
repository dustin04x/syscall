import { ArrowUpRight } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { api } from "../../lib/api";
import { formatDuration, formatNumber, formatTimestampShort } from "../../lib/format";
import { investigationPath } from "../../lib/routes";
import type { CSSProperties } from "react";
import { AssessmentBadge, StatusBadge } from "../../components/ui/Badges";
import { EmptyState, ErrorState, LoadingState, Notice } from "../../components/ui/States";
import { PageHeader } from "../../components/layout/PageHeader";
import { Button } from "../../components/ui/Button";

const stagger = (i: number) => ({ "--i": i }) as CSSProperties;

export function OverviewPage({ navigate }: { navigate: (path: string) => void }) {
  const state = useAsync(() => api.overview(8), []);

  if (state.loading && !state.data) {
    return (
      <div className="page">
        <PageHeader index="01" title="Evidence overview" />
        <LoadingState label="Reading the evidence store" />
      </div>
    );
  }

  if (state.error || !state.data) {
    return (
      <div className="page">
        <PageHeader index="01" title="Evidence overview" />
        <div className="panel">
          <ErrorState
            message={state.error ?? "The backend returned no overview data."}
            code="OVERVIEW_UNAVAILABLE"
            onRetry={state.reload}
          />
        </div>
      </div>
    );
  }

  const data = state.data;
  const findings = data.recentFindingCounts;
  const severityTotal = Math.max(findings.total, 1);
  const latest = data.recentSessions[0] ?? null;
  const verification = data.latestVerification;

  return (
    <div className="page">
      <PageHeader
        index="01"
        title="Evidence overview"
        subtitle="Read-only forensic access to recorded Linux process, filesystem, and network activity. Record → collect → normalize → correlate → investigate."
      />

      {data.totalSessions === 0 ? (
        <div className="panel">
          <EmptyState
            title="No recorded sessions"
            message="The evidence database is connected but contains no sessions. Record one with the syscall CLI, then reload this view."
            action={
              <Button size="sm" onClick={() => state.reload()}>
                Reload evidence
              </Button>
            }
          />
        </div>
      ) : (
        <div className="ov-canvas x-frame stagger">
          {latest ? (
            <section className="ov-feature" aria-label="Current evidence session" style={stagger(0)}>
              <div className="ov-feature-kicker">
                <span className="idx">02</span>
                <span>current evidence</span>
                <span>{latest.recordingScope === "system" ? "system scope" : "target tree"}</span>
              </div>
              <h2 className="ov-feature-command">
                <span className="prompt">$</span>
                {latest.commandDisplay}
              </h2>
              <div className="ov-feature-id">
                <span>{latest.id}</span>
                <span className="sep">/</span>
                <StatusBadge status={latest.status} />
              </div>

              <dl className="ov-feature-facts">
                <div className="ov-fact">
                  <dt>Started</dt>
                  <dd>{formatTimestampShort(latest.startedAtNs)}</dd>
                </div>
                <div className="ov-fact">
                  <dt>Duration</dt>
                  <dd>{formatDuration(latest.durationNs)}</dd>
                </div>
                <div className="ov-fact">
                  <dt>Events</dt>
                  <dd>{formatNumber(latest.eventCount)}</dd>
                </div>
                <div className="ov-fact">
                  <dt>Processes</dt>
                  <dd>{formatNumber(latest.processCount)}</dd>
                </div>
                <div className="ov-fact">
                  <dt>Findings</dt>
                  <dd>{latest.findingCounts ? formatNumber(latest.findingCounts.total) : "not analyzed"}</dd>
                </div>
              </dl>

              <div className="ov-feature-foot">
                <div className="chain" aria-label="Evidence state">
                  <span className="chain-node on" />
                  <span className="chain-line" />
                  <span
                    className={`chain-node ${latest.evidenceIncomplete ? "" : "on"}`}
                    aria-hidden="true"
                  />
                  <span className="chain-line" />
                  <span
                    className={`chain-node ${latest.verification ? "on" : ""}`}
                    aria-hidden="true"
                  />
                  <span className="chain-label">
                    recorded{latest.evidenceIncomplete ? " · loss declared" : " · no loss declared"}
                    {latest.verification ? ` · ${latest.verification.assessment.replaceAll("_", " ")}` : ""}
                  </span>
                </div>
                <Button variant="primary" size="sm" onClick={() => navigate(investigationPath(latest.id, "summary"))}>
                  Open investigation <ArrowUpRight size={11} />
                </Button>
              </div>
            </section>
          ) : null}

          <section className="ov-verify" aria-label="Latest verification" style={stagger(1)}>
            <div className="verify-verdict">
              <span className="verify-verdict-label">latest verification</span>
              {verification ? <AssessmentBadge assessment={verification.assessment} /> : null}
            </div>
            {verification ? (
              <>
                <div className="verify-counts">
                  <div className="verify-count">
                    <span>findings</span>
                    <strong>{verification.totalFindings}</strong>
                  </div>
                  <div className="verify-count">
                    <span>error</span>
                    <strong>{verification.counts.error + verification.counts.critical}</strong>
                  </div>
                  <div className="verify-count">
                    <span>warning</span>
                    <strong>{verification.counts.warning}</strong>
                  </div>
                </div>
                {verification.limitations.length > 0 ? (
                  <Notice tone="warning">{verification.limitations[0]}</Notice>
                ) : (
                  <p className="verify-note">
                    Structural verification does not prove complete collection.
                  </p>
                )}
              </>
            ) : (
              <p className="verify-note">
                No verification has been run. Verification is available from any recorded session.
              </p>
            )}
          </section>

          <div className="ov-band" aria-label="Evidence metrics" style={stagger(2)}>
            <div className="ov-metric">
              <span className="ov-metric-label">Sessions</span>
              <div className="ov-metric-value">{formatNumber(data.totalSessions)}</div>
              <div className="ov-metric-detail">
                {data.completedSessions} completed · {data.activeSessions} active
              </div>
            </div>
            <div className="ov-metric">
              <span className="ov-metric-label">Interrupted</span>
              <div className="ov-metric-value">
                {formatNumber(data.interruptedSessions + data.recoveredSessions)}
              </div>
              <div className="ov-metric-detail">
                {data.recoveredSessions} recovered · {data.failedSessions} failed
              </div>
            </div>
            <div className={`ov-metric ${data.sessionsWithLoss > 0 ? "warn" : ""}`.trim()}>
              <span className="ov-metric-label">Evidence loss</span>
              <div className="ov-metric-value">{formatNumber(data.sessionsWithLoss)}</div>
              <div className={`ov-metric-detail ${data.sessionsWithLoss > 0 ? "warn" : ""}`.trim()}>
                {data.sessionsWithLoss > 0 ? "sessions with detected loss" : "no loss recorded"}
              </div>
            </div>
            <div className={`ov-metric ${findings.high + findings.critical > 0 ? "warn" : ""}`.trim()}>
              <span className="ov-metric-label">Recent findings</span>
              <div className="ov-metric-value">{formatNumber(findings.total)}</div>
              <div className={`ov-metric-detail ${findings.high + findings.critical > 0 ? "warn" : ""}`.trim()}>
                {findings.high + findings.critical} high or critical
              </div>
            </div>
          </div>

          <section className="ov-index" aria-label="Recent sessions" style={stagger(3)}>
            <div className="session-index" style={{ border: "0" }}>
              {data.recentSessions.map((session, index) => (
                <button
                  key={session.id}
                  type="button"
                  className="session-row"
                  onClick={() => navigate(investigationPath(session.id, "summary"))}
                >
                  <span className="session-idx">{String(index + 1).padStart(2, "0")}</span>
                  <StatusBadge status={session.status} />
                  <span className="session-main">
                    <span className="session-command">{session.commandDisplay}</span>
                    <span className="session-sub">
                      {formatTimestampShort(session.startedAtNs)} · {session.eventCount} events ·{" "}
                      {session.processCount} processes
                    </span>
                  </span>
                  <span className={`session-findings ${session.findingCounts?.total ? "has" : ""}`.trim()}>
                    {session.findingCounts
                      ? `${session.findingCounts.total} finding${session.findingCounts.total === 1 ? "" : "s"}`
                      : "not analyzed"}
                  </span>
                  <span className={`session-cell ${session.evidenceIncomplete ? "" : "dim"}`.trim()}>
                    {session.evidenceIncomplete ? "loss detected" : "evidence intact"}
                  </span>
                  <ArrowUpRight className="session-arrow" size={12} aria-hidden="true" />
                </button>
              ))}
            </div>
          </section>

          <aside className="ov-side" aria-label="Evidence integrity and findings" style={stagger(4)}>
            <div className="ov-side-block">
              <div className="section-label" style={{ marginBottom: 8 }}>
                integrity
              </div>
              <div className="integrity-lines">
                <div className="integrity-line">
                  <span className="integrity-dot ok" aria-hidden="true" />
                  <span className="integrity-label">Completed</span>
                  <span className="integrity-value">{data.completedSessions}</span>
                </div>
                <div className="integrity-line">
                  <span className="integrity-dot warn" aria-hidden="true" />
                  <span className="integrity-label">Interrupted / recovered</span>
                  <span className="integrity-value">
                    {data.interruptedSessions + data.recoveredSessions}
                  </span>
                </div>
                <div className="integrity-line">
                  <span className="integrity-dot bad" aria-hidden="true" />
                  <span className="integrity-label">Failed</span>
                  <span className="integrity-value">{data.failedSessions}</span>
                </div>
                <div className="integrity-line">
                  <span className="integrity-dot warn" aria-hidden="true" />
                  <span className="integrity-label">With evidence loss</span>
                  <span className="integrity-value">{data.sessionsWithLoss}</span>
                </div>
              </div>
            </div>
            <div className="ov-side-block">
              <div className="section-label" style={{ marginBottom: 8 }}>
                recent behavioral findings
              </div>
              {findings.total === 0 ? (
                <p className="verify-note" style={{ marginTop: 0 }}>
                  No behavioral findings. Open a session and run behavioral analysis to evaluate the
                  recorded evidence.
                </p>
              ) : (
                <div className="sev-ladder">
                  {(
                    [
                      ["Critical", findings.critical, "critical"],
                      ["High", findings.high, "high"],
                      ["Medium", findings.medium, "medium"],
                      ["Low", findings.low, "low"],
                      ["Informational", findings.informational, "informational"]
                    ] as const
                  ).map(([label, count, tone]) => (
                    <div className="sev-row" key={label}>
                      <span className="sev-name">{label}</span>
                      <span className="sev-track" aria-hidden="true">
                        <span
                          className={`sev-fill ${tone}`}
                          style={{ width: `${(count / severityTotal) * 100}%` }}
                        />
                      </span>
                      <span className="sev-count">{count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </aside>

          <div className="ov-boundary" aria-label="Recording boundary" style={stagger(5)}>
            <div className="boundary-cell">
              <span className="boundary-idx">A</span>
              <div>
                <dt>Collector</dt>
                <dd>Kernel tracepoint capture owned by the syscall CLI.</dd>
              </div>
            </div>
            <div className="boundary-cell">
              <span className="boundary-idx">B</span>
              <div>
                <dt>This application</dt>
                <dd>Reads evidence only. It does not invoke the collector or request privilege.</dd>
              </div>
            </div>
            <div className="boundary-cell">
              <span className="boundary-idx">C</span>
              <div>
                <dt>Analysis</dt>
                <dd>Findings are heuristics over persisted evidence, with explicit limitations.</dd>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
