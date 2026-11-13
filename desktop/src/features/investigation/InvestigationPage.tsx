import { useEffect } from "react";
import { ArrowLeft } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { useIndicator } from "../../hooks/useIndicator";
import { api } from "../../lib/api";
import { formatDuration, formatNumber, formatTimestamp } from "../../lib/format";
import { investigationPath, investigationTabs, tabLabel, type InvestigationTab } from "../../lib/routes";
import { AssessmentBadge, StatusBadge } from "../../components/ui/Badges";
import { Button } from "../../components/ui/Button";
import { ErrorState, LoadingState } from "../../components/ui/States";
import { SummaryTab } from "./SummaryTab";
import { ProcessesTab } from "../processes/ProcessesTab";
import { TimelineTab } from "../timeline/TimelineTab";
import { FilesystemTab } from "../filesystem/FilesystemTab";
import { NetworkTab } from "../network/NetworkTab";
import { AnalysisTab } from "../analysis/AnalysisTab";
import { VerificationTab } from "../verification/VerificationTab";
import { ExportTab } from "../export/ExportTab";

export function InvestigationPage({
  sessionId,
  tab,
  eventId,
  processInstanceId,
  navigate
}: {
  sessionId: string;
  tab: InvestigationTab;
  eventId: number | null;
  processInstanceId: string | null;
  navigate: (path: string) => void;
}) {
  const state = useAsync(() => api.getSession(sessionId), [sessionId]);
  const { containerRef: spineRef, box: spineBox } = useIndicator<HTMLElement>(tab);

  useEffect(() => {
    // Dimension changes should not leave the reader scrolled away from context.
    document.querySelector(".shell-content")?.scrollTo({ top: 0 });
  }, [tab, sessionId]);

  if (state.loading && !state.data) {
    return (
      <div className="page">
        <LoadingState label="Opening session evidence" />
      </div>
    );
  }

  if (state.error || !state.data) {
    return (
      <div className="page">
        <div className="panel">
          <ErrorState
            title="Session unavailable"
            message={state.error ?? "The requested session could not be read."}
            code="SESSION_UNAVAILABLE"
            onRetry={state.reload}
          />
        </div>
        <div style={{ textAlign: "center", marginTop: 14 }}>
          <Button variant="ghost" onClick={() => navigate("/sessions")}>
            <ArrowLeft size={12} /> Return to session index
          </Button>
        </div>
      </div>
    );
  }

  const { session, stats } = state.data;

  return (
    <div className="page">
      <header className="inv-head">
        <div className="inv-identity">
          <div style={{ minWidth: 0 }}>
            <div className="inv-kicker">
              <button type="button" className="back-link" onClick={() => navigate("/sessions")}>
                <ArrowLeft size={11} aria-hidden="true" />
                sessions
              </button>
              <span className="sep">/</span>
              <span className="idx">{String(investigationTabs.indexOf(tab) + 1).padStart(2, "0")}</span>
              <span>{tabLabel(tab).toLowerCase()}</span>
            </div>
            <h1 className="inv-command">
              <span className="prompt">$</span>
              {session.commandDisplay}
            </h1>
            <div className="inv-idline">
              {session.id} · {session.recordingScope === "system" ? "system scope" : "target tree"} ·{" "}
              {session.kernelRelease ?? "kernel not recorded"}
            </div>
          </div>
          <div className="inv-badges">
            {session.evidenceIncomplete ? (
              <span className="mark" data-tone="failed">
                <span className="mark-glyph" aria-hidden="true" />
                evidence loss
              </span>
            ) : null}
            {session.verification ? <AssessmentBadge assessment={session.verification.assessment} /> : null}
            <StatusBadge status={session.status} />
          </div>
        </div>

        <dl className="inv-facts">
          <div className="definition-cell">
            <dt>Started</dt>
            <dd>{formatTimestamp(session.startedAtNs)}</dd>
          </div>
          <div className="definition-cell">
            <dt>Duration</dt>
            <dd>{formatDuration(session.durationNs)}</dd>
          </div>
          <div className="definition-cell">
            <dt>Events</dt>
            <dd>{formatNumber(stats.eventCount)}</dd>
          </div>
          <div className="definition-cell">
            <dt>Processes</dt>
            <dd>{formatNumber(stats.processCount)}</dd>
          </div>
          <div className="definition-cell">
            <dt>Evidence</dt>
            <dd>{session.evidenceIncomplete ? "incomplete" : "no loss declared"}</dd>
          </div>
          <div className="definition-cell">
            <dt>Termination</dt>
            <dd>{stats.terminationReason ?? "not recorded"}</dd>
          </div>
        </dl>
      </header>

      <nav
        className="dim-spine"
        aria-label="Investigation dimensions"
        ref={spineRef}
        style={{ position: "relative" }}
      >
        {spineBox ? (
          <span
            className="dim-glider"
            aria-hidden="true"
            style={{ transform: `translateX(${spineBox.x}px)`, width: spineBox.w }}
          />
        ) : null}
        {investigationTabs.map((item) => (
          <button
            key={item}
            type="button"
            className="dim-item"
            data-active={item === tab ? "true" : "false"}
            aria-current={item === tab ? "page" : undefined}
            onClick={() => navigate(investigationPath(session.id, item, item === tab ? eventId : null))}
          >
            <span className="dim-idx">{String(investigationTabs.indexOf(item) + 1).padStart(2, "0")}</span>
            <span className="dim-label">{tabLabel(item)}</span>
            {item === "timeline" ? (
              <span className="dim-count">{stats.eventCount}</span>
            ) : item === "processes" ? (
              <span className="dim-count">{stats.processCount}</span>
            ) : null}
          </button>
        ))}
      </nav>

      <div key={tab} className="dim-body">
        {tab === "summary" ? <SummaryTab detail={state.data} navigate={navigate} /> : null}
        {tab === "processes" ? (
          <ProcessesTab
            sessionId={session.id}
            initialProcessInstanceId={processInstanceId}
            navigate={navigate}
          />
        ) : null}
        {tab === "timeline" ? (
          <TimelineTab
            sessionId={session.id}
            initialEventId={eventId}
            initialProcessInstanceId={processInstanceId}
            navigate={navigate}
          />
        ) : null}
        {tab === "filesystem" ? <FilesystemTab sessionId={session.id} /> : null}
        {tab === "network" ? <NetworkTab sessionId={session.id} /> : null}
        {tab === "analysis" ? <AnalysisTab sessionId={session.id} navigate={navigate} /> : null}
        {tab === "verification" ? <VerificationTab sessionId={session.id} navigate={navigate} /> : null}
        {tab === "export" ? <ExportTab detail={state.data} /> : null}
      </div>
    </div>
  );
}
