import { useState, type CSSProperties } from "react";
import { ArrowDown, ArrowUp, ArrowUpRight, RotateCcw } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { api, type SessionQuery } from "../../lib/api";
import { formatDuration, formatTimestampShort } from "../../lib/format";
import { investigationPath } from "../../lib/routes";
import type { SessionView } from "../../types/contracts";
import { AssessmentBadge, StatusBadge, Tag } from "../../components/ui/Badges";
import { Button } from "../../components/ui/Button";
import { SearchInput, SelectField } from "../../components/ui/Fields";
import { PageHeader } from "../../components/layout/PageHeader";
import { EmptyState, ErrorState, LoadingState, Notice } from "../../components/ui/States";

type SortBy = NonNullable<SessionQuery["sortBy"]>;

const statusOptions = [
  { value: "", label: "All statuses" },
  { value: "recording", label: "Recording" },
  { value: "completed", label: "Completed" },
  { value: "interrupted", label: "Interrupted" },
  { value: "recovered", label: "Recovered" },
  { value: "failed", label: "Failed" },
  { value: "starting", label: "Starting" },
  { value: "unknown", label: "Unknown" }
];

const sortOptions: Array<{ value: SortBy; label: string }> = [
  { value: "started", label: "Started" },
  { value: "status", label: "Status" },
  { value: "events", label: "Events" },
  { value: "processes", label: "Processes" },
  { value: "findings", label: "Findings" },
  { value: "verification", label: "Verification" }
];

export function SessionsPage({ navigate }: { navigate: (path: string) => void }) {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [sortBy, setSortBy] = useState<SortBy>("started");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");
  const debouncedSearch = useDebouncedValue(search);

  const state = useAsync(
    () =>
      api.listSessions({
        search: debouncedSearch || undefined,
        status: status || undefined,
        sortBy,
        sortDirection,
        includeIntelligence: true,
        limit: 500
      }),
    [debouncedSearch, status, sortBy, sortDirection]
  );

  function reset() {
    setSearch("");
    setStatus("");
    setSortBy("started");
    setSortDirection("desc");
  }

  function sortWith(key: SortBy) {
    if (sortBy === key) {
      setSortDirection((value) => (value === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(key);
      setSortDirection("desc");
    }
  }

  const sessions = state.data?.sessions ?? [];
  const total = state.data?.totalMatched ?? 0;
  const filtered = Boolean(search || status);

  function SortHead({ label, field }: { label: string; field: SortBy }) {
    const active = sortBy === field;
    return (
      <button
        type="button"
        className="sortable"
        data-active={active ? "true" : "false"}
        aria-label={`Sort by ${label}`}
        onClick={() => sortWith(field)}
      >
        {label}
        {active ? (
          sortDirection === "asc" ? (
            <ArrowUp size={9} aria-hidden="true" />
          ) : (
            <ArrowDown size={9} aria-hidden="true" />
          )
        ) : null}
      </button>
    );
  }

  return (
    <div className="page">
      <PageHeader
        index="02"
        title="Session index"
        subtitle="Every recorded capture, indexed by evidence integrity. Select a session to open its investigation workspace."
        actions={
          <Button variant="ghost" onClick={reset}>
            <RotateCcw size={12} /> Reset filters
          </Button>
        }
      />

      <div className="stack" style={{ "--i": 0 } as CSSProperties}>
        <div className="filter-rail">
          <SearchInput
            id="session-search"
            label="Search sessions"
            placeholder="Search command, session ID, or target…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <SelectField
            id="status-filter"
            label="Status"
            options={statusOptions}
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          />
          <SelectField
            id="sort-field"
            label="Sort by"
            options={sortOptions}
            value={sortBy}
            onChange={(event) => setSortBy(event.target.value as SortBy)}
          />
          <Button
            aria-label={`Sort ${sortDirection === "asc" ? "descending" : "ascending"}`}
            title={`Sort ${sortDirection === "asc" ? "descending" : "ascending"}`}
            onClick={() => setSortDirection((value) => (value === "asc" ? "desc" : "asc"))}
          >
            {sortDirection === "asc" ? <ArrowUp size={12} /> : <ArrowDown size={12} />}
            {sortDirection === "asc" ? "Asc" : "Desc"}
          </Button>
          <div className={`filter-meta ${state.loading && state.data ? "live" : ""}`.trim()}>
            {state.loading && state.data ? "updating" : `${total} matched`}
          </div>
        </div>

        {state.data?.intelligenceLimited ? (
          <Notice tone="warning" title="Session verification summary is limited">
            Some sessions could not be summarized for this list. Open a session to run verification
            directly.
          </Notice>
        ) : null}

        {state.loading && !state.data ? (
          <LoadingState label="Reading session index" />
        ) : state.error ? (
          <div className="panel">
            <ErrorState message={state.error} code="SESSION_QUERY_FAILED" onRetry={state.reload} />
          </div>
        ) : sessions.length === 0 ? (
          <div className="panel">
            <EmptyState
              title={filtered ? "No sessions match these filters" : "No sessions recorded"}
              message={
                filtered
                  ? "Adjust the search text or status filter to widen the result set."
                  : "Record a target with the syscall CLI. Sessions appear here after the collector has persisted evidence."
              }
              action={
                filtered ? (
                  <Button size="sm" onClick={reset}>
                    Clear filters
                  </Button>
                ) : undefined
              }
            />
          </div>
        ) : (
          <div className="session-index x-frame stagger">
            <div className="session-row session-head" aria-hidden="true">
              <span className="session-idx">#</span>
              <span>status</span>
              <span>session</span>
              <span><SortHead label="started" field="started" /></span>
              <span className="hide-md">duration</span>
              <span><SortHead label="events" field="events" /></span>
              <span><SortHead label="procs" field="processes" /></span>
              <span className="hide-md">loss</span>
              <span><SortHead label="verification" field="verification" /></span>
              <span><SortHead label="findings" field="findings" /></span>
              <span />
            </div>
            {sessions.map((session, index) => (
              <SessionRow
                key={session.id}
                session={session}
                index={index}
                onOpen={() => navigate(investigationPath(session.id, "summary"))}
              />
            ))}
            <div className="session-foot">
              <span>
                {sessions.length} of {total} sessions shown
              </span>
              <span>evidence access is read-only</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function SessionRow({
  session,
  index,
  onOpen
}: {
  session: SessionView;
  index: number;
  onOpen: () => void;
}) {
  return (
    <button
      type="button"
      className="session-row"
      onClick={onOpen}
      aria-label={`Open investigation for ${session.commandDisplay}`}
      style={{ "--i": Math.min(index, 12) } as CSSProperties}
    >
      <span className="session-idx">{String(index + 1).padStart(2, "0")}</span>
      <StatusBadge status={session.status} />
      <span className="session-main">
        <span className="session-command">{session.commandDisplay}</span>
        <span className="session-sub">
          {session.id} · {session.recordingScope === "system" ? "system scope" : "target tree"}
        </span>
      </span>
      <span className="session-cell" data-label="Started">
        {formatTimestampShort(session.startedAtNs)}
      </span>
      <span className="session-cell hide-md" data-label="Duration">
        {formatDuration(session.durationNs)}
      </span>
      <span className="session-cell" data-label="Events">{session.eventCount}</span>
      <span className="session-cell" data-label="Processes">{session.processCount}</span>
      <span
        className={`session-cell hide-md ${session.evidenceIncomplete ? "" : "dim"}`.trim()}
        data-label="Evidence loss"
      >
        {session.evidenceIncomplete ? "detected" : "none"}
      </span>
      <span className="session-verification" data-label="Verification">
        {session.verification ? (
          <AssessmentBadge assessment={session.verification.assessment} />
        ) : session.intelligenceError ? (
          <Tag>unavailable</Tag>
        ) : (
          <span className="session-cell dim">not checked</span>
        )}
      </span>
      <span
        className={`session-findings ${session.findingCounts?.total ? "has" : ""}`.trim()}
        data-label="Findings"
      >
        {session.findingCounts ? session.findingCounts.total : "—"}
      </span>
      <ArrowUpRight className="session-arrow" size={12} aria-hidden="true" />
    </button>
  );
}
