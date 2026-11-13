import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { ChevronLeft, ChevronRight, Timer } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { api } from "../../lib/api";
import { formatTimestampShort, parseUtcInput } from "../../lib/format";
import { investigationPath } from "../../lib/routes";
import type { EventType, EventView } from "../../types/contracts";
import { Button } from "../../components/ui/Button";
import { DataTable, type Column } from "../../components/ui/DataTable";
import { Field, SearchInput, SelectField } from "../../components/ui/Fields";
import { EmptyState, ErrorState, LoadingState, Notice } from "../../components/ui/States";
import { EventDetailPanel } from "../evidence/EventDetailPanel";
import { eventResult, eventSummary, eventTypeIcon, eventTypeLabel } from "../evidence/eventDisplay";
import { TimelineTrack } from "./TimelineTrack";

const eventTypeOptions = [
  { value: "", label: "All event types" },
  { value: "process_exec", label: "Process exec" },
  { value: "process_fork", label: "Process fork" },
  { value: "process_exit", label: "Process exit" },
  { value: "file_open", label: "File open" },
  { value: "network_connect", label: "Network connect" }
];

const PAGE_SIZE = 100;

export function TimelineTab({
  sessionId,
  initialEventId,
  initialProcessInstanceId,
  navigate
}: {
  sessionId: string;
  initialEventId: number | null;
  initialProcessInstanceId: string | null;
  navigate: (path: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [eventType, setEventType] = useState("");
  const [processId, setProcessId] = useState(initialProcessInstanceId ?? "");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [offset, setOffset] = useState(0);
  const [selectedEventId, setSelectedEventId] = useState<number | null>(initialEventId);
  const debouncedSearch = useDebouncedValue(search);

  const processes = useAsync(() => api.listProcesses(sessionId), [sessionId]);
  const timeline = useAsync(
    () =>
      api.timeline({
        sessionId,
        eventType: (eventType || undefined) as EventType | undefined,
        processInstanceId: processId || undefined,
        fromNs: parseUtcInput(from) ?? undefined,
        toNs: parseUtcInput(to) ?? undefined,
        search: debouncedSearch || undefined,
        limit: PAGE_SIZE,
        offset
      }),
    [sessionId, eventType, processId, from, to, debouncedSearch, offset]
  );

  const detail = useAsync(
    () =>
      selectedEventId != null ? api.event(sessionId, selectedEventId) : Promise.resolve(null),
    [sessionId, selectedEventId]
  );

  useEffect(() => {
    if (initialEventId != null) setSelectedEventId(initialEventId);
  }, [initialEventId]);

  useEffect(() => {
    if (initialProcessInstanceId) setProcessId(initialProcessInstanceId);
  }, [initialProcessInstanceId]);

  const processOptions = useMemo(
    () => [
      { value: "", label: "All processes" },
      ...(processes.data?.processes ?? []).map((process) => ({
        value: process.processInstanceId,
        label: `${process.comm} · pid ${process.pid}`
      }))
    ],
    [processes.data]
  );

  function resetFilters() {
    setSearch("");
    setEventType("");
    setProcessId("");
    setFrom("");
    setTo("");
    setOffset(0);
  }

  function selectEvent(event: EventView) {
    setSelectedEventId(event.id);
    navigate(investigationPath(sessionId, "timeline", event.id));
  }

  function closeDetail() {
    setSelectedEventId(null);
    navigate(investigationPath(sessionId, "timeline"));
  }

  const columns: Column<EventView>[] = [
    {
      key: "time",
      header: "Time (UTC)",
      width: "128px",
      render: (event) => <span className="mono">{formatTimestampShort(event.timestampNs)}</span>
    },
    {
      key: "type",
      header: "Type",
      width: "136px",
      render: (event) => {
        const Icon = eventTypeIcon(event.eventType);
        return (
          <span className="row" style={{ gap: 6 }}>
            <Icon size={10} aria-hidden="true" />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10 }}>
              {eventTypeLabel(event.eventType)}
            </span>
          </span>
        );
      }
    },
    {
      key: "process",
      header: "Process",
      width: "128px",
      render: (event) => (
        <span className="mono">
          {event.comm}
          <span className="faint"> · {event.pid}</span>
        </span>
      )
    },
    {
      key: "summary",
      header: "Recorded payload",
      render: (event) => (
        <span className="mono" style={{ overflowWrap: "anywhere" }}>
          {eventSummary(event)}
        </span>
      )
    },
    {
      key: "result",
      header: "Result",
      width: "104px",
      render: (event) => {
        const payload = event.payload;
        if (payload.kind !== "file_open" && payload.kind !== "network_connect") {
          return <span className="faint">—</span>;
        }
        return (
          <span className={`result-cell ${payload.success ? "success" : "failure"}`.trim()}>
            {eventResult(event)}
          </span>
        );
      }
    },
    {
      key: "id",
      header: "ID",
      width: "58px",
      align: "right",
      render: (event) => (
        <span className="mono faint">#{event.id}</span>
      )
    }
  ];

  const response = timeline.data;
  const activeFilters = Boolean(search || eventType || processId || from || to);

  return (
    <div className="stack" style={{ "--i": 0 } as CSSProperties}>
      <div className="filter-rail">
        <SearchInput
          id="timeline-search"
          label="Search events"
          placeholder="Search path, address, comm, or process…"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        />
        <SelectField
          id="event-type"
          label="Event type"
          options={eventTypeOptions}
          value={eventType}
          onChange={(event) => {
            setEventType(event.target.value);
            setOffset(0);
          }}
        />
        <SelectField
          id="timeline-process"
          label="Process"
          options={processOptions}
          value={processId}
          onChange={(event) => {
            setProcessId(event.target.value);
            setOffset(0);
          }}
        />
        <Field label="From (UTC)" htmlFor="timeline-from">
          <input
            id="timeline-from"
            type="datetime-local"
            className="input"
            value={from}
            onChange={(event) => {
              setFrom(event.target.value);
              setOffset(0);
            }}
          />
        </Field>
        <Field label="To (UTC)" htmlFor="timeline-to">
          <input
            id="timeline-to"
            type="datetime-local"
            className="input"
            value={to}
            onChange={(event) => {
              setTo(event.target.value);
              setOffset(0);
            }}
          />
        </Field>
        <Button onClick={resetFilters} disabled={!activeFilters}>
          Clear
        </Button>
        <div className={`filter-meta ${timeline.loading ? "live" : ""}`.trim()}>
          {timeline.loading ? "reading" : `${response?.total ?? 0} events`}
        </div>
      </div>

      {response?.evidenceIncomplete ? (
        <Notice tone="warning">
          Evidence completeness is qualified for this session. The timeline contains only persisted
          events and does not represent a complete system history.
        </Notice>
      ) : null}

      <div className="panel stagger" style={{ "--i": 1 } as CSSProperties}>
        <div className="panel-head">
          <h2 className="panel-title">
            <Timer size={12} aria-hidden="true" /> event timeline
          </h2>
          <span className="mono faint" style={{ fontSize: 9 }}>
            {response ? `${offset + 1}–${offset + response.events.length} of ${response.total} loaded` : ""}
          </span>
        </div>

        {timeline.loading && !response ? (
          <LoadingState label="Querying event timeline" />
        ) : timeline.error ? (
          <ErrorState message={timeline.error} code="TIMELINE_QUERY_FAILED" onRetry={timeline.reload} />
        ) : !response || response.events.length === 0 ? (
          <EmptyState
            title={activeFilters ? "No events match these filters" : "No recorded events"}
            message={
              activeFilters
                ? "Widen the event type, process, time range, or search text."
                : "This session contains no event records in the evidence store."
            }
            action={
              activeFilters ? (
                <Button size="sm" onClick={resetFilters}>
                  Clear filters
                </Button>
              ) : undefined
            }
          />
        ) : (
          <>
            <TimelineTrack
              events={response.events}
              selectedEventId={selectedEventId}
              onSelect={selectEvent}
            />

            <div className="tl-layout">
              <div className="tl-list">
                <DataTable
                  label="Recorded events"
                  columns={columns}
                  rows={response.events}
                  rowKey={(event) => String(event.id)}
                  selectedKey={selectedEventId != null ? String(selectedEventId) : null}
                  onRowClick={selectEvent}
                  emptyMessage="No events match the current query."
                />
                <div className="table-foot">
                  <span>
                    {offset + 1}–{offset + response.events.length} of {response.total}
                  </span>
                  <div className="pager">
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={offset === 0}
                      onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                    >
                      <ChevronLeft size={11} aria-hidden="true" /> Prev
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={!response.hasMore}
                      onClick={() => setOffset(offset + PAGE_SIZE)}
                    >
                      Next <ChevronRight size={11} aria-hidden="true" />
                    </Button>
                  </div>
                </div>
              </div>

              <EventDetailPanel
                event={detail.data?.event ?? null}
                loading={detail.loading}
                error={detail.error}
                onClose={closeDetail}
                onRetry={detail.reload}
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
}
