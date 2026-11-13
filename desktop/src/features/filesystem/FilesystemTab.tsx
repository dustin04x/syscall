import { useMemo, useState, type CSSProperties } from "react";
import { ChevronLeft, ChevronRight, FileSearch } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { api } from "../../lib/api";
import { formatFlags, formatTimestampShort, parseUtcInput } from "../../lib/format";
import type { FileActivityView } from "../../types/contracts";
import { Tag } from "../../components/ui/Badges";
import { Button } from "../../components/ui/Button";
import { DataTable, type Column } from "../../components/ui/DataTable";
import { Field, SearchInput, SelectField } from "../../components/ui/Fields";
import { EmptyState, ErrorState, LoadingState, Notice } from "../../components/ui/States";
import { EventDetailPanel } from "../evidence/EventDetailPanel";

const PAGE_SIZE = 100;

export function FilesystemTab({ sessionId }: { sessionId: string }) {
  const [search, setSearch] = useState("");
  const [processId, setProcessId] = useState("");
  const [success, setSuccess] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [offset, setOffset] = useState(0);
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);
  const debouncedSearch = useDebouncedValue(search);

  const processes = useAsync(() => api.listProcesses(sessionId), [sessionId]);
  const activity = useAsync(
    () =>
      api.filesystem({
        sessionId,
        processInstanceId: processId || undefined,
        success: success === "" ? undefined : success === "true",
        fromNs: parseUtcInput(from) ?? undefined,
        toNs: parseUtcInput(to) ?? undefined,
        search: debouncedSearch || undefined,
        limit: PAGE_SIZE,
        offset
      }),
    [sessionId, processId, success, from, to, debouncedSearch, offset]
  );
  const detail = useAsync(
    () => (selectedEventId != null ? api.event(sessionId, selectedEventId) : Promise.resolve(null)),
    [sessionId, selectedEventId]
  );

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

  const activeFilters = Boolean(search || processId || success || from || to);

  function resetFilters() {
    setSearch("");
    setProcessId("");
    setSuccess("");
    setFrom("");
    setTo("");
    setOffset(0);
  }

  const columns: Column<FileActivityView>[] = [
    {
      key: "time",
      header: "Time (UTC)",
      width: "128px",
      render: (row) => <span className="mono">{formatTimestampShort(row.timestampNs)}</span>
    },
    {
      key: "process",
      header: "Process",
      width: "124px",
      render: (row) => (
        <span className="mono">
          {row.comm}
          <span className="faint"> · {row.pid}</span>
        </span>
      )
    },
    {
      key: "path",
      header: "Attempted path",
      render: (row) => (
        <span
          className="mono"
          title={row.path}
          style={{
            color: row.pathTruncated ? "var(--warning)" : undefined,
            overflowWrap: "anywhere"
          }}
        >
          {row.path}
        </span>
      )
    },
    {
      key: "kind",
      header: "Path form",
      width: "118px",
      render: (row) => (
        <span className="row" style={{ gap: 4 }}>
          <Tag>{row.pathIsAbsolute ? "absolute" : "relative"}</Tag>
          {row.pathTruncated ? <Tag tone="warning">truncated</Tag> : null}
        </span>
      )
    },
    {
      key: "flags",
      header: "Flags",
      width: "96px",
      render: (row) => <span className="mono faint">{formatFlags(row.flags)}</span>
    },
    {
      key: "result",
      header: "Result",
      width: "104px",
      render: (row) => (
        <span className={`result-cell ${row.success ? "success" : "failure"}`.trim()}>
          {row.success ? "success" : `errno ${row.errno ?? "—"}`}
        </span>
      )
    },
    {
      key: "id",
      header: "Event",
      width: "58px",
      align: "right",
      render: (row) => <span className="mono faint">#{row.eventId}</span>
    }
  ];

  const response = activity.data;
  const loaded = response?.files ?? [];
  const okCount = loaded.filter((row) => row.success).length;
  const failedCount = loaded.length - okCount;

  return (
    <div className="stack" style={{ "--i": 0 } as CSSProperties}>
      <div className="filter-rail">
        <SearchInput
          id="fs-search"
          label="Search filesystem activity"
          placeholder="Search path, comm, or process instance…"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        />
        <SelectField
          id="fs-process"
          label="Process"
          options={processOptions}
          value={processId}
          onChange={(event) => {
            setProcessId(event.target.value);
            setOffset(0);
          }}
        />
        <SelectField
          id="fs-success"
          label="Result"
          options={[
            { value: "", label: "All results" },
            { value: "true", label: "Successful" },
            { value: "false", label: "Failed" }
          ]}
          value={success}
          onChange={(event) => {
            setSuccess(event.target.value);
            setOffset(0);
          }}
        />
        <Field label="From (UTC)" htmlFor="fs-from">
          <input
            id="fs-from"
            type="datetime-local"
            className="input"
            value={from}
            onChange={(event) => {
              setFrom(event.target.value);
              setOffset(0);
            }}
          />
        </Field>
        <Field label="To (UTC)" htmlFor="fs-to">
          <input
            id="fs-to"
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
        <div className={`filter-meta ${activity.loading ? "live" : ""}`.trim()}>
          {activity.loading ? "reading" : `${response?.total ?? 0} attempts`}
        </div>
      </div>

      {response?.evidenceIncomplete ? (
        <Notice tone="warning">
          Evidence completeness is qualified for this session. Missing file activity cannot be
          inferred from the records that remain.
        </Notice>
      ) : null}

      <div className="panel stagger" style={{ "--i": 1 } as CSSProperties}>
        <div className="panel-head">
          <h2 className="panel-title">
            <FileSearch size={12} aria-hidden="true" /> path attempts
          </h2>
          <div className="row" style={{ gap: 8 }}>
            <Tag tone="ok">{okCount} ok in view</Tag>
            <Tag tone={failedCount > 0 ? "error" : undefined}>{failedCount} failed in view</Tag>
            <span className="micro" style={{ marginLeft: 8 }}>
              attempt semantics — failed opens remain evidence
            </span>
          </div>
        </div>

        {activity.loading && !response ? (
          <LoadingState label="Querying filesystem activity" />
        ) : activity.error ? (
          <ErrorState message={activity.error} code="FILESYSTEM_QUERY_FAILED" onRetry={activity.reload} />
        ) : !response || response.files.length === 0 ? (
          <EmptyState
            icon={<FileSearch size={14} />}
            title={activeFilters ? "No path attempts match" : "No filesystem activity recorded"}
            message={
              activeFilters
                ? "Adjust the process, result, time range, or search text."
                : "No file-open events were persisted for this session."
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
          <div className="tl-layout">
            <div className="tl-list">
              <DataTable
                label="Filesystem activity"
                columns={columns}
                rows={response.files}
                rowKey={(row) => String(row.eventId)}
                selectedKey={selectedEventId != null ? String(selectedEventId) : null}
                onRowClick={(row) => setSelectedEventId(row.eventId)}
                emptyMessage="No file-open events match the query."
              />
              <div className="table-foot">
                <span>
                  {offset + 1}–{offset + response.files.length} of {response.total}
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
              onClose={() => setSelectedEventId(null)}
              onRetry={detail.reload}
            />
          </div>
        )}
      </div>
    </div>
  );
}
