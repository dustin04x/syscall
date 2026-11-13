import { useMemo, useState, type CSSProperties } from "react";
import { ChevronLeft, ChevronRight, Network } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { api } from "../../lib/api";
import { formatTimestampShort, parseUtcInput } from "../../lib/format";
import type { ConnectionView } from "../../types/contracts";
import { Tag } from "../../components/ui/Badges";
import { Button } from "../../components/ui/Button";
import { DataTable, type Column } from "../../components/ui/DataTable";
import { Field, SearchInput, SelectField } from "../../components/ui/Fields";
import { EmptyState, ErrorState, LoadingState, Notice } from "../../components/ui/States";
import { EventDetailPanel } from "../evidence/EventDetailPanel";

const PAGE_SIZE = 100;

export function NetworkTab({ sessionId }: { sessionId: string }) {
  const [search, setSearch] = useState("");
  const [processId, setProcessId] = useState("");
  const [success, setSuccess] = useState("");
  const [family, setFamily] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [offset, setOffset] = useState(0);
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);
  const debouncedSearch = useDebouncedValue(search);

  const processes = useAsync(() => api.listProcesses(sessionId), [sessionId]);
  const connections = useAsync(
    () =>
      api.network({
        sessionId,
        processInstanceId: processId || undefined,
        success: success === "" ? undefined : success === "true",
        family: (family || undefined) as "ipv4" | "ipv6" | undefined,
        fromNs: parseUtcInput(from) ?? undefined,
        toNs: parseUtcInput(to) ?? undefined,
        search: debouncedSearch || undefined,
        limit: PAGE_SIZE,
        offset
      }),
    [sessionId, processId, success, family, from, to, debouncedSearch, offset]
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

  const activeFilters = Boolean(search || processId || success || family || from || to);

  function resetFilters() {
    setSearch("");
    setProcessId("");
    setSuccess("");
    setFamily("");
    setFrom("");
    setTo("");
    setOffset(0);
  }

  const columns: Column<ConnectionView>[] = [
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
      key: "family",
      header: "Family",
      width: "70px",
      render: (row) => <Tag>{row.family}</Tag>
    },
    {
      key: "destination",
      header: "Attempted destination",
      render: (row) => (
        <span className="mono" style={{ color: "var(--text)" }}>
          {row.destinationAddress}
          <span className="faint">:{row.destinationPort}</span>
        </span>
      )
    },
    {
      key: "source",
      header: "Source",
      width: "168px",
      render: (row) => (
        <span className="mono faint">
          {row.sourceAddress ? `${row.sourceAddress}:${row.sourcePort ?? "—"}` : "—"}
        </span>
      )
    },
    {
      key: "result",
      header: "Result",
      width: "104px",
      render: (row) => (
        <span className={`result-cell ${row.success ? "success" : "failure"}`.trim()}>
          {row.success ? "accepted" : `errno ${row.errno ?? "—"}`}
        </span>
      )
    },
    {
      key: "established",
      header: "Established",
      width: "100px",
      render: () => <span className="faint">no · attempt</span>
    },
    {
      key: "id",
      header: "Event",
      width: "58px",
      align: "right",
      render: (row) => <span className="mono faint">#{row.eventId}</span>
    }
  ];

  const response = connections.data;
  const loaded = response?.connections ?? [];
  const okCount = loaded.filter((row) => row.success).length;
  const failedCount = loaded.length - okCount;

  return (
    <div className="stack" style={{ "--i": 0 } as CSSProperties}>
      <Notice tone="info" title="These are connection attempts, not session telemetry">
        A successful connect does not prove that a connection was established, that data was sent,
        or that the destination was reachable end-to-end. Established is always reported as no.
      </Notice>

      <div className="filter-rail">
        <SearchInput
          id="network-search"
          label="Search network activity"
          placeholder="Search address, port, comm, or process…"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        />
        <SelectField
          id="network-process"
          label="Process"
          options={processOptions}
          value={processId}
          onChange={(event) => {
            setProcessId(event.target.value);
            setOffset(0);
          }}
        />
        <SelectField
          id="network-family"
          label="Family"
          options={[
            { value: "", label: "All families" },
            { value: "ipv4", label: "IPv4" },
            { value: "ipv6", label: "IPv6" }
          ]}
          value={family}
          onChange={(event) => {
            setFamily(event.target.value);
            setOffset(0);
          }}
        />
        <SelectField
          id="network-success"
          label="Result"
          options={[
            { value: "", label: "All results" },
            { value: "true", label: "Accepted" },
            { value: "false", label: "Failed" }
          ]}
          value={success}
          onChange={(event) => {
            setSuccess(event.target.value);
            setOffset(0);
          }}
        />
        <Field label="From (UTC)" htmlFor="network-from">
          <input
            id="network-from"
            type="datetime-local"
            className="input"
            value={from}
            onChange={(event) => {
              setFrom(event.target.value);
              setOffset(0);
            }}
          />
        </Field>
        <Field label="To (UTC)" htmlFor="network-to">
          <input
            id="network-to"
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
        <div className={`filter-meta ${connections.loading ? "live" : ""}`.trim()}>
          {connections.loading ? "reading" : `${response?.total ?? 0} attempts`}
        </div>
      </div>

      {response?.evidenceIncomplete ? (
        <Notice tone="warning">
          Evidence completeness is qualified for this session. Absence of a connection attempt does
          not prove that no attempt occurred.
        </Notice>
      ) : null}

      <div className="panel stagger" style={{ "--i": 1 } as CSSProperties}>
        <div className="panel-head">
          <h2 className="panel-title">
            <Network size={12} aria-hidden="true" /> connect attempts
          </h2>
          <div className="row" style={{ gap: 8 }}>
            <Tag tone="ok">{okCount} accepted in view</Tag>
            <Tag tone={failedCount > 0 ? "error" : undefined}>{failedCount} failed in view</Tag>
          </div>
        </div>

        {connections.loading && !response ? (
          <LoadingState label="Querying network activity" />
        ) : connections.error ? (
          <ErrorState message={connections.error} code="NETWORK_QUERY_FAILED" onRetry={connections.reload} />
        ) : !response || response.connections.length === 0 ? (
          <EmptyState
            icon={<Network size={14} />}
            title={activeFilters ? "No connect attempts match" : "No network attempts recorded"}
            message={
              activeFilters
                ? "Adjust the process, family, result, time range, or search text."
                : "No network-connect events were persisted for this session."
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
                label="Network connect attempts"
                columns={columns}
                rows={response.connections}
                rowKey={(row) => String(row.eventId)}
                selectedKey={selectedEventId != null ? String(selectedEventId) : null}
                onRowClick={(row) => setSelectedEventId(row.eventId)}
                emptyMessage="No connect attempts match the query."
              />
              <div className="table-foot">
                <span>
                  {offset + 1}–{offset + response.connections.length} of {response.total}
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
