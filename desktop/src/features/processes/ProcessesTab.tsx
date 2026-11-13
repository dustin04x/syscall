import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { ChevronRight, Fingerprint, GitBranch, Search } from "lucide-react";

import { useAsync } from "../../hooks/useAsync";
import { api } from "../../lib/api";
import { formatNumber, formatTimestamp } from "../../lib/format";
import { investigationPath } from "../../lib/routes";
import { SeverityBadge, Tag } from "../../components/ui/Badges";
import { Button } from "../../components/ui/Button";
import { Copyable } from "../../components/ui/CopyButton";
import { KeyValueGrid } from "../../components/ui/KeyValue";
import { SearchInput } from "../../components/ui/Fields";
import { EmptyState, ErrorState, LoadingState, Notice } from "../../components/ui/States";
import { ProcessGraph } from "./ProcessGraph";

export function ProcessesTab({
  sessionId,
  initialProcessInstanceId,
  navigate
}: {
  sessionId: string;
  initialProcessInstanceId?: string | null;
  navigate: (path: string) => void;
}) {
  const tree = useAsync(() => api.listProcesses(sessionId), [sessionId]);
  const analysis = useAsync(() => api.analysis(sessionId), [sessionId]);
  const [search, setSearch] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const byId = useMemo(
    () => new Map((tree.data?.processes ?? []).map((process) => [process.processInstanceId, process])),
    [tree.data]
  );

  useEffect(() => {
    if (!tree.data) return;
    if (initialProcessInstanceId && byId.has(initialProcessInstanceId)) {
      setSelectedId(initialProcessInstanceId);
      return;
    }
    if (selectedId && byId.has(selectedId)) return;
    const first = tree.data.roots[0] ?? tree.data.processes[0]?.processInstanceId ?? null;
    setSelectedId(first);
  }, [tree.data, byId, selectedId, initialProcessInstanceId]);

  const selected = selectedId ? (byId.get(selectedId) ?? null) : null;
  const query = search.trim().toLowerCase();
  const filtered = useMemo(() => {
    if (!query) return [];
    return (tree.data?.processes ?? []).filter((process) => {
      const fields = [
        process.comm,
        process.executable ?? "",
        process.commandLine ?? "",
        String(process.pid),
        process.processInstanceId
      ];
      return fields.some((field) => field.toLowerCase().includes(query));
    });
  }, [query, tree.data]);

  const findings = useMemo(
    () =>
      (analysis.data?.findings ?? []).filter((finding) =>
        selected ? finding.process_instance_ids.includes(selected.processInstanceId) : false
      ),
    [analysis.data, selected]
  );

  function toggle(id: string) {
    setCollapsed((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  if (tree.loading && !tree.data) {
    return (
      <div className="panel" style={{ "--i": 0 } as CSSProperties}>
        <LoadingState label="Reconstructing process ancestry" />
      </div>
    );
  }

  if (tree.error || !tree.data) {
    return (
      <div className="panel" style={{ "--i": 0 } as CSSProperties}>
        <ErrorState
          message={tree.error ?? "No process data was returned."}
          code="PROCESS_TREE_UNAVAILABLE"
          onRetry={tree.reload}
        />
      </div>
    );
  }

  return (
    <div className="stack" style={{ "--i": 0 } as CSSProperties}>
      {tree.data.unresolvedAncestryCount > 0 || tree.data.identityUnresolvedCount > 0 ? (
        <Notice tone="warning" title="Process ancestry is partially unresolved">
          {tree.data.unresolvedAncestryCount} unresolved parent relationships and{" "}
          {tree.data.identityUnresolvedCount} unresolved identities. The graph shows observed
          relationships only; missing links are not fabricated.
        </Notice>
      ) : null}

      <div className="pg-layout x-frame stagger">
        <section className="pg-canvas" aria-label="Process graph" style={{ "--i": 0 } as CSSProperties}>
          <div className="pg-toolbar">
            <span className="panel-title">
              <GitBranch size={12} aria-hidden="true" /> observed ancestry
            </span>
            <div className="row" style={{ gap: 8 }}>
              <Tag>{tree.data.processes.length} observed</Tag>
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  setCollapsed(
                    collapsed.size > 0
                      ? new Set()
                      : new Set((tree.data?.processes ?? []).map((item) => item.processInstanceId))
                  )
                }
              >
                {collapsed.size > 0 ? "Expand all" : "Collapse all"}
              </Button>
            </div>
          </div>
          <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--line)" }}>
            <SearchInput
              id="process-search"
              label="Search processes"
              placeholder="Filter by comm, executable, pid, or instance…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <div className="pg-canvas-inner">
            {tree.data.processes.length === 0 ? (
              <EmptyState
                title="No processes"
                message="No processes were persisted in this session."
              />
            ) : query ? (
              <div role="list" aria-label="Matching processes">
                {filtered.length === 0 ? (
                  <EmptyState
                    icon={<Search size={13} />}
                    title="No matches"
                    message={`No process matches “${search}”.`}
                  />
                ) : (
                  filtered.map((process) => (
                    <button
                      key={process.processInstanceId}
                      type="button"
                      role="listitem"
                      className="session-row"
                      style={{ gridTemplateColumns: "18px 110px minmax(0,1fr) 90px 60px", gap: 10 }}
                      onClick={() => setSelectedId(process.processInstanceId)}
                    >
                      <span
                        className={`mark-glyph ${selectedId === process.processInstanceId ? "" : ""}`.trim()}
                        aria-hidden="true"
                        style={{ background: selectedId === process.processInstanceId ? "var(--accent)" : "var(--text-faint)" }}
                      />
                      <span className="mono" style={{ fontSize: 11, color: "var(--text)" }}>
                        {process.comm}
                      </span>
                      <span className="session-sub" style={{ marginTop: 0 }}>
                        {process.executable ?? process.commandLine ?? "executable not resolved"}
                      </span>
                      <span className="session-cell">pid {process.pid}</span>
                      <span className="session-cell">{process.eventCount}</span>
                    </button>
                  ))
                )}
              </div>
            ) : (
              <ProcessGraph
                processes={tree.data.processes}
                roots={tree.data.roots}
                collapsed={collapsed}
                selectedId={selectedId}
                onSelect={setSelectedId}
                onToggleCollapse={toggle}
              />
            )}
          </div>
          <div className="table-foot">
            <span>
              {query
                ? `${filtered.length} matching processes shown as a flat list`
                : `${tree.data.roots.length} roots · child links are observed parent relationships`}
            </span>
            <span>click a node to inspect</span>
          </div>
        </section>

        <aside className="pg-detail" aria-label="Process details" style={{ "--i": 1 } as CSSProperties}>
          {!selected ? (
            <EmptyState
              title="Select a process"
              message="Choose a node from the graph to inspect its identity, observed lifetime, and related findings."
            />
          ) : (
            <div className="pg-detail-pad">
              <div className="row-between" style={{ marginBottom: 4 }}>
                <span className="micro">{selected.relationship === "root" ? "root process" : selected.relationship}</span>
                {selected.exitObserved ? <Tag tone="ok">exit observed</Tag> : <Tag>no exit</Tag>}
              </div>
              <h2 style={{ fontFamily: "var(--font-display)", fontSize: 17, fontWeight: 560, letterSpacing: "-0.01em" }}>
                {selected.comm}
              </h2>
              <div className="mono faint" style={{ fontSize: 10, marginTop: 3 }}>
                pid {selected.pid} · instance {selected.processInstanceId}
              </div>

              {selected.identityUnresolved || selected.ancestryUnresolved ? (
                <div style={{ marginTop: 12 }}>
                  <Notice tone="warning" title="Attribution limitation">
                    {selected.identityUnresolved ? "This process identity could not be fully resolved. " : ""}
                    {selected.ancestryUnresolved ? "One or more ancestry links could not be resolved." : ""}
                  </Notice>
                </div>
              ) : null}

              <div className="detail-section" style={{ marginTop: 14 }}>
                <div className="detail-section-label">identity</div>
                <KeyValueGrid
                  entries={[
                    { label: "Instance", value: <Copyable value={selected.processInstanceId} /> },
                    { label: "PID", value: selected.pid, mono: true },
                    { label: "Comm", value: selected.comm, mono: true },
                    { label: "Executable", value: selected.executable ?? "not resolved", mono: true },
                    { label: "Command line", value: selected.commandLine ?? "not resolved", mono: true },
                    {
                      label: "Parent",
                      value: selected.parentProcessInstanceId ? (
                        <Copyable value={selected.parentProcessInstanceId} />
                      ) : selected.parentPid != null ? (
                        `pid ${selected.parentPid} (unresolved)`
                      ) : (
                        "no observed parent"
                      )
                    }
                  ]}
                />
              </div>

              <div className="detail-section">
                <div className="detail-section-label">observed lifetime</div>
                <KeyValueGrid
                  entries={[
                    { label: "First seen", value: formatTimestamp(selected.firstSeenNs), mono: true },
                    { label: "Last seen", value: formatTimestamp(selected.lastSeenNs), mono: true },
                    { label: "Events", value: formatNumber(selected.eventCount), mono: true },
                    { label: "Exit observed", value: selected.exitObserved ? "yes" : "no" },
                    { label: "Exit priority", value: selected.exitPriority ?? "—", mono: true },
                    { label: "Children", value: selected.childInstanceIds.length, mono: true }
                  ]}
                />
              </div>

              {selected.notes.length > 0 ? (
                <div className="detail-section">
                  <div className="detail-section-label">collector notes</div>
                  <ul className="dotted-list">
                    {selected.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                </div>
              ) : null}

              <div className="detail-section">
                <div className="detail-section-label">
                  related behavioral findings{analysis.loading ? " · evaluating" : ""}
                </div>
                {analysis.error ? (
                  <ErrorState compact message={analysis.error} onRetry={analysis.reload} />
                ) : findings.length === 0 ? (
                  <p className="state-body" style={{ marginTop: 0, textAlign: "left" }}>
                    {analysis.data
                      ? "No behavioral finding references this process instance."
                      : "Behavioral analysis is unavailable for this session."}
                  </p>
                ) : (
                  <div className="stack-sm">
                    {findings.map((finding) => (
                      <div key={finding.finding_id}>
                        <div className="row" style={{ marginBottom: 5 }}>
                          <SeverityBadge severity={finding.severity} />
                          <span style={{ fontSize: 11.5 }}>{finding.title}</span>
                        </div>
                        {finding.supporting_events
                          .filter((event) => event.process_instance_id === selected.processInstanceId)
                          .slice(0, 3)
                          .map((event) => (
                            <button
                              type="button"
                              className="supporting-event"
                              key={event.event_id}
                              onClick={() =>
                                navigate(
                                  investigationPath(
                                    sessionId,
                                    "timeline",
                                    event.event_id,
                                    selected.processInstanceId
                                  )
                                )
                              }
                            >
                              <span className="supporting-event-id">#{event.event_id}</span>
                              <span className="supporting-event-summary">{event.summary}</span>
                              <ChevronRight size={11} aria-hidden="true" />
                            </button>
                          ))}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="detail-section">
                <div className="row" style={{ flexWrap: "wrap" }}>
                  <Button
                    size="sm"
                    onClick={() =>
                      navigate(investigationPath(sessionId, "timeline", null, selected.processInstanceId))
                    }
                  >
                    Events for this process
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => navigate(investigationPath(sessionId, "analysis"))}>
                    <Fingerprint size={11} /> Behavioral analysis
                  </Button>
                </div>
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
