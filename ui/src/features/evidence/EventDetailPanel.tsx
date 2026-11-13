import { X } from "lucide-react";

import type { EventView } from "../../types/contracts";
import {
  eventResult,
  eventSummary,
  eventTypeColor,
  eventTypeIcon,
  eventTypeLabel
} from "./eventDisplay";
import { formatFlags, formatTimestamp } from "../../lib/format";
import { Copyable } from "../../components/ui/CopyButton";
import { KeyValueGrid, type KeyValueEntry } from "../../components/ui/KeyValue";
import { ErrorState, LoadingState } from "../../components/ui/States";

export function EventDetailPanel({
  event,
  loading,
  error,
  onClose,
  onRetry
}: {
  event: EventView | null;
  loading: boolean;
  error: string | null;
  onClose: () => void;
  onRetry?: () => void;
}) {
  if (loading) {
    return (
      <aside className="split-side" aria-label="Event details">
        <LoadingState label="Reading event" />
      </aside>
    );
  }

  if (error) {
    return (
      <aside className="split-side" aria-label="Event details">
        <ErrorState compact message={error} onRetry={onRetry} />
      </aside>
    );
  }

  if (!event) {
    return (
      <aside className="split-side" aria-label="Event details">
        <div className="state-block">
          <div className="state-glyph" aria-hidden="true" />
          <div className="state-title">No event selected</div>
          <p className="state-body">
            Select an event to inspect its recorded payload, attribution, and provenance.
          </p>
        </div>
      </aside>
    );
  }

  const Icon = eventTypeIcon(event.eventType);
  const payload = event.payload;
  const payloadEntries: KeyValueEntry[] = [];

  switch (payload.kind) {
    case "process_exec":
      payloadEntries.push(
        { label: "Filename", value: payload.filename, mono: true },
        { label: "Parent pid", value: payload.ppid ?? "—", mono: true },
        { label: "Start ticks", value: payload.startTimeTicks ?? "—", mono: true },
        { label: "Old pid", value: payload.oldPid ?? "—", mono: true }
      );
      break;
    case "process_fork":
      payloadEntries.push(
        { label: "Parent pid", value: payload.parentPid, mono: true },
        { label: "Parent tgid", value: payload.parentTgid ?? "—", mono: true },
        { label: "Child pid", value: payload.childPid, mono: true },
        { label: "Child comm", value: payload.childComm, mono: true },
        { label: "Child start ticks", value: payload.childStartTimeTicks ?? "—", mono: true }
      );
      break;
    case "process_exit":
      payloadEntries.push(
        { label: "Parent pid", value: payload.ppid ?? "—", mono: true },
        { label: "Start ticks", value: payload.startTimeTicks ?? "—", mono: true },
        { label: "Exit priority", value: payload.exitPriority, mono: true }
      );
      break;
    case "file_open":
      payloadEntries.push(
        { label: "Path", value: payload.path, mono: true },
        { label: "Absolute path", value: payload.pathIsAbsolute ? "yes" : "no" },
        { label: "Truncated", value: payload.pathTruncated ? "yes" : "no" },
        { label: "Dirfd", value: payload.dirfd, mono: true },
        { label: "Flags", value: formatFlags(payload.flags), mono: true },
        { label: "Result", value: payload.result, mono: true },
        { label: "Success", value: payload.success ? "yes" : "no" },
        { label: "Errno", value: payload.errno ?? "—", mono: true }
      );
      break;
    case "network_connect":
      payloadEntries.push(
        { label: "Family", value: payload.family.toUpperCase(), mono: true },
        { label: "Source address", value: payload.sourceAddress ?? "—", mono: true },
        { label: "Source port", value: payload.sourcePort ?? "—", mono: true },
        { label: "Destination", value: payload.destinationAddress, mono: true },
        { label: "Destination port", value: payload.destinationPort, mono: true },
        { label: "Result", value: payload.result, mono: true },
        { label: "Success", value: payload.success ? "yes" : "no" },
        { label: "Errno", value: payload.errno ?? "—", mono: true },
        { label: "Established", value: payload.established ? "yes" : "no" }
      );
      break;
  }

  const provenance = event.provenance;

  return (
    <aside className="split-side detail-enter" key={event.id} aria-label="Event details">
      <div
        className="row-between"
        style={{
          padding: "12px 14px",
          borderBottom: "1px solid var(--line)",
          position: "sticky",
          top: 0,
          background: "var(--surface)",
          zIndex: 1
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div className="micro" style={{ marginBottom: 5 }}>
            recorded event
          </div>
          <div className="row" style={{ gap: 8 }}>
            <Icon size={12} style={{ color: eventTypeColor(event.eventType) }} aria-hidden="true" />
            <span style={{ fontFamily: "var(--font-display)", fontSize: 12.5, fontWeight: 550, letterSpacing: "0.02em" }}>
              {eventTypeLabel(event.eventType)}
            </span>
            <span className="mono faint" style={{ fontSize: 9.5 }}>
              #{event.id}
            </span>
          </div>
        </div>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Close event details">
          <X size={12} aria-hidden="true" />
        </button>
      </div>

      <div style={{ padding: "0 14px 16px" }}>
        <div className="detail-section" style={{ borderTop: 0 }}>
          <div className="detail-section-label">summary</div>
          <div className="code-block">{eventSummary(event)}</div>
        </div>

        <div className="detail-section">
          <div className="detail-section-label">attribution</div>
          <KeyValueGrid
            entries={[
              { label: "Event ID", value: <Copyable value={String(event.id)} /> },
              {
                label: "Process instance",
                value: <Copyable value={event.processInstanceId} display={event.processInstanceId} />
              },
              { label: "Timestamp", value: <span className="mono">{formatTimestamp(event.timestampNs)}</span> },
              { label: "Monotonic", value: <Copyable value={String(event.monotonicNs)} /> },
              { label: "PID / TID", value: `${event.pid} / ${event.tid}`, mono: true },
              { label: "PPID", value: event.ppid ?? "—", mono: true },
              { label: "UID / GID", value: `${event.uid} / ${event.gid}`, mono: true },
              { label: "Comm", value: event.comm, mono: true }
            ]}
          />
        </div>

        <div className="detail-section">
          <div className="detail-section-label">payload</div>
          <KeyValueGrid entries={payloadEntries} />
        </div>

        <div className="detail-section">
          <div className="detail-section-label">result</div>
          <div className="code-block">{eventResult(event)}</div>
        </div>

        <div className="detail-section">
          <div className="detail-section-label">provenance</div>
          {provenance ? (
            <KeyValueGrid
              entries={[
                { label: "Raw bpf pid", value: provenance.rawBpfPid ?? "—", mono: true },
                { label: "Raw bpf tgid", value: provenance.rawBpfTgid ?? "—", mono: true },
                { label: "Observer pid", value: provenance.observerPid ?? "—", mono: true },
                { label: "Observer tgid", value: provenance.observerTgid ?? "—", mono: true },
                { label: "Tracepoint", value: provenance.sourceTracepoint ?? "—", mono: true },
                { label: "Wire schema", value: provenance.wireSchemaVersion ?? "—", mono: true },
                { label: "Attribution", value: provenance.attributionMethod ?? "—", mono: true },
                { label: "Clock", value: provenance.timestampClockDomain ?? "—", mono: true }
              ]}
            />
          ) : (
            <p className="state-body" style={{ marginTop: 0, textAlign: "left" }}>
              Provenance was not retained for this event. Treat attribution as less certain.
            </p>
          )}
        </div>
      </div>
    </aside>
  );
}
