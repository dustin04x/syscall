import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";

import type { EventView, EventType } from "../../types/contracts";
import { eventTypeBarHeight, eventTypeColor, eventTypeLabel } from "../evidence/eventDisplay";

/*
 * TimelineTrack — the forensic time band.
 *
 * A continuous track under the loaded window of events. Markers are placed
 * proportionally to their recorded timestamps; type, color and height carry
 * the semantics. Nothing here is synthesized: only loaded, persisted events
 * are drawn, and the window bounds are labeled as such.
 */

const HEIGHT = 96;
const BASELINE = HEIGHT - 26;
const PAD_X = 14;

function useTrackWidth<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const observer = new ResizeObserver(() => setWidth(element.clientWidth));
    observer.observe(element);
    setWidth(element.clientWidth);
    return () => observer.disconnect();
  }, []);
  return { ref, width };
}

function timeLabel(ns: number, spanNs: number): string {
  const date = new Date(ns / 1_000_000);
  const iso = date.toISOString();
  if (spanNs < 2_000_000_000) return iso.slice(11, 23);
  if (spanNs < 200_000_000_000) return iso.slice(11, 19);
  return iso.slice(5, 19).replace("T", " ");
}

export function TimelineTrack({
  events,
  selectedEventId,
  onSelect
}: {
  events: EventView[];
  selectedEventId: number | null;
  onSelect: (event: EventView) => void;
}) {
  const { ref, width } = useTrackWidth<HTMLDivElement>();

  const [minNs, maxNs] = useMemo(() => {
    if (events.length === 0) return [0, 0];
    let min = events[0]!.timestampNs;
    let max = min;
    for (const event of events) {
      if (event.timestampNs < min) min = event.timestampNs;
      if (event.timestampNs > max) max = event.timestampNs;
    }
    if (max === min) max = min + 1;
    return [min, max];
  }, [events]);

  const spanNs = maxNs - minNs;

  const scale = useMemo(() => {
    const usable = Math.max(width - PAD_X * 2, 1);
    return (ns: number) => PAD_X + ((ns - minNs) / spanNs) * usable;
  }, [width, minNs, spanNs]);

  const ticks = useMemo(() => {
    if (!width || events.length === 0) return [];
    const count = Math.max(2, Math.min(7, Math.floor(width / 140)));
    return Array.from({ length: count }, (_, index) => {
      const t = minNs + (spanNs * index) / (count - 1);
      return { ns: t, x: scale(t) };
    });
  }, [width, events.length, minNs, spanNs, scale]);

  const selected = selectedEventId != null ? events.find((event) => event.id === selectedEventId) ?? null : null;

  return (
    <div className="tl-track-wrap" ref={ref}>
      {events.length === 0 || !width ? (
        <svg className="tl-svg" width={Math.max(width, 0)} height={HEIGHT} aria-hidden="true" />
      ) : (
        <svg
          className="tl-svg"
          width={width}
          height={HEIGHT}
          viewBox={`0 0 ${width} ${HEIGHT}`}
          role="img"
          aria-label={`Timeline band of ${events.length} events between ${timeLabel(minNs, spanNs)} and ${timeLabel(maxNs, spanNs)} UTC`}
        >
          {ticks.map((tick) => (
            <g key={tick.ns}>
              <line className="tl-gridline" x1={tick.x} y1={18} x2={tick.x} y2={BASELINE} />
              <text className="tl-tick-label" x={tick.x} y={12} textAnchor="middle">
                {timeLabel(tick.ns, spanNs)}
              </text>
            </g>
          ))}

          <line className="tl-baseline" x1={0} y1={BASELINE} x2={width} y2={BASELINE} />

          {events.map((event, index) => {
            const x = scale(event.timestampNs);
            const h = eventTypeBarHeight(event.eventType);
            const isSelected = event.id === selectedEventId;
            return (
              <g
                key={event.id}
                className={`tl-marker ${isSelected ? "selected" : ""}`.trim()}
                tabIndex={0}
                role="button"
                aria-label={`Event ${event.id}, ${eventTypeLabel(event.eventType)}, ${new Date(event.timestampNs / 1_000_000).toISOString()}`}
                onKeyDown={(enterEvent) => {
                  if (enterEvent.key === "Enter" || enterEvent.key === " ") {
                    enterEvent.preventDefault();
                    onSelect(event);
                  }
                }}
                onClick={() => onSelect(event)}
                style={{ "--d": index } as CSSProperties}
              >
                <title>
                  {`#${event.id} · ${eventTypeLabel(event.eventType)} · ${timeLabel(event.timestampNs, spanNs)}`}
                </title>
                {/* generous hit target behind the visible bar */}
                <rect
                  x={x - 4}
                  y={BASELINE - h - 6}
                  width={8}
                  height={h + 6}
                  fill="transparent"
                />
                <rect
                  className="tl-bar"
                  x={x - 1}
                  y={BASELINE - h}
                  width={2}
                  height={h}
                  fill={eventTypeColor(event.eventType)}
                />
              </g>
            );
          })}

          {selected ? (
            <line
              className="tl-cursor on"
              x1={scale(selected.timestampNs)}
              y1={16}
              x2={scale(selected.timestampNs)}
              y2={HEIGHT - 6}
            />
          ) : null}
        </svg>
      )}
      <div className="tl-legend" role="list" aria-label="Event type legend">
        {(
          [
            ["process_exec", "exec"],
            ["process_fork", "fork"],
            ["process_exit", "exit"],
            ["network_connect", "connect"],
            ["file_open", "file open"]
          ] as Array<[EventType, string]>
        ).map(([type, label]) => (
          <span className="tl-legend-item" role="listitem" key={type}>
            <i style={{ background: eventTypeColor(type) }} aria-hidden="true" />
            {label}
          </span>
        ))}
        <span className="tl-legend-item" style={{ marginLeft: "auto" }}>
          window {timeLabel(minNs, spanNs)} → {timeLabel(maxNs, spanNs)} UTC · loaded events
        </span>
      </div>
    </div>
  );
}
