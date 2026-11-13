import {
  ArrowRightLeft,
  FilePenLine,
  LogOut,
  Network,
  Play,
  type LucideIcon
} from "lucide-react";

import type { EventType, EventView } from "../../types/contracts";

export function eventTypeLabel(type: EventType): string {
  switch (type) {
    case "process_exec":
      return "process exec";
    case "process_fork":
      return "process fork";
    case "process_exit":
      return "process exit";
    case "file_open":
      return "file open";
    case "network_connect":
      return "network connect";
  }
}

export function eventTypeIcon(type: EventType): LucideIcon {
  switch (type) {
    case "process_exec":
      return Play;
    case "process_fork":
      return ArrowRightLeft;
    case "process_exit":
      return LogOut;
    case "file_open":
      return FilePenLine;
    case "network_connect":
      return Network;
  }
}

export function eventSummary(event: EventView): string {
  const payload = event.payload;
  switch (payload.kind) {
    case "process_exec":
      return payload.filename;
    case "process_fork":
      return `${payload.childComm} (pid ${payload.childPid})`;
    case "process_exit":
      return `exit priority ${payload.exitPriority}`;
    case "file_open":
      return payload.path;
    case "network_connect":
      return `${payload.family} ${payload.destinationAddress}:${payload.destinationPort}`;
  }
}

export function eventResult(event: EventView): string {
  const payload = event.payload;
  if (payload.kind === "file_open" || payload.kind === "network_connect") {
    return payload.success ? "success" : `errno ${payload.errno ?? "—"}`;
  }
  return "—";
}

/* Track geometry per event type — taller bars for lifecycle events. */
export function eventTypeColor(type: EventType): string {
  switch (type) {
    case "process_exec":
      return "var(--ev-exec)";
    case "process_fork":
      return "var(--ev-fork)";
    case "process_exit":
      return "var(--ev-exit)";
    case "file_open":
      return "var(--ev-file)";
    case "network_connect":
      return "var(--ev-net)";
  }
}

export function eventTypeBarHeight(type: EventType): number {
  switch (type) {
    case "process_exec":
      return 30;
    case "process_fork":
      return 24;
    case "process_exit":
      return 24;
    case "network_connect":
      return 14;
    case "file_open":
      return 10;
  }
}
