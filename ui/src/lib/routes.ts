export const investigationTabs = [
  "summary",
  "processes",
  "timeline",
  "filesystem",
  "network",
  "analysis",
  "verification",
  "export"
] as const;

export type InvestigationTab = (typeof investigationTabs)[number];

export type Route =
  | { kind: "overview" }
  | { kind: "sessions" }
  | {
      kind: "investigation";
      sessionId: string;
      tab: InvestigationTab;
      eventId: number | null;
      processInstanceId: string | null;
    };

export function isInvestigationTab(value: string | undefined): value is InvestigationTab {
  return !!value && (investigationTabs as readonly string[]).includes(value);
}

export function parseRoute(hash: string): Route {
  const raw = hash.replace(/^#\/?/, "");
  const [pathname = "", query = ""] = raw.split("?", 2);
  const segments = pathname.split("/").filter(Boolean).map(decodeURIComponent);
  if (segments[0] === "sessions" && segments[1]) {
    const params = new URLSearchParams(query);
    const eventParam = params.get("event");
    return {
      kind: "investigation",
      sessionId: segments[1],
      tab: isInvestigationTab(segments[2]) ? segments[2] : "summary",
      eventId: eventParam && /^\d+$/.test(eventParam) ? Number(eventParam) : null,
      processInstanceId: params.get("process")
    };
  }
  if (segments[0] === "sessions") return { kind: "sessions" };
  return { kind: "overview" };
}

export function investigationPath(
  sessionId: string,
  tab: InvestigationTab,
  eventId?: number | null,
  processInstanceId?: string | null
): string {
  const params = new URLSearchParams();
  if (eventId) params.set("event", String(eventId));
  if (processInstanceId) params.set("process", processInstanceId);
  const query = params.toString();
  const base = `/sessions/${encodeURIComponent(sessionId)}/${tab}`;
  return query ? `${base}?${query}` : base;
}

export function tabLabel(tab: InvestigationTab): string {
  switch (tab) {
    case "summary":
      return "Summary";
    case "processes":
      return "Processes";
    case "timeline":
      return "Timeline";
    case "filesystem":
      return "Filesystem";
    case "network":
      return "Network";
    case "analysis":
      return "Behavioral analysis";
    case "verification":
      return "Verification";
    case "export":
      return "Evidence export";
  }
}
