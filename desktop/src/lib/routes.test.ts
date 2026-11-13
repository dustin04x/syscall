import { describe, expect, it } from "vitest";

import { investigationPath, parseRoute, tabLabel } from "./routes";

describe("workbench routes", () => {
  it("defaults to overview", () => {
    expect(parseRoute("")).toEqual({ kind: "overview" });
    expect(parseRoute("#/unknown")).toEqual({ kind: "overview" });
  });

  it("parses the session browser", () => {
    expect(parseRoute("#/sessions")).toEqual({ kind: "sessions" });
  });

  it("preserves the session, tab, event, and process context", () => {
    const hash = "#/sessions/phase7-session-001/timeline?event=42&process=proc-4100";
    expect(parseRoute(hash)).toEqual({
      kind: "investigation",
      sessionId: "phase7-session-001",
      tab: "timeline",
      eventId: 42,
      processInstanceId: "proc-4100"
    });
  });

  it("falls back to summary for an unknown investigation section", () => {
    expect(parseRoute("#/sessions/session-1/not-a-tab")).toMatchObject({
      kind: "investigation",
      tab: "summary"
    });
  });

  it("builds investigation links without losing the session", () => {
    expect(investigationPath("session-1", "processes")).toBe("/sessions/session-1/processes");
    expect(investigationPath("session-1", "timeline", 42)).toBe(
      "/sessions/session-1/timeline?event=42"
    );
    expect(investigationPath("session-1", "processes", null, "proc-9")).toBe(
      "/sessions/session-1/processes?process=proc-9"
    );
  });

  it("labels all investigation sections", () => {
    expect(tabLabel("summary")).toBe("Summary");
    expect(tabLabel("analysis")).toBe("Behavioral analysis");
    expect(tabLabel("export")).toBe("Evidence export");
  });
});
