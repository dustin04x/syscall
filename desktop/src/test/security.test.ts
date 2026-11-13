import { describe, expect, it, vi } from "vitest";

import { api } from "../lib/api";
import { appInfo } from "./fixtures";

const sourceModules = import.meta.glob("../**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true
}) as Record<string, string>;

describe("desktop IPC boundary", () => {
  it("has a single Tauri IPC entry point outside tests", () => {
    const offenders = Object.entries(sourceModules)
      .filter(
        ([path]) =>
          !path.startsWith("./") &&
          !path.includes("/test/") &&
          !/\.test\.(ts|tsx)$/.test(path)
      )
      .filter(([path]) => path !== "../lib/api.ts")
      .filter(([, source]) => source.includes("@tauri-apps/api/core"))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });

  it("does not use raw HTML injection or browser shells", () => {
    const unsafe = Object.entries(sourceModules)
      .filter(
        ([path]) =>
          !path.startsWith("./") &&
          !path.includes("/test/") &&
          !/\.test\.(ts|tsx)$/.test(path)
      )
      .filter(([, source]) =>
        /dangerouslySetInnerHTML|@tauri-apps\/plugin-(shell|fs|dialog|http)/.test(source)
      )
      .map(([path]) => path);
    expect(unsafe).toEqual([]);
  });

  it("sends export requests without a caller-supplied filesystem path", async () => {
    const invoke = vi.mocked((await import("@tauri-apps/api/core")).invoke);
    invoke.mockResolvedValue({
      sessionId: "s",
      outputPath: "/managed/s.json",
      formatVersion: "syscall-export/v2",
      bytesWritten: 1,
      manifest: [],
      status: "exported"
    });

    await api.exportSession("s", true);

    expect(invoke).toHaveBeenCalledWith("export_session", {
      request: { sessionId: "s", force: true }
    });
    const args = invoke.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(args).not.toHaveProperty("output");
    expect(args).not.toHaveProperty("path");
  });

  it("remains read-only and does not expose recording controls", () => {
    expect(appInfo.readOnly).toBe(true);
    expect(appInfo.recordingSupported).toBe(false);
  });
});
