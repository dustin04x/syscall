import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ExportTab } from "./ExportTab";
import { mockCommands } from "../../test/mockCommands";
import { appInfo, exportResult, sessionDetail } from "../../test/fixtures";

describe("evidence export", () => {
  it("writes to the backend destination and reports the manifest", async () => {
    const invoke = mockCommands({
      app_info: appInfo,
      export_session: exportResult
    });
    render(<ExportTab detail={sessionDetail} />);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /Export evidence/ }));

    expect(await screen.findByText("Package written successfully")).toBeInTheDocument();
    expect(screen.getAllByText(exportResult.outputPath).length).toBeGreaterThan(0);
    expect(screen.getByText("events")).toBeInTheDocument();
    const call = invoke.mock.calls.find(([command]) => command === "export_session");
    expect(call?.[1]).toEqual({
      request: { sessionId: "phase7-session-001", force: false }
    });
  });

  it("requires explicit confirmation before replacing an existing export", async () => {
    const invoke = mockCommands({
      app_info: appInfo,
      export_session: (args: Record<string, unknown> | undefined) => {
        const request = args?.request as { force?: boolean } | undefined;
        if (!request?.force) {
          throw {
            code: "EXPORT_EXISTS",
            message: "export already exists at /exports/session.json; confirm overwrite to replace it"
          };
        }
        return exportResult;
      }
    });
    render(<ExportTab detail={sessionDetail} />);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /Export evidence/ }));
    expect(await screen.findByText("An export already exists")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Replace existing export/ }));
    expect(await screen.findByText("Package written successfully")).toBeInTheDocument();
    const forceCall = invoke.mock.calls
      .filter(([command]) => command === "export_session")
      .at(-1);
    expect(forceCall?.[1]).toEqual({
      request: { sessionId: "phase7-session-001", force: true }
    });
  });
});
