import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ProcessesTab } from "./ProcessesTab";
import { mockCommands } from "../../test/mockCommands";
import { analysisReport, processTree } from "../../test/fixtures";

describe("process tree", () => {
  it("renders observed ancestry and resolves a selected process", async () => {
    const navigate = vi.fn();
    mockCommands({
      list_processes: processTree,
      run_analysis: analysisReport
    });
    render(<ProcessesTab sessionId="phase7-session-001" navigate={navigate} />);
    const user = userEvent.setup();

    expect(
      await screen.findByRole("button", { name: /curl, pid 4000/ })
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /sh, pid 4100/ }));

    expect(screen.getByText("/usr/bin/dash")).toBeInTheDocument();
    expect(screen.getByText("/bin/sh -c true")).toBeInTheDocument();
    expect(screen.getByText("Outbound connection from short-lived curl process")).toBeInTheDocument();
  });

  it("collapses and expands descendants without losing the session", async () => {
    mockCommands({ list_processes: processTree, run_analysis: analysisReport });
    render(<ProcessesTab sessionId="phase7-session-001" navigate={vi.fn()} />);
    const user = userEvent.setup();

    await screen.findByRole("button", { name: /sh, pid 4100/ });
    await user.click(screen.getByRole("button", { name: /Collapse descendants of curl/ }));
    expect(screen.queryByRole("button", { name: /sh, pid 4100/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Expand 1 descendant of curl/ }));
    expect(screen.getByRole("button", { name: /sh, pid 4100/ })).toBeInTheDocument();
  });

  it("opens the timeline scoped to the selected process", async () => {
    const navigate = vi.fn();
    mockCommands({ list_processes: processTree, run_analysis: analysisReport });
    render(<ProcessesTab sessionId="phase7-session-001" navigate={navigate} />);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /sh, pid 4100/ }));
    await user.click(screen.getByRole("button", { name: /Events for this process/ }));

    expect(navigate).toHaveBeenCalledWith(
      "/sessions/phase7-session-001/timeline?process=proc-4100"
    );
  });
});
