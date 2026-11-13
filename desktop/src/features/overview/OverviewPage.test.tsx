import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { OverviewPage } from "./OverviewPage";
import { mockCommands } from "../../test/mockCommands";
import { session } from "../../test/fixtures";

const overview = {
  totalSessions: 3,
  activeSessions: 0,
  completedSessions: 2,
  interruptedSessions: 1,
  recoveredSessions: 0,
  failedSessions: 0,
  sessionsWithLoss: 1,
  recentSessions: [session],
  recentFindingCounts: {
    informational: 0,
    low: 1,
    medium: 0,
    high: 0,
    critical: 0,
    total: 1
  },
  latestVerification: session.verification
};

describe("overview", () => {
  it("summarizes only backend-provided evidence", async () => {
    mockCommands({ get_overview: overview });
    render(<OverviewPage navigate={vi.fn()} />);

    expect(await screen.findByText("Evidence overview")).toBeInTheDocument();
    expect(screen.getByLabelText("Recent sessions")).toBeInTheDocument();
    expect(screen.getAllByText(/\/usr\/bin\/curl/).length).toBeGreaterThan(0);
    expect(screen.getByLabelText("Latest verification")).toBeInTheDocument();
    expect(screen.getAllByText("1").length).toBeGreaterThan(0);
  });

  it("opens the recent session in the investigation workspace", async () => {
    const navigate = vi.fn();
    mockCommands({ get_overview: overview });
    render(<OverviewPage navigate={navigate} />);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /\/usr\/bin\/curl/ }));
    expect(navigate).toHaveBeenCalledWith("/sessions/phase7-session-001/summary");
  });

  it("renders a truthful empty state when no sessions exist", async () => {
    mockCommands({
      get_overview: {
        ...overview,
        totalSessions: 0,
        completedSessions: 0,
        interruptedSessions: 0,
        sessionsWithLoss: 0,
        recentSessions: [],
        latestVerification: null
      }
    });
    render(<OverviewPage navigate={vi.fn()} />);

    expect(await screen.findByText("No recorded sessions")).toBeInTheDocument();
  });
});
