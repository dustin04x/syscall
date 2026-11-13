import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SessionsPage } from "./SessionsPage";
import { mockCommands } from "../../test/mockCommands";
import { session } from "../../test/fixtures";

describe("session browser", () => {
  it("lists recorded sessions with verification and finding counts", async () => {
    mockCommands({
      list_sessions: {
        sessions: [session],
        totalMatched: 1,
        intelligenceLimited: false
      }
    });
    render(<SessionsPage navigate={vi.fn()} />);

    expect(await screen.findByText(/\/usr\/bin\/curl/)).toBeInTheDocument();
    expect(screen.getByText("Valid, incomplete")).toBeInTheDocument();
    expect(screen.getAllByText("1").length).toBeGreaterThan(0);
    expect(screen.getByText(/1 of 1 sessions shown/)).toBeInTheDocument();
  });

  it("navigates to the preserved session workspace", async () => {
    const navigate = vi.fn();
    mockCommands({
      list_sessions: {
        sessions: [session],
        totalMatched: 1,
        intelligenceLimited: false
      }
    });
    render(<SessionsPage navigate={navigate} />);
    const user = userEvent.setup();

    await user.click(
      await screen.findByRole("button", { name: /Open investigation for \/usr\/bin\/curl/ })
    );
    expect(navigate).toHaveBeenCalledWith(
      "/sessions/phase7-session-001/summary"
    );
  });

  it("sends the selected status and sort order to the backend", async () => {
    const invoke = mockCommands({
      list_sessions: {
        sessions: [session],
        totalMatched: 1,
        intelligenceLimited: false
      }
    });
    render(<SessionsPage navigate={vi.fn()} />);
    const user = userEvent.setup();

    await screen.findByText(/\/usr\/bin\/curl/);
    await user.selectOptions(screen.getByLabelText("Status"), "completed");
    await waitFor(() => {
      const latest = invoke.mock.calls.at(-1);
      expect(latest?.[0]).toBe("list_sessions");
      expect(latest?.[1]).toMatchObject({
        request: {
          status: "completed",
          sortBy: "started",
          sortDirection: "desc",
          includeIntelligence: true
        }
      });
    });
  });

  it("shows a retryable error instead of fabricating sessions", async () => {
    mockCommands({
      list_sessions: () => {
        throw { code: "DB_UNAVAILABLE", message: "The evidence database is locked." };
      }
    });
    render(<SessionsPage navigate={vi.fn()} />);

    expect(await screen.findByText("The evidence database is locked.")).toBeInTheDocument();
    expect(screen.getByText("SESSION_QUERY_FAILED")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("renders a filtered empty state without inventing results", async () => {
    mockCommands({
      list_sessions: { sessions: [], totalMatched: 0, intelligenceLimited: false }
    });
    render(<SessionsPage navigate={vi.fn()} />);

    expect(await screen.findByText("No sessions recorded")).toBeInTheDocument();
    expect(screen.getByText(/Record a target with the syscall CLI/)).toBeInTheDocument();
  });
});
