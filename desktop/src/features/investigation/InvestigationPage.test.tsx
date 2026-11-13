import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { InvestigationPage } from "./InvestigationPage";
import { mockCommands } from "../../test/mockCommands";
import { analysisReport, sessionDetail } from "../../test/fixtures";

describe("investigation workspace", () => {
  it("keeps the selected session when changing sections", async () => {
    const navigate = vi.fn();
    mockCommands({
      get_session: sessionDetail,
      run_analysis: analysisReport
    });
    render(
      <InvestigationPage
        sessionId={sessionDetail.session.id}
        tab="summary"
        eventId={null}
        processInstanceId={null}
        navigate={navigate}
      />
    );
    const user = userEvent.setup();

    expect(await screen.findByText("/usr/bin/curl --silent https://example.test")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Processes/ }));

    expect(navigate).toHaveBeenCalledWith(
      `/sessions/${sessionDetail.session.id}/processes`
    );
    expect(screen.getByText(/evidence composition/i)).toBeInTheDocument();
    expect(screen.getByText("Collector self-filtered")).toBeInTheDocument();
  });

  it("shows a session-not-found error with a path back", async () => {
    const navigate = vi.fn();
    mockCommands({
      get_session: () => {
        throw { code: "SESSION_NOT_FOUND", message: "Session not found." };
      }
    });
    render(
      <InvestigationPage
        sessionId="missing"
        tab="summary"
        eventId={null}
        processInstanceId={null}
        navigate={navigate}
      />
    );
    const user = userEvent.setup();

    expect(await screen.findByText("Session unavailable")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Return to session index/ }));
    expect(navigate).toHaveBeenCalledWith("/sessions");
  });
});
