import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { AnalysisTab } from "./AnalysisTab";
import { mockCommands } from "../../test/mockCommands";
import { analysisReport } from "../../test/fixtures";

describe("behavioral analysis", () => {
  it("renders findings and filters by severity without changing the report", async () => {
    mockCommands({ run_analysis: analysisReport });
    render(<AnalysisTab sessionId="phase7-session-001" navigate={vi.fn()} />);
    const user = userEvent.setup();

    expect(
      (await screen.findAllByText("Outbound connection from short-lived curl process")).length
    ).toBeGreaterThan(0);
    expect(screen.getAllByText("NET-001").length).toBeGreaterThan(0);

    await user.selectOptions(screen.getByLabelText("Severity"), "high");
    expect(screen.getByText("No matches")).toBeInTheDocument();
    expect(screen.getByText(/Clear one or more finding filters/)).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Severity"), "");
    expect(
      screen.getAllByText("Outbound connection from short-lived curl process").length
    ).toBeGreaterThan(0);
  });

  it("opens supporting evidence with the event context", async () => {
    const navigate = vi.fn();
    mockCommands({ run_analysis: analysisReport });
    render(<AnalysisTab sessionId="phase7-session-001" navigate={navigate} />);
    const user = userEvent.setup();

    await screen.findByText("Outbound connection from short-lived curl process");
    await user.click(await screen.findByRole("button", { name: /\/etc\/ssl\/certs/ }));

    expect(navigate).toHaveBeenCalledWith(
      "/sessions/phase7-session-001/timeline?event=42"
    );
  });

  it("shows explicit limitations supplied by the analysis report", async () => {
    mockCommands({ run_analysis: analysisReport });
    render(<AnalysisTab sessionId="phase7-session-001" navigate={vi.fn()} />);

    expect(await screen.findByText("Analysis is limited to persisted evidence.")).toBeInTheDocument();
    expect(screen.getByText(/Findings are observations, not verdicts/)).toBeInTheDocument();
  });
});
