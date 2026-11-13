import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { VerificationTab } from "./VerificationTab";
import { mockCommands } from "../../test/mockCommands";
import { verificationReport } from "../../test/fixtures";

describe("verification", () => {
  it("distinguishes structural validity from evidence completeness", async () => {
    mockCommands({ run_verification: verificationReport });
    render(<VerificationTab sessionId="phase7-session-001" navigate={vi.fn()} />);

    expect(await screen.findByText("Valid, incomplete")).toBeInTheDocument();
    expect(
      screen.getAllByText(/structurally valid, but collection counters or coverage gaps/).length
    ).toBeGreaterThan(0);
    expect(screen.getByText("Evidence coverage is incomplete")).toBeInTheDocument();
  });

  it("links an affected event into the timeline", async () => {
    const navigate = vi.fn();
    mockCommands({ run_verification: verificationReport });
    render(<VerificationTab sessionId="phase7-session-001" navigate={navigate} />);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /Inspect event #42/ }));
    expect(navigate).toHaveBeenCalledWith(
      "/sessions/phase7-session-001/timeline?event=42"
    );
  });
});
