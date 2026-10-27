import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ShareVerificationLink } from "./ShareVerificationLink";
import {
  MAX_SHARE_URL_BYTES,
  shareLinkErrorMessage,
  type VerificationShareLinkInput,
} from "../verificationShareLink";

const VALID_INPUT: VerificationShareLinkInput = {
  videoHash: "a".repeat(64),
  proofId: "b".repeat(64),
  metadataHash: "c".repeat(64),
  network: "Test SDF Network ; September 2015",
  contractId: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M",
};

let writeText: ReturnType<typeof vi.fn>;

beforeEach(() => {
  writeText = vi.fn();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
});

describe("ShareVerificationLink", () => {
  it("copies a valid link and communicates success", async () => {
    render(
      <ShareVerificationLink
        input={VALID_INPUT}
        baseUrl="https://share.example"
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Copy shareable verification link" }),
    );

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(
        expect.stringMatching(/^https:\/\/share\.example#verify\?p=/),
      );
    });
    expect(
      await screen.findByText(/Verification link copied\./),
    ).toBeInTheDocument();
  });

  it("communicates clipboard failure", async () => {
    writeText.mockRejectedValueOnce(new Error("Clipboard unavailable"));
    render(
      <ShareVerificationLink
        input={VALID_INPUT}
        baseUrl="https://share.example"
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Copy shareable verification link" }),
    );

    expect(
      await screen.findByText("Unable to copy the verification link."),
    ).toBeInTheDocument();
  });

  it("shows the mapped size-limit error for an oversized URL", () => {
    const baseUrl = `https://share.example/${"a".repeat(MAX_SHARE_URL_BYTES)}`;
    render(<ShareVerificationLink input={VALID_INPUT} baseUrl={baseUrl} />);

    expect(
      screen.getByRole("button", { name: "Copy shareable verification link" }),
    ).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent(
      shareLinkErrorMessage("OVERSIZED_URL"),
    );
  });
});
