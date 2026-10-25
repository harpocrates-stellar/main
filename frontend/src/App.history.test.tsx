import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { createVerificationShareLink } from "./verificationShareLink";

const { cancelProving, loadSharedVerification } = vi.hoisted(() => ({
  cancelProving: vi.fn(),
  loadSharedVerification: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("./components/EvilEye", () => ({ default: () => null }));
vi.mock("./views/LandingView", () => ({ LandingView: () => <h1>Landing</h1> }));
vi.mock("./views/VerifyView", () => ({
  VerifyView: () => <h2>Verify Artifact</h2>,
}));
vi.mock("./views/StudioView", () => ({
  StudioView: () => <h2>Evidence Studio</h2>,
}));
vi.mock("./components/BatchVerificationWorkspace", () => ({
  default: () => <h2>Batch Workspace</h2>,
}));
vi.mock("./hooks/useWallet", () => ({
  useWallet: () => ({
    wallet: "",
    networkMismatch: null,
    connectWallet: vi.fn(),
  }),
}));
vi.mock("./hooks/useEvidence", () => ({
  useEvidence: () => ({
    stage: "idle",
    message: "",
    proof: null,
    registration: null,
    cancelProving,
  }),
}));
vi.mock("./hooks/useVerification", () => ({
  useVerification: () => ({ chainProof: null, loadSharedVerification }),
}));
vi.mock("./hooks/useOpenDisputeCount", () => ({
  useOpenDisputeCount: () => 0,
}));
vi.mock("./stellar", () => ({ CONTRACT_NETWORK_PASSPHRASE: "test-network" }));
vi.mock("./provenance/provenanceModel", () => ({
  buildProvenanceRecord: vi.fn(),
}));

describe("App browser history navigation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState(null, "", "/");
    Object.defineProperty(window, "scrollTo", {
      configurable: true,
      value: vi.fn(),
    });
  });

  it("pushes user view changes and follows simulated popstate events", async () => {
    render(<App />);

    await screen.findByRole("heading", { name: "Landing" });
    fireEvent.click(screen.getByRole("button", { name: /^evidence$/i }));
    await screen.findByRole("heading", { name: "Evidence Studio" });
    expect(window.location.hash).toBe("#studio");

    fireEvent.click(screen.getByRole("button", { name: /^verify$/i }));
    expect(
      screen.getByRole("heading", { name: "Verify Artifact" }),
    ).toBeInTheDocument();
    expect(window.location.hash).toBe("#verify");

    window.history.replaceState(null, "", "/#studio");
    fireEvent.popState(window);
    expect(
      screen.getByRole("heading", { name: "Evidence Studio" }),
    ).toBeInTheDocument();

    window.history.replaceState(null, "", "/");
    fireEvent.popState(window);
    expect(
      screen.getByRole("heading", { name: "Landing" }),
    ).toBeInTheDocument();
    expect(cancelProving).toHaveBeenCalledTimes(4);
  });

  it("follows manually edited hashes and still processes share-link payloads", async () => {
    const shareLink = createVerificationShareLink({
      videoHash: "a".repeat(64),
      proofId: "b".repeat(64),
      metadataHash: "c".repeat(64),
      network: "test-network",
      contractId: "test-contract",
    });
    if (!shareLink.ok)
      throw new Error("Expected a valid share-link test fixture");

    window.history.replaceState(null, "", shareLink.url);
    render(<App />);
    expect(
      screen.getByRole("heading", { name: "Verify Artifact" }),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(loadSharedVerification).toHaveBeenCalledWith(shareLink.payload),
    );

    window.history.replaceState(null, "", "/#batch");
    fireEvent(window, new Event("hashchange"));
    expect(
      await screen.findByRole("heading", { name: "Batch Workspace" }),
    ).toBeInTheDocument();
  });
});
