import '../App.css'
import { render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { UseVerificationReturn } from '../hooks/useVerification'
import { resolveIssuerTrust, type IssuerTrust } from '../provenance/issuerTrust'
import type { ProvenanceRecord } from '../provenance/provenanceModel'
import {
  evaluateStructuredVerificationResult,
  verifyUploadedVideo,
} from '../services/verificationFlow'
import * as verificationService from '../services/verificationService'
import type { ChainProofRecord } from '../stellarTypes'
import { expectNoA11yViolations, runAxe } from '../test/axeA11y'
import type { ProofEvent } from '../types'
import { VerifyView } from './VerifyView'

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
  getProofByVideoHash: vi.fn(),
  WatchWalletChanges: vi.fn(),
  connectFreighter: vi.fn(),
  getWalletNetwork: vi.fn(),
}))

vi.mock('../components/ChainProofPanel', () => ({
  ChainProofPanel: () => <div data-testid="chain-proof-panel" />,
  formatProofExpiry: () => 'Never',
}))

vi.mock('../components/VerifierSetStatusPanel', () => ({
  VerifierSetStatusPanel: () => <div data-testid="verifier-set-status-panel" />,
}))

vi.mock('../provenance/ProvenanceCard', () => ({
  default: () => <div data-testid="provenance-card" />,
}))

const VIDEO_HASH = '11'.repeat(32)
const METADATA_HASH = '22'.repeat(32)
const SOURCE_HASH = '33'.repeat(32)
const PROOF_ID = '44'.repeat(32)
const TX_HASH = '55'.repeat(32)
const SYNTHETIC_ISSUER = 'G' + 'A'.repeat(55)
const SYNTHETIC_CONTRACT = 'C' + 'B'.repeat(55)
const FIXED_NOW_SECONDS = 1_800_000_000

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    proofId: PROOF_ID,
    videoHash: VIDEO_HASH,
    metadataHash: METADATA_HASH,
    tier: 2,
    status: 1,
    createdAt: '2026-11-15T12:00:00.000Z',
    expiresAt: FIXED_NOW_SECONDS + 86_400,
    source: SOURCE_HASH,
    issuer: SYNTHETIC_ISSUER,
    ...overrides,
  }
}

function makeProvenance(overrides: Partial<ProvenanceRecord> = {}): ProvenanceRecord {
  return {
    circuit: { name: 'silent_witness', version: '1' },
    circuitVersion: 1,
    verifier: { contractId: SYNTHETIC_CONTRACT, method: 'verify_proof' },
    network: {
      passphrase: 'Test SDF Network ; September 2015',
      rpcUrl: 'https://soroban-testnet.stellar.org',
      label: 'Stellar Testnet',
    },
    ledger: {
      transactionHash: TX_HASH,
      status: 1,
      createdAt: '2026-11-15T12:00:00.000Z',
    },
    metadata: {
      videoHash: VIDEO_HASH,
      metadataHash: METADATA_HASH,
      sourceHash: SOURCE_HASH,
    },
    links: {
      transaction: null,
      contract: 'https://stellar.expert/explorer/testnet/contract/' + SYNTHETIC_CONTRACT,
    },
    mismatches: [],
    staleness: { stale: false },
    disputes: { openCount: 0 },
    fetchedAt: '2026-11-15T12:01:00.000Z',
    ...overrides,
  }
}

function makeEvent(overrides: Partial<ProofEvent> = {}): ProofEvent {
  return {
    id: 1,
    event_type: 'proof_submitted',
    file_name: 'synthetic-clip.mp4',
    video_hash: VIDEO_HASH,
    proof_id: PROOF_ID,
    tier: 'seal',
    tx_hash: TX_HASH,
    tx_status: 'SUCCESS',
    created_at: '2026-11-15T12:00:05.000Z',
    ...overrides,
  }
}

function makeHook(overrides: Partial<UseVerificationReturn> = {}): UseVerificationReturn {
  return {
    verifyHash: VIDEO_HASH,
    verifyResult:
      'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
    events: [makeEvent()],
    chainProof: makeChainProof(),
    status: 'success',
    errorCode: null,
    isVerifying: false,
    offline: false,
    setOffline: vi.fn(),
    verifyEvidence: vi.fn(),
    loadEvents: vi.fn(),
    loadSharedVerification: vi.fn(),
    cancel: vi.fn(),
    retry: vi.fn(),
    clear: vi.fn(),
    ...overrides,
  }
}

describe('Structured verification result model — independent trust dimensions (#1134)', () => {
  it('verifies all four dimensions independently for an active Institutional Seal and enables share link', async () => {
    const trustedIssuer: IssuerTrust = resolveIssuerTrust({
      issuer: SYNTHETIC_ISSUER,
      lookup: { kind: 'active' },
      expiresAt: FIXED_NOW_SECONDS + 86_400,
      now: FIXED_NOW_SECONDS,
    })

    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={makeProvenance()}
        issuerTrust={trustedIssuer}
        nowUnixSeconds={FIXED_NOW_SECONDS}
      />,
    )

    const verdictBanner = screen.getByTestId('structured-overall-verdict')
    expect(verdictBanner).toHaveAttribute('data-verdict', 'verified')
    expect(verdictBanner).toHaveTextContent(/Overall verdict: Verified/i)

    for (const id of [
      'contentIntegrity',
      'chainRegistration',
      'issuerTrust',
      'freshness',
    ] as const) {
      const card = screen.getByTestId(`trust-dimension-${id}`)
      expect(card).toHaveAttribute('data-dimension-status', 'verified')
      expect(within(card).getByTestId(`trust-dimension-badge-${id}`)).toHaveTextContent(
        'Verified',
      )
    }

    expect(
      screen.getByRole('button', { name: /copy shareable verification link/i }),
    ).toBeEnabled()

    expectNoA11yViolations(
      await runAxe(container),
      'VerifyView structured trust dimensions — all verified',
    )
  })

  it('prevents passing contentIntegrity, chainRegistration, and freshness from masking a revoked issuer', async () => {
    const revokedIssuer: IssuerTrust = resolveIssuerTrust({
      issuer: SYNTHETIC_ISSUER,
      lookup: { kind: 'inactive' },
      expiresAt: FIXED_NOW_SECONDS + 86_400,
      now: FIXED_NOW_SECONDS,
    })

    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={makeProvenance()}
        issuerTrust={revokedIssuer}
        nowUnixSeconds={FIXED_NOW_SECONDS}
      />,
    )

    const verdictBanner = screen.getByTestId('structured-overall-verdict')
    expect(verdictBanner).toHaveAttribute('data-verdict', 'rejected')
    expect(verdictBanner).toHaveTextContent(
      /Rejected: Issuer trust failed \(Content integrity, Chain registration, Freshness passed independently/i,
    )

    expect(screen.getByTestId('trust-dimension-contentIntegrity')).toHaveAttribute(
      'data-dimension-status',
      'verified',
    )
    expect(screen.getByTestId('trust-dimension-chainRegistration')).toHaveAttribute(
      'data-dimension-status',
      'verified',
    )
    expect(screen.getByTestId('trust-dimension-issuerTrust')).toHaveAttribute(
      'data-dimension-status',
      'failed',
    )
    expect(screen.getByTestId('trust-dimension-freshness')).toHaveAttribute(
      'data-dimension-status',
      'verified',
    )

    // Primary banner refuses to show misleading success text and share link is blocked
    expect(
      screen.getByText(/verification did not pass all trust dimensions/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /copy shareable verification link/i }),
    ).toBeDisabled()

    expectNoA11yViolations(
      await runAxe(container),
      'VerifyView structured trust dimensions — non-masking rejected state',
    )
  })

  it('prevents passing dimensions from masking single-dimension failures across contentIntegrity, chainRegistration, and freshness', () => {
    const trustedIssuer = resolveIssuerTrust({
      issuer: SYNTHETIC_ISSUER,
      lookup: { kind: 'active' },
      expiresAt: 0,
      now: FIXED_NOW_SECONDS,
    })

    // 1. contentIntegrity fails (metadataHash mismatch) while other 3 dimensions pass
    const contentFailure = evaluateStructuredVerificationResult({
      status: 'success',
      verifyHash: VIDEO_HASH,
      chainProof: makeChainProof({ expiresAt: 0 }),
      issuerTrust: trustedIssuer,
      provenanceRecord: makeProvenance({
        mismatches: [
          {
            field: 'metadataHash',
            manifestValue: 'aa'.repeat(32),
            chainValue: METADATA_HASH,
          },
        ],
      }),
      nowUnixSeconds: FIXED_NOW_SECONDS,
    })
    expect(contentFailure.overallVerdict).toBe('rejected')
    expect(contentFailure.failedDimensions).toEqual(['contentIntegrity'])
    expect(contentFailure.verifiedDimensions).toEqual([
      'chainRegistration',
      'issuerTrust',
      'freshness',
    ])

    // 2. chainRegistration fails (revoked on chain) while contentIntegrity, issuerTrust, freshness pass
    const chainFailure = evaluateStructuredVerificationResult({
      status: 'error',
      errorCode: 'REVOKED_EVIDENCE',
      verifyHash: VIDEO_HASH,
      chainProof: makeChainProof({ status: 2, expiresAt: 0 }),
      issuerTrust: trustedIssuer,
      provenanceRecord: makeProvenance(),
      nowUnixSeconds: FIXED_NOW_SECONDS,
    })
    expect(chainFailure.overallVerdict).toBe('rejected')
    expect(chainFailure.failedDimensions).toEqual(['chainRegistration'])
    expect(chainFailure.verifiedDimensions).toEqual([
      'contentIntegrity',
      'issuerTrust',
      'freshness',
    ])

    // 3. freshness fails (expired proof window) while contentIntegrity, chainRegistration, issuerTrust pass
    const freshnessFailure = evaluateStructuredVerificationResult({
      status: 'success',
      verifyHash: VIDEO_HASH,
      chainProof: makeChainProof({
        status: 1,
        expiresAt: FIXED_NOW_SECONDS - 60,
      }),
      issuerTrust: trustedIssuer,
      provenanceRecord: makeProvenance(),
      nowUnixSeconds: FIXED_NOW_SECONDS,
    })
    expect(freshnessFailure.overallVerdict).toBe('rejected')
    expect(freshnessFailure.failedDimensions).toEqual(['freshness'])
    expect(freshnessFailure.dimensions.freshness.reasonCode).toBe('PROOF_EXPIRED')
    expect(freshnessFailure.verifiedDimensions).toEqual([
      'contentIntegrity',
      'chainRegistration',
      'issuerTrust',
    ])
  })

  it('preserves identity tier separation (Silent Witness tier=0 vs Institutional Seal tier=2) and unconfirmed boundaries', () => {
    // Silent Witness (tier 0) carries no issuer by design -> issuerTrust is not-applicable, verdict verified
    const silentModel = evaluateStructuredVerificationResult({
      status: 'success',
      verifyHash: VIDEO_HASH,
      chainProof: makeChainProof({ tier: 0, issuer: null }),
      provenanceRecord: makeProvenance(),
      nowUnixSeconds: FIXED_NOW_SECONDS,
    })
    expect(silentModel.dimensions.issuerTrust.status).toBe('not-applicable')
    expect(silentModel.overallVerdict).toBe('verified')

    // Institutional Seal (tier 2) missing issuer -> fails closed on issuerTrust
    const missingSealIssuer = evaluateStructuredVerificationResult({
      status: 'success',
      verifyHash: VIDEO_HASH,
      chainProof: makeChainProof({ tier: 2, issuer: null }),
      provenanceRecord: makeProvenance(),
      nowUnixSeconds: FIXED_NOW_SECONDS,
    })
    expect(missingSealIssuer.dimensions.issuerTrust.status).toBe('failed')
    expect(missingSealIssuer.dimensions.issuerTrust.reasonCode).toBe('SEAL_ISSUER_MISSING')
    expect(missingSealIssuer.overallVerdict).toBe('rejected')

    // Unknown issuer on Tier 2 -> unconfirmed (passing dimensions do not promote unverified issuer to verified)
    const unknownIssuer = resolveIssuerTrust({
      issuer: SYNTHETIC_ISSUER,
      lookup: { kind: 'missing' },
      now: FIXED_NOW_SECONDS,
    })
    const unconfirmedModel = evaluateStructuredVerificationResult({
      status: 'success',
      verifyHash: VIDEO_HASH,
      chainProof: makeChainProof(),
      issuerTrust: unknownIssuer,
      provenanceRecord: makeProvenance(),
      nowUnixSeconds: FIXED_NOW_SECONDS,
    })
    expect(unconfirmedModel.dimensions.issuerTrust.status).toBe('unverified')
    expect(unconfirmedModel.overallVerdict).toBe('unconfirmed')
  })

  it('attaches structuredResult to verifyUploadedVideo and rejects missing embedded metadata even when chain record is active', async () => {
    const extractSpy = vi
      .spyOn(verificationService, 'extractMetadata')
      .mockResolvedValue({ hasHarpocratesMetadata: false })
    const eventsSpy = vi
      .spyOn(verificationService, 'fetchProofEventsByVideo')
      .mockResolvedValue([makeEvent()])
    const onChainSpy = vi
      .spyOn(verificationService, 'getOnChainProof')
      .mockResolvedValue(makeChainProof({ tier: 0, issuer: null }))

    try {
      const syntheticFile = new File(['synthetic-bytes'], 'clip.mp4', {
        type: 'video/mp4',
      })
      const result = await verifyUploadedVideo(syntheticFile, VIDEO_HASH, {
        nowUnixSeconds: FIXED_NOW_SECONDS,
      })

      expect(result.hasHarpocratesMetadata).toBe(false)
      expect(result.structuredResult.dimensions.contentIntegrity.status).toBe('failed')
      expect(result.structuredResult.dimensions.chainRegistration.status).toBe('verified')
      expect(result.structuredResult.dimensions.freshness.status).toBe('verified')
      expect(result.structuredResult.overallVerdict).toBe('rejected')
    } finally {
      extractSpy.mockRestore()
      eventsSpy.mockRestore()
      onChainSpy.mockRestore()
    }
  })
})
