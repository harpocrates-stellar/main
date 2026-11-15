import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import '../App.css'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { ChainProofRecord, Hex32 } from '../stellarTypes'
import type { ProvenanceRecord } from '../provenance/provenanceModel'
import {
  createVerificationResultSnapshotBinding,
  evaluateCachedVerificationFreshness,
} from '../services/verificationFlow'
import { expectNoA11yViolations, runAxe } from '../test/axeA11y'

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Future Network ; October 2022',
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

const HASH_A = '1'.repeat(64) as Hex32
const HASH_B = '2'.repeat(64) as Hex32
const META_A = 'a'.repeat(64) as Hex32
const SOURCE_A = 'b'.repeat(64) as Hex32
const PROOF_A = 'c'.repeat(64)

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: HASH_A,
    metadataHash: META_A,
    sourceHash: SOURCE_A,
    tier: 1,
    issuer: 'GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEF',
    createdAt: 1_750_000_000,
    expiresAt: 0,
    status: 1,
    ...overrides,
  }
}

function makeProvenance(overrides: Partial<ProvenanceRecord> = {}): ProvenanceRecord {
  return {
    circuit: { name: 'silent_witness', version: '1' },
    verifier: {
      contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
      method: 'verify_proof',
    },
    network: {
      passphrase: 'Test SDF Future Network ; October 2022',
      rpcUrl: 'https://soroban-testnet.stellar.org',
      label: 'Futurenet',
    },
    ledger: {
      transactionHash: 'd'.repeat(64),
      status: 1,
      createdAt: '2026-10-01T00:00:00Z',
    },
    metadata: {
      videoHash: HASH_A,
      metadataHash: META_A,
      sourceHash: SOURCE_A,
    },
    links: {
      transaction: null,
      contract: 'https://stellar.expert/contract',
    },
    mismatches: [],
    staleness: { stale: false },
    disputes: { openCount: 0 },
    fetchedAt: '2026-10-01T00:00:00Z',
    ...overrides,
  }
}

function makeHook(overrides: Partial<UseVerificationReturn> = {}): UseVerificationReturn {
  return {
    verifyHash: HASH_A,
    verifyResult: 'Confirmed on Soroban: artifact integrity and registry standing match.',
    events: [
      {
        id: 1,
        video_hash: HASH_A,
        proof_id: PROOF_A,
        tier: 'source',
        tx_hash: 'e'.repeat(64),
        created_at: '2026-10-01T00:00:00Z',
      },
    ],
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

describe('VerifyView stale verification snapshot guard (#1142)', () => {
  it('evaluates snapshot bindings deterministically across statement and trust context changes', () => {
    const baseInput = {
      videoHash: HASH_A,
      proofId: PROOF_A,
      metadataHash: META_A,
      networkPassphrase: 'Test SDF Future Network ; October 2022',
      contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
      offline: false,
      networkMismatch: null,
      chainStatus: 1,
      issuer: 'GABC',
    }
    const bound = createVerificationResultSnapshotBinding(baseInput)

    expect(evaluateCachedVerificationFreshness(bound, baseInput)).toEqual({
      fresh: true,
      reason: null,
      message: null,
    })

    expect(
      evaluateCachedVerificationFreshness(bound, { ...baseInput, videoHash: HASH_B }).reason,
    ).toBe('STATEMENT_CHANGED')

    expect(
      evaluateCachedVerificationFreshness(bound, {
        ...baseInput,
        networkPassphrase: 'Public Global Stellar Network ; September 2015',
      }).reason,
    ).toBe('NETWORK_CONTEXT_CHANGED')

    expect(
      evaluateCachedVerificationFreshness(bound, { ...baseInput, contractId: 'COTHER' }).reason,
    ).toBe('CONTRACT_CONTEXT_CHANGED')

    expect(
      evaluateCachedVerificationFreshness(bound, { ...baseInput, offline: true }).reason,
    ).toBe('VERIFICATION_MODE_CHANGED')

    expect(
      evaluateCachedVerificationFreshness(bound, { ...baseInput, chainStatus: 2 }).reason,
    ).toBe('TRUST_STANDING_CHANGED')
  })

  it('suppresses a cached success banner when a stale verification link changes the statement hash without a fresh check, and restores it only after an explicit re-verification', async () => {
    const provenance = makeProvenance()
    const initialHook = makeHook()

    const { container, rerender } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={initialHook}
        provenanceRecord={provenance}
      />,
    )

    expect(screen.getByText(/confirmed on soroban/i)).toBeInTheDocument()

    // Simulate navigating to a different verification link whose hash changed while cached status remained 'success'
    rerender(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({ verifyHash: HASH_B })}
        provenanceRecord={provenance}
      />,
    )

    expect(screen.queryByText(/confirmed on soroban/i)).not.toBeInTheDocument()
    expect(
      screen.getByText(/statement inputs changed since the last check/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/snapshot status: STATEMENT_CHANGED/i)).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /copy shareable verification link/i }),
    ).toBeDisabled()

    expectNoA11yViolations(await runAxe(container), 'VerifyView stale snapshot guard')

    // Transition through explicit 'verifying' -> 'success' for HASH_B
    rerender(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({
          verifyHash: HASH_B,
          status: 'verifying',
          isVerifying: true,
        })}
        provenanceRecord={provenance}
      />,
    )

    rerender(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({
          verifyHash: HASH_B,
          status: 'success',
          isVerifying: false,
          verifyResult: 'Freshly verified on Soroban for statement B.',
          events: [
            {
              id: 2,
              video_hash: HASH_B,
              proof_id: PROOF_A,
              tier: 'source',
              tx_hash: 'f'.repeat(64),
              created_at: '2026-10-02T00:00:00Z',
            },
          ],
          chainProof: makeChainProof({ videoHash: HASH_B }),
        })}
        provenanceRecord={makeProvenance({
          metadata: { videoHash: HASH_B, metadataHash: META_A, sourceHash: SOURCE_A },
        })}
      />,
    )

    expect(
      screen.getByText(/freshly verified on soroban for statement b/i),
    ).toBeInTheDocument()
    expect(
      screen.queryByText(/statement inputs changed since the last check/i),
    ).not.toBeInTheDocument()
  })

  it('invalidates cached success when the user edits statement inputs or when network/mode trust context diverges', async () => {
    const user = userEvent.setup()
    const provenance = makeProvenance()
    const { rerender } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={provenance}
      />,
    )

    expect(screen.getByText(/confirmed on soroban/i)).toBeInTheDocument()

    // Incompatible wallet network mismatch appears while cached result is displayed
    rerender(
      <VerifyView
        wallet="GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEF"
        networkMismatch="Connected wallet is on Public Global Stellar Network instead of Futurenet."
        verification={makeHook()}
        provenanceRecord={provenance}
      />,
    )

    expect(screen.queryByText(/confirmed on soroban/i)).not.toBeInTheDocument()
    expect(
      screen.getByText(/stellar network context changed since the last check/i),
    ).toBeInTheDocument()

    // Restore matching network, then edit Proof ID in form -> STATEMENT_CHANGED
    rerender(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={provenance}
      />,
    )
    expect(screen.getByText(/confirmed on soroban/i)).toBeInTheDocument()

    const proofIdField = screen.getByLabelText(/proof id/i)
    await user.clear(proofIdField)
    await user.type(proofIdField, '9'.repeat(64))

    expect(screen.queryByText(/confirmed on soroban/i)).not.toBeInTheDocument()
    expect(
      screen.getByText(/statement inputs changed since the last check/i),
    ).toBeInTheDocument()
  })
})
