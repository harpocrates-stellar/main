import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import '../App.css'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { ChainProofRecord, Hex32 } from '../stellarTypes'
import type { ProvenanceRecord } from '../provenance/provenanceModel'
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

const HASH_ONE = '1'.repeat(64) as Hex32
const HASH_TWO = '2'.repeat(64) as Hex32
const META_ONE = 'a'.repeat(64) as Hex32
const SOURCE_ONE = 'b'.repeat(64) as Hex32
const PROOF_ONE = 'c'.repeat(64)

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: HASH_ONE,
    metadataHash: META_ONE,
    sourceHash: SOURCE_ONE,
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
      videoHash: HASH_ONE,
      metadataHash: META_ONE,
      sourceHash: SOURCE_ONE,
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
    verifyHash: HASH_ONE,
    verifyResult: 'Confirmed on Soroban: artifact integrity and registry standing match.',
    events: [
      {
        id: 1,
        video_hash: HASH_ONE,
        proof_id: PROOF_ONE,
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

describe('VerifyView verification export preview (#1141)', () => {
  it('displays included fields, freshness, and unresolved checks and exports the exact reviewed result without silently refreshing trust context', async () => {
    const user = userEvent.setup()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const hook = makeHook()
    const provenance = makeProvenance()

    const { container, rerender } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={hook}
        provenanceRecord={provenance}
      />,
    )

    await user.click(screen.getByRole('button', { name: /prepare export preview/i }))

    expect(screen.getByTestId('export-preview-freshness')).toHaveTextContent(
      /fresh: Fresh online registry observation/i,
    )
    expect(screen.getByText(/included fields \(10\)/i)).toBeInTheDocument()
    expect(screen.getByText(/unresolved checks \(0\)/i)).toBeInTheDocument()
    expect(
      screen.getByText(/none — all required online verification checks resolved/i),
    ).toBeInTheDocument()

    expectNoA11yViolations(await runAxe(container), 'VerifyView export preview')

    // Mutate live trust context AFTER the user reviewed the preview
    rerender(
      <VerifyView
        wallet=""
        networkMismatch="Wallet switched to Mainnet after review."
        verification={makeHook({
          verifyHash: HASH_TWO,
          verifyResult: 'Later unreviewed state.',
          chainProof: makeChainProof({ videoHash: HASH_TWO, status: 2 }),
        })}
        provenanceRecord={makeProvenance({
          network: {
            passphrase: 'Public Global Stellar Network ; September 2015',
            rpcUrl: 'https://mainnet.stellar.org',
            label: 'Mainnet',
          },
          staleness: { stale: true, reason: 'fetched-long-ago' },
        })}
      />,
    )

    expect(
      screen.getByText(/live portal state changed after this preview was captured/i),
    ).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /export reviewed result json/i }))

    // Verify zero silent network/trust refreshes occurred
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(hook.loadEvents).not.toHaveBeenCalled()
    expect(hook.loadSharedVerification).not.toHaveBeenCalled()

    const exportedRaw = screen.getByTestId('exported-verification-json').textContent ?? ''
    const exported = JSON.parse(exportedRaw) as {
      statementHash: string
      verdictSummary: string
      freshness: { state: string }
      trustContext: { networkPassphrase: string; chainStatusLabel: string }
      unresolvedChecks: unknown[]
    }

    // Exported snapshot preserves the exact reviewed context (HASH_ONE, Futurenet, Confirmed, fresh)
    expect(exported.statementHash).toBe(HASH_ONE)
    expect(exported.verdictSummary).toMatch(/confirmed on soroban/i)
    expect(exported.freshness.state).toBe('fresh')
    expect(exported.trustContext.networkPassphrase).toBe(
      'Test SDF Future Network ; October 2022',
    )
    expect(exported.trustContext.chainStatusLabel).toBe('Confirmed')
    expect(exported.unresolvedChecks).toHaveLength(0)

    fetchSpy.mockRestore()
  })

  it('enumerates unresolved checks clearly for offline or partial verification results', async () => {
    const user = userEvent.setup()
    render(
      <VerifyView
        wallet=""
        networkMismatch="Wallet network differs from configured registry."
        verification={makeHook({
          offline: true,
          chainProof: null,
          events: [],
          verifyResult: 'Locally inspected envelope.',
        })}
        provenanceRecord={null}
      />,
    )

    await user.click(screen.getByRole('button', { name: /prepare export preview/i }))

    expect(screen.getByTestId('export-preview-freshness')).toHaveTextContent(
      /unverified: Offline local inspection only/i,
    )
    expect(screen.getByText(/soroban registry standing:/i)).toBeInTheDocument()
    expect(screen.getByText(/neondb event corroboration:/i)).toBeInTheDocument()
    expect(screen.getByText(/wallet network alignment:/i)).toBeInTheDocument()
    expect(screen.getByText(/metadata commitment digest:/i)).toBeInTheDocument()
  })
})
