import { render, screen } from '@testing-library/react'
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

const VIDEO_HASH = '1'.repeat(64) as Hex32
const META_HASH = 'a'.repeat(64) as Hex32

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: VIDEO_HASH,
    metadataHash: META_HASH,
    tier: 1,
    source: null,
    issuer: null,
    createdAt: '1750000000',
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
      videoHash: VIDEO_HASH,
      metadataHash: META_HASH,
      sourceHash: 'c'.repeat(64),
    },
    links: {
      transaction: null,
      contract: 'https://stellar.expert/contract',
    },
    mismatches: [],
    staleness: { stale: false },
    disputes: { openCount: 0 },
    fetchedAt: '2026-10-10T12:00:00Z',
    ...overrides,
  }
}

function makeHook(overrides: Partial<UseVerificationReturn> = {}): UseVerificationReturn {
  return {
    verifyHash: VIDEO_HASH,
    verifyResult: 'Confirmed on Soroban.',
    events: [
      {
        id: 5,
        video_hash: VIDEO_HASH,
        proof_id: `0x${'e'.repeat(64)}`,
        tier: 'source',
        tx_hash: 'f'.repeat(64),
        created_at: '2026-10-10T12:00:00Z',
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

describe('VerifyView timeline observation freshness and source disagreements (#1135)', () => {
  it('extends the existing 5-stage timeline with observation sources and ledger bounds while distinguishing stale observations from contradictions', async () => {
    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={makeProvenance({
          staleness: { stale: true, reason: 'fetched-long-ago' },
        })}
        ledgerBounds={{ minLedger: 510200, maxLedger: 510240 }}
      />,
    )

    // Existing 5-stage model remains intact
    expect(screen.getAllByText('Complete')).toHaveLength(5)

    // Observation source and ledger bounds are surfaced per stage
    expect(screen.getByTestId('timeline-meta-database')).toHaveTextContent(
      /Source: NeonDB proof event index/i,
    )
    expect(screen.getByTestId('timeline-meta-chain')).toHaveTextContent(
      /Source: Soroban HarpocratesRegistry · Bounds: Ledger #510200\.\.#510240/i,
    )

    // Stale evidence is explicitly distinguished from contradictory observations
    const freshness = screen.getByTestId('timeline-freshness-status')
    expect(freshness).toHaveAttribute('data-freshness-state', 'stale')
    expect(freshness).toHaveTextContent(/staleness reflects aged data rather than contradictory evidence/i)
    expect(
      screen.queryByTestId('timeline-source-disagreements'),
    ).not.toBeInTheDocument()
    expect(screen.getByTestId('timeline-no-contradiction-note')).toHaveTextContent(
      /no contradictory observations detected across sources/i,
    )

    expectNoA11yViolations(await runAxe(container), 'VerifyView stale timeline')
  })

  it('surfaces contradictory source observations distinctly when active sources disagree while observation is fresh', async () => {
    const freshNowIso = new Date().toISOString()
    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({
          // Event #5 claims tier "source" (1), whereas Soroban chainProof reports tier 2 ("seal")
          chainProof: makeChainProof({ tier: 2 }),
        })}
        provenanceRecord={makeProvenance({
          fetchedAt: freshNowIso,
          staleness: { stale: false },
          mismatches: [
            {
              field: 'metadataHash',
              manifestValue: META_HASH,
              chainValue: '9'.repeat(64),
            },
          ],
        })}
        ledgerBounds={{ observedLedger: 510300, maxLedger: 510305 }}
      />,
    )

    const freshness = screen.getByTestId('timeline-freshness-status')
    expect(freshness).toHaveAttribute('data-freshness-state', 'fresh')

    const disagreements = screen.getByTestId('timeline-source-disagreements')
    expect(disagreements).toHaveTextContent(/Source disagreements \(2\)/i)
    expect(disagreements).toHaveTextContent(
      /NeonDB proof event index vs Soroban HarpocratesRegistry/i,
    )
    expect(disagreements).toHaveTextContent(
      /Portable proof manifest vs Soroban HarpocratesRegistry/i,
    )

    expectNoA11yViolations(
      await runAxe(container),
      'VerifyView contradictory timeline',
    )
  })
})
