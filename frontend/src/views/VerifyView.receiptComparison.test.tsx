import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import '../App.css'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'
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

function makeHook(overrides: Partial<UseVerificationReturn> = {}): UseVerificationReturn {
  return {
    verifyHash: '',
    verifyResult: '',
    events: [],
    chainProof: null,
    status: 'idle',
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

const VIDEO_HASH = '1'.repeat(64)
const META_HASH = 'a'.repeat(64)
const PROOF_ID = `0x${'b'.repeat(64)}`

function decodeCompareFragment(url: string): string {
  const encoded = url.split('#verify?compare=')[1] ?? ''
  const padded = encoded.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - (encoded.length % 4)) % 4)
  return atob(padded)
}

describe('VerifyView verification receipt comparison (#1139)', () => {
  it('highlights changed trust and chain observations with exact timestamps while stripping private metadata from shared URLs', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={null}
      />,
    )

    const baselineReceipt = {
      protocol: 'harpocrates-verification-receipt',
      version: 1,
      result: 'verified',
      verifiedAt: '2026-10-01T12:00:00.123Z',
      proofId: PROOF_ID,
      videoHash: VIDEO_HASH,
      metadataHash: META_HASH,
      tier: 'source',
      networkPassphrase: 'Test SDF Future Network ; October 2022',
      contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
      ledgerSequence: 120500,
      transactionHash: 'c'.repeat(64),
      circuitVersion: '1',
      verifierVersion: '1.0.0',
      signer: { keyId: 'portal-key-2026-q3', algorithm: 'ECDSA_P256_SHA256' },
      fileName: 'whistleblower-raw-footage.mp4',
      issuerNotes: 'confidential newsroom desk room 402',
    }

    const candidateReceipt = {
      protocol: 'harpocrates-verification-receipt',
      version: 1,
      result: 'unverified',
      verifiedAt: '2026-10-02T18:45:30.987Z',
      proofId: PROOF_ID,
      videoHash: VIDEO_HASH,
      metadataHash: META_HASH,
      tier: 'source',
      networkPassphrase: 'Test SDF Future Network ; October 2022',
      contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
      ledgerSequence: 121990,
      transactionHash: 'd'.repeat(64),
      circuitVersion: '1',
      verifierVersion: '1.1.0',
      signer: { keyId: 'portal-key-2026-q4', algorithm: 'ECDSA_P256_SHA256' },
      sourcePath: '/Users/reporter/private/evidence.mov',
    }

    fireEvent.change(screen.getByLabelText(/baseline receipt json/i), {
      target: { value: JSON.stringify(baselineReceipt) },
    })
    fireEvent.change(screen.getByLabelText(/candidate receipt json/i), {
      target: { value: JSON.stringify(candidateReceipt) },
    })

    await user.click(screen.getByRole('button', { name: /compare receipts/i }))

    expect(screen.getByTestId('comparison-baseline-timestamp')).toHaveTextContent(
      '2026-10-01T12:00:00.123Z',
    )
    expect(screen.getByTestId('comparison-candidate-timestamp')).toHaveTextContent(
      '2026-10-02T18:45:30.987Z',
    )

    // Trust changes highlighted with exact timestamps
    expect(screen.getByText(/changed trust observations \(3\)/i)).toBeInTheDocument()
    expect(
      screen.getByText(
        /verified \(2026-10-01T12:00:00\.123Z\) → unverified \(2026-10-02T18:45:30\.987Z\)/i,
      ),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/portal-key-2026-q3.*portal-key-2026-q4/i),
    ).toBeInTheDocument()

    // Chain changes highlighted with exact timestamps
    expect(screen.getByText(/changed chain observations \(2\)/i)).toBeInTheDocument()
    expect(
      screen.getByText(
        /#120500 \(2026-10-01T12:00:00\.123Z\) → #121990 \(2026-10-02T18:45:30\.987Z\)/i,
      ),
    ).toBeInTheDocument()

    // Shared URL never leaks private evidence metadata in raw URL or decoded payload
    const shareUrl = screen.getByTestId('receipt-comparison-share-url').textContent ?? ''
    expect(shareUrl).toContain('#verify?compare=')
    expect(shareUrl).not.toContain('whistleblower')
    expect(shareUrl).not.toContain('room 402')
    expect(shareUrl).not.toContain('evidence.mov')

    const decoded = decodeCompareFragment(shareUrl)
    expect(decoded).not.toContain('whistleblower')
    expect(decoded).not.toContain('402')
    expect(decoded).not.toContain('evidence.mov')
    expect(decoded).not.toContain('fileName')
    expect(decoded).not.toContain('issuerNotes')
    expect(decoded).not.toContain('sourcePath')

    expectNoA11yViolations(await runAxe(container), 'VerifyView receipt comparison')
  })

  it('fails closed with an accessible alert on malformed receipt JSON', async () => {
    const user = userEvent.setup()
    render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={null}
      />,
    )

    fireEvent.change(screen.getByLabelText(/baseline receipt json/i), {
      target: { value: '{broken json' },
    })
    fireEvent.change(screen.getByLabelText(/candidate receipt json/i), {
      target: { value: '{}' },
    })

    await user.click(screen.getByRole('button', { name: /compare receipts/i }))
    expect(screen.getByRole('alert')).toHaveTextContent(
      /invalid or malformed verification receipt json/i,
    )
  })
})
