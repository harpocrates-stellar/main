/**
 * StudioView file-replacement tests.
 * Verifies that replacing an evidence file in Studio clears stale verification
 * badges, results, and provenance state, preserves an accessible privacy-safe
 * explanation of the changed state, and handles boundary/failure cases cleanly.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { StudioView } from './StudioView'
import { EVIDENCE_REPLACED_MESSAGE, type UseEvidenceReturn } from '../hooks/useEvidence'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofPackage } from '../types'
import type { ProvenanceRecord } from '../provenance/provenanceModel'

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
}))

vi.mock('../components/ChainProofPanel', () => ({
  ChainProofPanel: ({ chainProof }: { chainProof: ChainProofRecord | null }) =>
    chainProof ? (
      <div data-testid="chain-proof-badge" role="status">
        Issuer trusted
      </div>
    ) : (
      <p className="muted">No on-chain match loaded.</p>
    ),
}))

vi.mock('../components/VerifierSetStatusPanel', () => ({
  VerifierSetStatusPanel: () => <div data-testid="verifier-set-status-panel" />,
}))

function makeVerification(overrides: Partial<UseVerificationReturn> = {}): UseVerificationReturn {
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
    cancel: vi.fn(),
    retry: vi.fn(),
    loadSharedVerification: vi.fn(),
    clear: vi.fn(),
    ...overrides,
  }
}

function makeEvidence(overrides: Partial<UseEvidenceReturn> = {}): UseEvidenceReturn {
  return {
    selectedTier: 'silent',
    setSelectedTier: vi.fn(),
    selectedTierMeta: {
      id: 'silent',
      title: 'Silent Witness',
      label: 'Anonymous Credential',
      icon: vi.fn(),
      description: 'Noir ZK proof.',
    },
    stage: 'idle',
    hashProgress: null,
    file: null,
    proof: null,
    processedVideoUrl: '',
    credentialSeed: '',
    setCredentialSeed: vi.fn(),
    nullifierSeed: '',
    setNullifierSeed: vi.fn(),
    message: 'Upload evidence to begin.',
    evidenceChangeNotice: null,
    clearEvidenceChangeNotice: vi.fn(),
    registration: null,
    networkMismatch: null,
    isCancellable: false,
    handleEvidence: vi.fn(),
    registerProof: vi.fn(),
    cancelEvidence: vi.fn(),
    cancelProving: vi.fn(),
    ...overrides,
  }
}

const verifiedChainProof: ChainProofRecord = {
  videoHash: 'b'.repeat(64),
  metadataHash: 'c'.repeat(64),
  proofId: 'd'.repeat(64),
  tier: 0,
  status: 1,
  expiresAt: 0,
  issuer: 'GISSUERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  source: 'GSOURCEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  createdAt: '2026-01-01T00:00:00.000Z',
}

const verifiedProvenance: ProvenanceRecord = {
  circuit: { name: 'silent_witness', version: '1' },
  verifier: { contractId: 'CCONTRACT', method: 'register_anonymous_verified' },
  network: {
    passphrase: 'Test SDF Network ; September 2015',
    rpcUrl: 'https://soroban-testnet.stellar.org',
    label: 'Stellar Testnet',
  },
  ledger: {
    transactionHash: 'e'.repeat(64),
    status: 1,
    createdAt: '2026-01-01T00:00:00.000Z',
  },
  metadata: {
    videoHash: 'b'.repeat(64),
    metadataHash: 'c'.repeat(64),
    sourceHash: 'a'.repeat(64),
  },
  links: { transaction: null, contract: 'https://example.invalid/contract' },
  mismatches: [],
  staleness: { stale: false },
  disputes: { openCount: null },
  fetchedAt: '2026-01-01T00:05:00.000Z',
}

describe('StudioView – file replacement clears stale verification badges', () => {
  let proof: ProofPackage

  beforeEach(() => {
    proof = {
      fileName: 'harpocrates-clip.mp4',
      sourceHash: 'a'.repeat(64),
      videoHash: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
      proofId: 'd'.repeat(64),
      timestamp: '2026-01-01T00:00:00.000Z',
      tier: 'silent',
    }
  })

  it('clears stale verification badges and preserves an accessible explanation when replacing the file', () => {
    const handleEvidence = vi.fn()
    const clear = vi.fn()
    const evidence = makeEvidence({
      stage: 'registered',
      file: new File(['first'], 'original-clip.mp4', { type: 'video/mp4' }),
      proof,
      registration: { hash: 'e'.repeat(64), status: 'SUCCESS' },
      handleEvidence,
    })
    const verification = makeVerification({
      verifyHash: 'b'.repeat(64),
      verifyResult:
        'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
      chainProof: verifiedChainProof,
      status: 'success',
      clear,
    })

    const { container } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={evidence}
        verification={verification}
        provenanceRecord={verifiedProvenance}
      />,
    )

    // Before replacement: previous verification badge and confirmed result are displayed.
    expect(screen.getByTestId('chain-proof-badge')).toHaveTextContent('Issuer trusted')
    expect(screen.getByText(/confirmed: embedded harpocrates metadata/i)).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /provenance record/i })).toBeInTheDocument()
    expect(screen.queryByTestId('studio-evidence-change-notice')).not.toBeInTheDocument()

    // Replace the Studio evidence file.
    const studioFileInput = container.querySelector('.dropzone input[type="file"]') as HTMLInputElement
    const replacementFile = new File(['second'], 'replacement-clip.mp4', { type: 'video/mp4' })
    fireEvent.change(studioFileInput, { target: { files: [replacementFile] } })

    expect(clear).toHaveBeenCalledTimes(1)
    expect(handleEvidence).toHaveBeenCalledWith(replacementFile)

    // After replacement: stale verification badge, Quick Verify result, and verified provenance are cleared.
    expect(screen.queryByTestId('chain-proof-badge')).not.toBeInTheDocument()
    expect(screen.getByText('No on-chain match loaded.')).toBeInTheDocument()
    expect(screen.getByText('No verification run yet.')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /provenance record/i })).not.toBeInTheDocument()

    // Accessible status notice explains the changed state without leaking filenames or hashes.
    const notice = screen.getByTestId('studio-evidence-change-notice')
    expect(notice).toHaveAttribute('role', 'status')
    expect(notice).toHaveAttribute('aria-live', 'polite')
    expect(notice).toHaveAttribute('aria-atomic', 'true')
    expect(notice).toHaveTextContent(EVIDENCE_REPLACED_MESSAGE)
    expect(notice.textContent).not.toContain('original-clip.mp4')
    expect(notice.textContent).not.toContain('replacement-clip.mp4')
    expect(notice.textContent).not.toContain('b'.repeat(16))
  })

  it('does not clear verification badges when file selection is cancelled (empty selection boundary)', () => {
    const handleEvidence = vi.fn()
    const clear = vi.fn()
    const evidence = makeEvidence({
      stage: 'ready',
      file: new File(['first'], 'original-clip.mp4', { type: 'video/mp4' }),
      proof,
      handleEvidence,
    })
    const verification = makeVerification({
      verifyHash: 'b'.repeat(64),
      verifyResult:
        'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
      chainProof: verifiedChainProof,
      status: 'success',
      clear,
    })

    const { container } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={evidence}
        verification={verification}
        provenanceRecord={verifiedProvenance}
      />,
    )

    const studioFileInput = container.querySelector('.dropzone input[type="file"]') as HTMLInputElement
    fireEvent.change(studioFileInput, { target: { files: [] } })

    expect(clear).not.toHaveBeenCalled()
    expect(handleEvidence).not.toHaveBeenCalled()
    expect(screen.getByTestId('chain-proof-badge')).toHaveTextContent('Issuer trusted')
    expect(screen.queryByTestId('studio-evidence-change-notice')).not.toBeInTheDocument()
  })

  it('preserves the accessible replacement notice on processing failure and clears it on fresh Quick Verify', () => {
    const clearEvidenceChangeNotice = vi.fn()
    const verifyEvidence = vi.fn()
    const evidence = makeEvidence({
      stage: 'error',
      file: new File(['broken'], 'broken.mp4', { type: 'video/mp4' }),
      proof: null,
      message: 'Evidence hashing failed.',
      evidenceChangeNotice: EVIDENCE_REPLACED_MESSAGE,
      clearEvidenceChangeNotice,
    })
    const verification = makeVerification({
      verifyEvidence,
    })

    const { container } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={evidence}
        verification={verification}
        provenanceRecord={null}
      />,
    )

    const notice = screen.getByTestId('studio-evidence-change-notice')
    expect(notice).toHaveAttribute('role', 'status')
    expect(notice).toHaveTextContent(EVIDENCE_REPLACED_MESSAGE)
    expect(screen.queryByTestId('chain-proof-badge')).not.toBeInTheDocument()

    const quickVerifyInput = container.querySelector('.verify-input input[type="file"]') as HTMLInputElement
    const receivedFile = new File(['received'], 'received.mp4', { type: 'video/mp4' })
    fireEvent.change(quickVerifyInput, { target: { files: [receivedFile] } })

    expect(clearEvidenceChangeNotice).toHaveBeenCalledTimes(1)
    expect(verifyEvidence).toHaveBeenCalledWith(receivedFile, 'GSOURCEGAUTH')
  })

  it('clears the replacement notice once a fresh registration completes for the new file', () => {
    const handleEvidence = vi.fn()
    const clear = vi.fn()
    const initialEvidence = makeEvidence({
      stage: 'registered',
      file: new File(['first'], 'original-clip.mp4', { type: 'video/mp4' }),
      proof,
      registration: { hash: 'e'.repeat(64), status: 'SUCCESS' },
      handleEvidence,
    })
    const initialVerification = makeVerification({
      verifyHash: 'b'.repeat(64),
      verifyResult: 'Confirmed.',
      chainProof: verifiedChainProof,
      status: 'success',
      clear,
    })

    const { container, rerender } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={initialEvidence}
        verification={initialVerification}
        provenanceRecord={verifiedProvenance}
      />,
    )

    const studioFileInput = container.querySelector('.dropzone input[type="file"]') as HTMLInputElement
    fireEvent.change(studioFileInput, {
      target: { files: [new File(['second'], 'replacement-clip.mp4', { type: 'video/mp4' })] },
    })

    expect(screen.getByTestId('studio-evidence-change-notice')).toBeInTheDocument()

    // Simulate a fresh registration completing for the replacement file (new tx hash).
    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'registered',
          file: new File(['second'], 'replacement-clip.mp4', { type: 'video/mp4' }),
          proof: { ...proof, videoHash: 'f'.repeat(64), proofId: '9'.repeat(64) },
          registration: { hash: '1'.repeat(64), status: 'SUCCESS' },
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    expect(screen.queryByTestId('studio-evidence-change-notice')).not.toBeInTheDocument()
  })
})
