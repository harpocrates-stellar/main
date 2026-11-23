/**
 * Focus-restoration tests for the Evidence Studio stage flow.
 *
 * These cover the requested behavior and its boundary: focus returns to a
 * surviving control or the status heading only when the control the user was
 * on disappears or disables, and is never stolen while a usable control keeps
 * focus.
 *
 * The registry module is mocked because the reviewed baseline still contains
 * duplicate exports in `src/harpocratesRegistry.ts`, which makes Vite unable to
 * parse any suite that imports the studio's chain panels. The mock is a test
 * harness only; it does not change product behavior.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { StudioView } from './StudioView'
import type { UseEvidenceReturn } from '../hooks/useEvidence'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { ProofPackage } from '../types'

vi.mock('../harpocratesRegistry', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
  correctProof: vi.fn(),
  expireProof: vi.fn(),
  getIssuerRecord: vi.fn().mockResolvedValue(null),
  getOpenDisputeCount: vi.fn(),
  getProofByVideoHash: vi.fn(),
  getProofHistory: vi.fn(),
  getProofHistoryAt: vi.fn(),
  getProofHistoryCount: vi.fn(),
  getVerifierState: vi.fn().mockResolvedValue(null),
  registerProofOnStellar: vi.fn(),
  verifyProof: vi.fn(),
}))

function makeVerification(): UseVerificationReturn {
  return {
    verifyHash: '',
    verifyResult: '',
    events: [],
    chainProof: null,
    status: 'idle',
    errorCode: null,
    isVerifying: false,
    verifyEvidence: vi.fn(),
    loadEvents: vi.fn(),
    cancel: vi.fn(),
    retry: vi.fn(),
    clear: vi.fn(),
  }
}

function makeEvidence(overrides: Partial<UseEvidenceReturn>): UseEvidenceReturn {
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

function studio(evidence: UseEvidenceReturn) {
  return (
    <StudioView
      wallet="GSOURCEGAUTH"
      evidence={evidence}
      verification={makeVerification()}
      provenanceRecord={null}
    />
  )
}

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

describe('StudioView – stage focus restoration', () => {
  it('moves focus to the status heading when the focused cancel control is removed', () => {
    const { rerender } = render(
      studio(makeEvidence({ stage: 'embedding', isCancellable: true, proof })),
    )
    const cancel = screen.getByRole('button', { name: 'Cancel upload' })
    cancel.focus()
    expect(cancel).toHaveFocus()

    rerender(studio(makeEvidence({ stage: 'cancelled', isCancellable: false, proof })))

    expect(screen.queryByRole('button', { name: 'Cancel upload' })).not.toBeInTheDocument()
    const heading = screen.getByRole('heading', { name: 'Cancelled' })
    expect(heading).toHaveAttribute('tabindex', '-1')
    expect(heading).toHaveFocus()
  })

  it('leaves focus on a surviving control instead of moving it on a stage change', () => {
    const { rerender } = render(
      studio(
        makeEvidence({
          stage: 'hashing',
          hashProgress: { processedBytes: 0, totalBytes: 100, percentage: 0 },
        }),
      ),
    )
    const dropzone = screen.getByRole('button', { name: /choose a video file/i })
    dropzone.focus()

    rerender(
      studio(
        makeEvidence({
          stage: 'embedding',
          hashProgress: { processedBytes: 100, totalBytes: 100, percentage: 100 },
        }),
      ),
    )

    expect(dropzone).toHaveFocus()
    expect(screen.getByRole('heading', { name: 'Embedding metadata…' })).not.toHaveFocus()
  })

  it('focuses the Register proof control when processing completes after focus loss', () => {
    const { rerender } = render(
      studio(makeEvidence({ stage: 'proving', isCancellable: true, proof })),
    )
    screen.getAllByRole('button', { name: 'Cancel proof generation' })[0].focus()

    rerender(studio(makeEvidence({ stage: 'ready', isCancellable: false, proof })))

    expect(screen.getByRole('button', { name: /register proof/i })).toHaveFocus()
  })

  it('falls back to the status heading when the next action is disabled', () => {
    const { rerender } = render(
      studio(makeEvidence({ stage: 'proving', isCancellable: true, proof })),
    )
    screen.getAllByRole('button', { name: 'Cancel proof generation' })[0].focus()

    rerender(
      studio(
        makeEvidence({
          stage: 'ready',
          isCancellable: false,
          proof,
          networkMismatch: 'Switch Freighter to Testnet.',
        }),
      ),
    )

    expect(screen.getByRole('button', { name: /register proof/i })).toBeDisabled()
    expect(screen.getByRole('heading', { name: 'Evidence package ready' })).toHaveFocus()
  })
})
