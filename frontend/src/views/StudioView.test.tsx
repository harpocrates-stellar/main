/**
 * StudioView cancel-button tests.
 * Renders the Evidence Studio with fixture hook returns so the Cancel button
 * visibility, label, click, and keyboard activation are deterministic.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StudioView } from './StudioView'
import type { UseEvidenceReturn } from '../hooks/useEvidence'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { ProofPackage } from '../types'
import { expectNoA11yViolations, runAxe } from '../test/axeA11y'

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

function renderStudio(evidence: UseEvidenceReturn) {
  return render(
    <StudioView wallet="GSOURCEGAUTH" evidence={evidence} verification={makeVerification()} provenanceRecord={null} />,
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

describe('StudioView – cancel button', () => {
  it('does not render a Cancel button outside busy stages', () => {
    renderStudio(makeEvidence({ stage: 'idle', proof }))
    expect(screen.queryByRole('button', { name: /cancel/i })).not.toBeInTheDocument()

    renderStudio(makeEvidence({ stage: 'ready', proof }))
    expect(screen.queryByRole('button', { name: /cancel/i })).not.toBeInTheDocument()
  })

  it('labels the button Cancel upload during the upload stage', () => {
    renderStudio(
      makeEvidence({ stage: 'embedding', isCancellable: true, proof, file: new File([], 'clip.mp4') }),
    )
    const cancel = screen.getByRole('button', { name: 'Cancel upload' })
    expect(cancel).toBeInTheDocument()
    expect(cancel).toHaveTextContent('Cancel upload')
  })

  it('labels the button Cancel proof generation during the proving stage', () => {
    renderStudio(makeEvidence({ stage: 'proving', isCancellable: true, proof }))
    const cancel = screen.getByRole('button', { name: 'Cancel proof generation' })
    expect(cancel).toBeInTheDocument()
    expect(cancel).toHaveTextContent('Cancel proof')
  })

  it('calls cancelEvidence on click', async () => {
    const user = userEvent.setup()
    const cancelEvidence = vi.fn()
    renderStudio(makeEvidence({ stage: 'embedding', isCancellable: true, proof, cancelEvidence }))

    await user.click(screen.getByRole('button', { name: 'Cancel upload' }))
    expect(cancelEvidence).toHaveBeenCalledTimes(1)
  })

  it('is keyboard-activatable', async () => {
    const user = userEvent.setup()
    const cancelEvidence = vi.fn()
    renderStudio(makeEvidence({ stage: 'proving', isCancellable: true, proof, cancelEvidence }))

    const cancel = screen.getByRole('button', { name: 'Cancel proof generation' })
    cancel.focus()
    await user.keyboard('{Enter}')
    expect(cancelEvidence).toHaveBeenCalledTimes(1)
  })
})

describe('StudioView – upload admission and queue state', () => {
  it('renders queue/capacity rejection with retry action distinct from invalid evidence replacement guidance', async () => {
    const user = userEvent.setup()
    const retryUploadAdmission = vi.fn().mockResolvedValue(true)
    const file = new File(['video'], 'clip.mp4', { type: 'video/mp4' })

    const { container, rerender } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'error',
          file,
          retryUploadAdmission,
          uploadAdmission: {
            status: 'deferred_queue',
            category: 'admission_rejected',
            reasonCode: 'QUEUE_FULL',
            queuePosition: 4,
            retryAfterSeconds: 15,
            retryable: true,
            summary: 'Upload deferred by admission queue (queue position 4).',
            nextStep:
              'Your evidence file passed local checks and does not need to be replaced. Retry after 15s.',
          },
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const region = screen.getByRole('region', { name: /upload admission & queue status/i })
    expect(region).toHaveAttribute('data-admission-status', 'deferred_queue')
    expect(region).toHaveAttribute('data-failure-category', 'admission_rejected')
    expect(screen.getByText(/queue position: #4/i)).toBeInTheDocument()
    expect(screen.getByText(/suggested retry window: 15s/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /retry upload admission/i }))
    expect(retryUploadAdmission).toHaveBeenCalledTimes(1)
    expectNoA11yViolations(await runAxe(container), 'studio upload admission rejected')

    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'error',
          file,
          retryUploadAdmission,
          uploadAdmission: {
            status: 'invalid_evidence',
            category: 'invalid_evidence',
            reasonCode: 'UNSUPPORTED_MEDIA_TYPE',
            queuePosition: null,
            retryAfterSeconds: null,
            retryable: false,
            summary: 'Unsupported file type. Use an MP4, WebM, or MOV video.',
            nextStep:
              'Convert or replace the artifact with an MP4, WebM, or MOV video before uploading.',
          },
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    expect(region).toHaveAttribute('data-admission-status', 'invalid_evidence')
    expect(region).toHaveAttribute('data-failure-category', 'invalid_evidence')
    expect(screen.queryByRole('button', { name: /retry upload admission/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /choose a different video file/i })).toBeInTheDocument()
    expectNoA11yViolations(await runAxe(container), 'studio invalid evidence state')
  })
})
