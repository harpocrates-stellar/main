/**
 * StudioView cancel-button tests.
 * Renders the Evidence Studio with fixture hook returns so the Cancel button
 * visibility, label, click, and keyboard activation are deterministic.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StudioView } from './StudioView'
import type { InterruptedUploadSession, UseEvidenceReturn } from '../hooks/useEvidence'
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
    interruptedSession: null,
    message: 'Upload evidence to begin.',
    registration: null,
    networkMismatch: null,
    isCancellable: false,
    handleEvidence: vi.fn(),
    resumeInterruptedUpload: vi.fn(),
    dismissInterruptedSession: vi.fn(),
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

describe('StudioView – interrupted upload recovery', () => {
  const baseSourceIdentity = {
    fileName: 'clip.mp4',
    sizeBytes: 2048,
    lastModified: 1_700_000_000_000,
    mimeType: 'video/mp4',
    fingerprint: 'src-deadbeef',
  }

  function makeSession(overrides: Partial<InterruptedUploadSession>): InterruptedUploadSession {
    return {
      status: 'resumable',
      tier: 'silent',
      interruptedAt: 1_700_000_000_000,
      stageAtInterruption: 'embedding',
      reason: 'Temporary network outage.',
      sourceIdentity: baseSourceIdentity,
      hasInMemoryFile: false,
      sourceChanged: false,
      ...overrides,
    }
  }

  it('renders resumable, expired, and unrecoverable recovery choices distinctly and passes axe checks', async () => {
    const resumeInterruptedUpload = vi.fn().mockResolvedValue(false)
    const dismissInterruptedSession = vi.fn()

    const { container, rerender } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          interruptedSession: makeSession({ status: 'resumable', hasInMemoryFile: false }),
          resumeInterruptedUpload,
          dismissInterruptedSession,
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    expect(screen.getByRole('region', { name: /interrupted upload recovery/i })).toHaveAttribute(
      'data-session-status',
      'resumable',
    )
    expect(screen.getByText(/resumable session/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /verify source file to resume/i })).toBeInTheDocument()

    const recoveryInput = container.querySelector(
      '#studio-recovery-file-input',
    ) as HTMLInputElement
    const changedFile = new File(['different'], 'changed.mp4', { type: 'video/mp4' })
    fireEvent.change(recoveryInput, { target: { files: [changedFile] } })
    expect(resumeInterruptedUpload).toHaveBeenCalledWith(changedFile)

    expectNoA11yViolations(await runAxe(container), 'studio interrupted recovery resumable')

    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          interruptedSession: makeSession({ status: 'expired' }),
          resumeInterruptedUpload,
          dismissInterruptedSession,
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )
    expect(screen.getByText(/expired session/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /resume/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /start fresh upload/i })).toBeInTheDocument()

    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          interruptedSession: makeSession({
            status: 'unrecoverable',
            sourceChanged: true,
            reason: 'Selected source file differs from the interrupted session. Automatic retry is blocked.',
          }),
          resumeInterruptedUpload,
          dismissInterruptedSession,
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )
    expect(screen.getByText(/unrecoverable session/i)).toBeInTheDocument()
    expect(screen.getByText(/automatic retry is blocked/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /resume/i })).not.toBeInTheDocument()
    expectNoA11yViolations(await runAxe(container), 'studio interrupted recovery unrecoverable')
  })
})
