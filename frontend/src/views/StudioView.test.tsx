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
    file: null,
    proof: null,
    processedVideoUrl: '',
    credentialSeed: '',
    setCredentialSeed: vi.fn(),
    nullifierSeed: '',
    setNullifierSeed: vi.fn(),
    evidenceNotes: '',
    setEvidenceNotes: vi.fn(),
    message: 'Upload evidence to begin.',
    registration: null,
    networkMismatch: null,
    isCancellable: false,
    handleEvidence: vi.fn(),
    retryEvidence: vi.fn(),
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

describe('StudioView – evidence notes and recoverable failure retry', () => {
  it('renders the evidence notes textarea with current value and invokes setEvidenceNotes on edit', async () => {
    const user = userEvent.setup()
    const setEvidenceNotes = vi.fn()
    renderStudio(
      makeEvidence({
        evidenceNotes: 'Initial witness note',
        setEvidenceNotes,
      }),
    )

    const textarea = screen.getByRole('textbox', { name: 'Evidence notes' })
    expect(textarea).toBeInTheDocument()
    expect(textarea).toHaveValue('Initial witness note')

    await user.type(textarea, ' - additional detail')
    expect(setEvidenceNotes).toHaveBeenCalled()
  })

  it('renders a retry button when in error stage and invokes retryEvidence on click', async () => {
    const user = userEvent.setup()
    const retryEvidence = vi.fn()
    renderStudio(
      makeEvidence({
        stage: 'error',
        message: 'Steganography service did not accept the video.',
        retryEvidence,
      }),
    )

    const retryBtn = screen.getByRole('button', { name: 'Retry evidence processing' })
    expect(retryBtn).toBeInTheDocument()
    expect(retryBtn).toHaveTextContent('Retry evidence processing')

    await user.click(retryBtn)
    expect(retryEvidence).toHaveBeenCalledTimes(1)
  })

  it('does not render a retry button during non-error stages', () => {
    renderStudio(makeEvidence({ stage: 'ready' }))
    expect(screen.queryByRole('button', { name: 'Retry evidence processing' })).not.toBeInTheDocument()

    renderStudio(makeEvidence({ stage: 'idle' }))
    expect(screen.queryByRole('button', { name: 'Retry evidence processing' })).not.toBeInTheDocument()
  })

  it('renders evidence notes in the data list when proof includes notes', () => {
    const proofWithNotes: ProofPackage = {
      fileName: 'evidence.mp4',
      sourceHash: 'a'.repeat(64),
      videoHash: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
      proofId: 'd'.repeat(64),
      timestamp: '2026-01-01T00:00:00.000Z',
      tier: 'silent',
      evidenceNotes: 'Observed at 14:00 UTC',
    }
    renderStudio(makeEvidence({ stage: 'ready', proof: proofWithNotes }))
    expect(screen.getByText('Observed at 14:00 UTC')).toBeInTheDocument()
  })
})
