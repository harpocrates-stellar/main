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

describe('StudioView – keyboard focus restoration on stage transitions', () => {
  it('restores focus to surviving controls or status heading across stage changes and avoids re-announcing the page on progress ticks', async () => {
    const file = new File(['bytes'], 'clip.mp4', { type: 'video/mp4' })
    const { container, rerender } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'hashing',
          isCancellable: true,
          file,
          hashProgress: { processedBytes: 256, totalBytes: 1024, percentage: 25 },
          message: 'Hashing video locally in the browser: 25% (256 / 1,024 bytes).',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const studioSection = container.querySelector('#studio') as HTMLElement
    expect(studioSection).not.toHaveAttribute('aria-busy')
    expect(studioSection).not.toHaveAttribute('aria-live')

    const cancelUpload = screen.getByRole('button', { name: 'Cancel upload' })
    cancelUpload.focus()
    expect(document.activeElement).toBe(cancelUpload)

    // Intra-stage progress update must NOT move keyboard focus or alter the stage live-region text.
    const liveStatus = container.querySelector('.sr-only[role="status"]') as HTMLElement
    const initialAnnouncement = liveStatus.textContent

    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'hashing',
          isCancellable: true,
          file,
          hashProgress: { processedBytes: 768, totalBytes: 1024, percentage: 75 },
          message: 'Hashing video locally in the browser: 75% (768 / 1,024 bytes).',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )
    expect(document.activeElement).toBe(cancelUpload)
    expect(liveStatus.textContent).toBe(initialAnnouncement)

    // Transition hashing -> ready (Cancel unmounts): focus moves to surviving enabled Register proof button.
    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'ready',
          isCancellable: false,
          file,
          proof,
          message: 'Embedded evidence package is ready for Stellar registration.',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )
    const registerButton = screen.getByRole('button', { name: /register proof/i })
    expect(document.activeElement).toBe(registerButton)

    // Transition ready -> proving -> cancelled: focus restores to the surviving dropzone control.
    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'proving',
          isCancellable: true,
          file,
          proof,
          message: 'Generating Silent Witness ZK proof locally.',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )
    expect(document.activeElement).toBe(
      screen.getByRole('button', { name: 'Cancel proof generation' }),
    )

    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'cancelled',
          isCancellable: false,
          file: null,
          proof: null,
          message: 'Proof generation cancelled.',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )
    expect(document.activeElement).toBe(container.querySelector('#studio-evidence-dropzone'))

    // Transition cancelled -> error (or ready with networkMismatch disabling Register proof): focus restores to status heading.
    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'error',
          isCancellable: false,
          message: 'Evidence hashing failed.',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )
    expect(document.activeElement).toBe(container.querySelector('#studio-heading'))
    expectNoA11yViolations(await runAxe(container), 'studio focus restoration')
  })

  it('does not steal focus from an active text input when background processing changes stage', () => {
    const file = new File(['bytes'], 'clip.mp4', { type: 'video/mp4' })
    const { rerender } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'hashing',
          isCancellable: true,
          file,
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const credentialInput = screen.getByLabelText(/credential seed/i)
    credentialInput.focus()
    expect(document.activeElement).toBe(credentialInput)

    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'ready',
          isCancellable: false,
          file,
          proof,
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )
    expect(document.activeElement).toBe(credentialInput)
  })
})
