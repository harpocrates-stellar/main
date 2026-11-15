/**
 * StudioView cancel-button tests.
 * Renders the Evidence Studio with fixture hook returns so the Cancel button
 * visibility, label, click, and keyboard activation are deterministic.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
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

describe('StudioView – distinct selected evidence after file replacement', () => {
  it('clears stale verification badges upon file replacement while preserving an accessible explanation', async () => {
    const clearVerification = vi.fn()
    const handleEvidence = vi.fn().mockResolvedValue(undefined)
    const firstFile = new File(['first'], 'first.mp4', { type: 'video/mp4' })
    const secondFile = new File(['second'], 'second.mp4', { type: 'video/mp4' })

    const verificationWithBadges: UseVerificationReturn = {
      ...makeVerification(),
      verifyHash: proof.videoHash,
      verifyResult: 'Confirmed on Stellar registry.',
      chainProof: {
        tier: 2,
        status: 1,
        issuer: 'G'.repeat(56),
        source: 'G'.repeat(56),
        metadataHash: proof.metadataHash,
        expiresAt: 0,
      },
      clear: clearVerification,
    }

    const { container, rerender } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'ready',
          file: firstFile,
          proof,
          handleEvidence,
        })}
        verification={verificationWithBadges}
        provenanceRecord={null}
      />,
    )

    // Matching verification badges are visible before replacement.
    expect(screen.getByText('Confirmed on Stellar registry.')).toBeInTheDocument()
    expect(screen.queryByText('No on-chain match loaded.')).not.toBeInTheDocument()

    // Select a replacement file via Studio's dropzone input.
    const fileInput = container.querySelector('#studio-evidence-input') as HTMLInputElement
    fireEvent.change(fileInput, { target: { files: [secondFile] } })
    expect(clearVerification).toHaveBeenCalledTimes(1)
    expect(handleEvidence).toHaveBeenCalledWith(secondFile)

    // Even if stale verification props linger across a render before clearing settles, badges stay hidden and explained.
    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'hashing',
          file: secondFile,
          proof: null,
          evidenceChangeNotice:
            'Replacement evidence file selected. Previous verification and registration results were cleared so only the newly selected file is evaluated.',
        })}
        verification={verificationWithBadges}
        provenanceRecord={null}
      />,
    )

    expect(screen.queryByText('Confirmed on Stellar registry.')).not.toBeInTheDocument()
    expect(screen.getByText('No on-chain match loaded.')).toBeInTheDocument()
    const statusRegion = screen.getByRole('status', {
      name: /selected evidence replacement status/i,
    })
    expect(statusRegion).toHaveTextContent(/previous verification and registration results were cleared/i)
    expectNoA11yViolations(await runAxe(container), 'studio distinct selected evidence')
  })
})
