/**
 * StudioView cancel-button tests.
 * Renders the Evidence Studio with fixture hook returns so the Cancel button
 * visibility, label, click, and keyboard activation are deterministic.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
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

describe('StudioView – pre-registration review screen', () => {
  it('shows selected identity tier, statement digest, and target network and gates registration until confirmed', async () => {
    const user = userEvent.setup()
    const registerProof = vi.fn()
    const fileA = new File(['video-a'], 'clip-a.mp4', { type: 'video/mp4', lastModified: 1000 })

    const { container } = renderStudio(
      makeEvidence({
        stage: 'ready',
        proof,
        file: fileA,
        registerProof,
      }),
    )

    const reviewRegion = screen.getByRole('region', {
      name: /evidence-processing review before registration/i,
    })
    expect(reviewRegion).toHaveAttribute('data-review-confirmed', 'false')
    expect(within(reviewRegion).getByText(/Silent Witness \(Anonymous Credential\)/)).toBeInTheDocument()
    expect(within(reviewRegion).getByText(/Stellar Testnet/)).toBeInTheDocument()
    const digestCode = reviewRegion.querySelector('code')
    expect(digestCode?.textContent).toMatch(/^[0-9a-f]{64}$/)

    const registerBtn = screen.getByRole('button', { name: /register proof/i })
    expect(registerBtn).toBeDisabled()

    expectNoA11yViolations(await runAxe(container), 'StudioView pre-registration review (unconfirmed)')

    await user.click(screen.getByRole('button', { name: /confirm registration review/i }))
    expect(reviewRegion).toHaveAttribute('data-review-confirmed', 'true')
    expect(registerBtn).toBeEnabled()

    await user.click(registerBtn)
    expect(registerProof).toHaveBeenCalledWith('GSOURCEGAUTH')
  })

  it('invalidates the confirmed review and disables Register proof when source file or proof parameters change', async () => {
    const user = userEvent.setup()
    const fileA = new File(['video-a'], 'clip-a.mp4', { type: 'video/mp4', lastModified: 1000 })
    const fileB = new File(['video-b-modified'], 'clip-b.mp4', {
      type: 'video/mp4',
      lastModified: 2000,
    })

    const { container, rerender } = render(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'ready',
          proof,
          file: fileA,
          credentialSeed: 'seed-one',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    await user.click(screen.getByRole('button', { name: /confirm registration review/i }))
    expect(screen.getByRole('button', { name: /register proof/i })).toBeEnabled()

    // Changing source file invalidates the review and disables Register proof.
    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'ready',
          proof,
          file: fileB,
          credentialSeed: 'seed-one',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const reviewRegion = screen.getByRole('region', {
      name: /evidence-processing review before registration/i,
    })
    expect(reviewRegion).toHaveAttribute('data-review-confirmed', 'false')
    expect(reviewRegion).toHaveAttribute('data-review-invalidated', 'true')
    expect(
      within(reviewRegion).getByText(
        /invalidated because the source file or proof parameters changed/i,
      ),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /register proof/i })).toBeDisabled()

    expectNoA11yViolations(await runAxe(container), 'StudioView pre-registration review (invalidated)')

    // Re-confirm, then change proof parameter (credentialSeed) -> invalidated again.
    await user.click(screen.getByRole('button', { name: /confirm registration review/i }))
    expect(screen.getByRole('button', { name: /register proof/i })).toBeEnabled()

    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'ready',
          proof,
          file: fileB,
          credentialSeed: 'seed-two',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )
    expect(reviewRegion).toHaveAttribute('data-review-confirmed', 'false')
    expect(reviewRegion).toHaveAttribute('data-review-invalidated', 'true')
    expect(screen.getByRole('button', { name: /register proof/i })).toBeDisabled()

    // Hiding and reopening preserves review toggle accessibility.
    await user.click(screen.getByRole('button', { name: /hide review/i }))
    expect(
      screen.queryByRole('region', { name: /evidence-processing review before registration/i }),
    ).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /review before registration/i }))
    expect(
      screen.getByRole('region', { name: /evidence-processing review before registration/i }),
    ).toBeInTheDocument()
  })
})
