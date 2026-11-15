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

describe('StudioView – export privacy summary', () => {
  it('lists metadata classes and public identifiers without gating Silent Witness exports that expose no sensitive fields', async () => {
    const { container } = renderStudio(
      makeEvidence({
        stage: 'ready',
        proof,
        processedVideoUrl: 'blob:embedded-silent',
      }),
    )

    const summary = screen.getByRole('region', { name: /export privacy summary/i })
    expect(within(summary).getByRole('list', { name: /included metadata classes/i })).toBeInTheDocument()
    expect(within(summary).getByText(/portable harpocrates manifest/i)).toBeInTheDocument()
    expect(within(summary).getByText(/^Proof ID$/)).toBeInTheDocument()
    expect(within(summary).getByText(/explicit acknowledgement is not required/i)).toBeInTheDocument()

    const downloadLink = screen.getByRole('link', { name: /download harpocrates-clip\.mp4/i })
    expect(downloadLink).toHaveAttribute('href', 'blob:embedded-silent')
    expectNoA11yViolations(await runAxe(container), 'studio export privacy summary silent')
  })

  it('gates export until newly exposed sensitive fields are acknowledged, then unlocks without re-prompting previously acknowledged fields', async () => {
    const user = userEvent.setup()
    const sourceProof: ProofPackage = { ...proof, tier: 'source' }
    const { container, rerender } = render(
      <StudioView
        wallet={'G'.repeat(56)}
        evidence={makeEvidence({
          selectedTier: 'source',
          stage: 'ready',
          proof: sourceProof,
          processedVideoUrl: 'blob:embedded-source',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    expect(
      screen.getByRole('button', {
        name: /download harpocrates-clip\.mp4 \(requires sensitive field acknowledgement\)/i,
      }),
    ).toBeDisabled()
    expect(screen.queryByRole('link', { name: /download harpocrates-clip\.mp4/i })).not.toBeInTheDocument()
    expectNoA11yViolations(await runAxe(container), 'studio export privacy summary gated')

    await user.click(
      screen.getByRole('checkbox', {
        name: /i acknowledge exporting newly exposed sensitive fields: pseudonymous wallet address/i,
      }),
    )
    await user.click(screen.getByRole('button', { name: /confirm export disclosure/i }))

    expect(screen.getByRole('link', { name: /download harpocrates-clip\.mp4/i })).toHaveAttribute(
      'href',
      'blob:embedded-source',
    )

    // When a registration hash is later attached, only the newly exposed transaction reference requires acknowledgement.
    rerender(
      <StudioView
        wallet={'G'.repeat(56)}
        evidence={makeEvidence({
          selectedTier: 'source',
          stage: 'registered',
          proof: sourceProof,
          registration: { hash: 'f'.repeat(64), status: 'SUCCESS' },
          processedVideoUrl: 'blob:embedded-source',
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const checkbox = screen.getByRole('checkbox', {
      name: /i acknowledge exporting newly exposed sensitive fields: public stellar transaction reference/i,
    })
    expect(checkbox).not.toBeChecked()
    expect(screen.getByText(/previously acknowledged/i)).toBeInTheDocument()
  })
})
