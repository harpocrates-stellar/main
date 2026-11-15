/**
 * StudioView cancel-button tests.
 * Renders the Evidence Studio with fixture hook returns so the Cancel button
 * visibility, label, click, and keyboard activation are deterministic.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StudioView } from './StudioView'
import { CONCEALED_WITNESS_PLACEHOLDER, PROOF_PREPARATION_POLICY_VERSION, type UseEvidenceReturn } from '../hooks/useEvidence'
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
    isProofPreviewOpen: false,
    openProofPreview: vi.fn(),
    closeProofPreview: vi.fn(),
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

  it('renders a read-only proof preparation preview showing canonical public inputs and policy version while concealing witness secrets', async () => {
    const registerProof = vi.fn()
    const secretCred = '77777777777777'
    const secretNullifier = '88888888888888'

    const { container } = renderStudio(
      makeEvidence({
        stage: 'ready',
        proof: {
          ...proof,
          videoHash: '0'.repeat(31) + '3' + '0'.repeat(31) + '4',
        },
        credentialSeed: secretCred,
        nullifierSeed: secretNullifier,
        isProofPreviewOpen: true,
        openProofPreview: vi.fn(),
        closeProofPreview: vi.fn(),
        registerProof,
      }),
    )

    const region = screen.getByRole('region', { name: /read-only proof preparation preview/i })
    expect(region).toBeInTheDocument()
    expect(screen.getByTestId('preview-policy-version')).toHaveTextContent(PROOF_PREPARATION_POLICY_VERSION)
    expect(screen.getByTestId('preview-schema-version')).toHaveTextContent('v1')
    expect(screen.getByTestId('public-input-video_hash_hi')).toHaveTextContent('3')
    expect(screen.getByTestId('public-input-video_hash_lo')).toHaveTextContent('4')
    expect(screen.getByTestId('witness-credential_secret')).toHaveTextContent(CONCEALED_WITNESS_PLACEHOLDER)
    expect(screen.getByTestId('witness-nullifier_secret')).toHaveTextContent(CONCEALED_WITNESS_PLACEHOLDER)
    expect(region.textContent).not.toContain(secretCred)
    expect(region.textContent).not.toContain(secretNullifier)
    expect(registerProof).not.toHaveBeenCalled()
    expectNoA11yViolations(await runAxe(container), 'studio proof preparation preview')
  })
})