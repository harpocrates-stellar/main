/**
 * StudioView cancel-button tests.
 * Renders the Evidence Studio with fixture hook returns so the Cancel button
 * visibility, label, click, and keyboard activation are deterministic.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
  getVerifierState: vi.fn().mockResolvedValue(null),
  expireProof: vi.fn(),
  correctProof: vi.fn(),
}))

vi.mock('../harpocratesRegistry', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
  getVerifierState: vi.fn().mockResolvedValue(null),
  getOpenDisputeCount: vi.fn().mockResolvedValue(0),
  getProofHistory: vi.fn().mockResolvedValue({ entries: [], total: 0 }),
  expireProof: vi.fn(),
  correctProof: vi.fn(),
}))

import { StudioView } from './StudioView'
import { buildProofPreparationPreview } from '../proofPreparationPreview'
import type { UseEvidenceReturn } from '../hooks/useEvidence'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { ProofPackage } from '../types'

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
}))
vi.mock('../hooks/useIssuerTrust', () => ({
  useIssuerTrust: () => ({ trust: null, isLoading: false }),
}))
vi.mock('../hooks/useVerifierState', () => ({
  useVerifierState: () => ({ state: null, isLoading: false }),
}))
vi.mock('../hooks/useProofRevocationReason', () => ({
  useProofRevocationReason: () => ({ reason: null }),
}))
vi.mock('../hooks/useWallet', () => ({
  useWallet: () => ({ wallet: '', connectWallet: vi.fn(), networkMismatch: null }),
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
    evidenceNotes: '',
    setEvidenceNotes: vi.fn(),
    message: 'Upload evidence to begin.',
    proofPreparation: buildProofPreparationPreview({ proof: null, tier: 'silent' }),
    acknowledgedSensitiveFields: [],
    acknowledgeSensitiveFields: vi.fn(),
    registration: null,
    networkMismatch: null,
    networkMismatchRecovery: null,
    isCancellable: false,
    review: null,
    reviewInvalidatedReason: null,
    openReview: vi.fn(),
    closeReview: vi.fn(),
    handleEvidence: vi.fn(),
    retryEvidence: vi.fn(),
    registerProof: vi.fn(),
    revalidateNetworkMismatch: vi.fn(),
    cancelEvidence: vi.fn(),
    cancelProving: vi.fn(),
    interruptedSession: { category: 'none', fileName: null, interruptedAt: null },
    resumeEvidence: vi.fn(),
    discardEvidence: vi.fn(),
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

describe('StudioView – proof preparation preview', () => {
  it('shows canonical public inputs and the policy version before proving', () => {
    const preparation = buildProofPreparationPreview({
      proof,
      tier: 'silent',
      verifierScope: '0',
      epoch: 20_000,
    })

    renderStudio(makeEvidence({ stage: 'ready', proof, proofPreparation: preparation }))

    const region = screen.getByRole('region', {
      name: 'Read-only proof preparation preview',
    })
    expect(region).toHaveTextContent('silent_witness/input-v1')
    expect(region).toHaveTextContent(BigInt(`0x${'b'.repeat(32)}`).toString(10))
    expect(region).toHaveTextContent('20000')
    expect(region).toHaveTextContent('[REDACTED]')
    expect(within(region).queryAllByRole('button')).toHaveLength(0)
  })

  it('is hidden for identity tiers that do not generate a zero-knowledge proof', () => {
    const sourceMeta = {
      id: 'source' as const,
      title: 'Consistent Source',
      label: 'Pseudonymous Wallet',
      icon: vi.fn(),
      description: 'Freighter signature links evidence to a recurring Stellar source.',
    }

    renderStudio(
      makeEvidence({
        selectedTier: 'source',
        selectedTierMeta: sourceMeta,
        stage: 'ready',
        proof: { ...proof, tier: 'source' },
        proofPreparation: buildProofPreparationPreview({
          proof: { ...proof, tier: 'source' },
          tier: 'source',
        }),
      }),
    )

    expect(
      screen.queryByRole('region', { name: 'Read-only proof preparation preview' }),
    ).not.toBeInTheDocument()
  })
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

describe('StudioView – evidence processing review', () => {
  it('shows Review before registering button and opens review on click', async () => {
    const user = userEvent.setup()
    const openReview = vi.fn()
    renderStudio(makeEvidence({ stage: 'ready', proof, openReview }))

    const reviewBtn = screen.getByRole('button', { name: /review before registering/i })
    expect(reviewBtn).toBeEnabled()
    await user.click(reviewBtn)
    expect(openReview).toHaveBeenCalledTimes(1)
  })

  it('renders identity tier, statement digest, and network in the review screen', async () => {
    const user = userEvent.setup()
    const registerProof = vi.fn()
    const closeReview = vi.fn()
    const digest = 'f'.repeat(64)

    renderStudio(
      makeEvidence({
        stage: 'ready',
        proof,
        registerProof,
        closeReview,
        review: {
          tier: 'silent',
          tierTitle: 'Silent Witness',
          tierLabel: 'Anonymous Credential',
          statementDigest: digest,
          networkName: 'Testnet',
          networkPassphrase: 'Test SDF Network ; September 2015',
          proofId: proof.proofId,
          videoHash: proof.videoHash,
          metadataHash: proof.metadataHash,
          sourceHash: proof.sourceHash,
        },
      }),
    )

    const region = screen.getByRole('region', { name: 'Evidence processing review' })
    expect(region).toBeInTheDocument()
    expect(region).toHaveTextContent('Silent Witness (Anonymous Credential)')
    expect(screen.getByTestId('review-statement-digest')).toHaveTextContent(digest)
    expect(region).toHaveTextContent('Testnet')
    expect(region).toHaveTextContent('Test SDF Network ; September 2015')

    await user.click(screen.getByRole('button', { name: /confirm & register proof/i }))
    expect(registerProof).toHaveBeenCalledWith('GSOURCEGAUTH')

    await user.click(screen.getByRole('button', { name: 'Back' }))
    expect(closeReview).toHaveBeenCalledTimes(1)
  })

  it('displays an invalidation alert when reviewInvalidatedReason is set', () => {
    renderStudio(
      makeEvidence({
        stage: 'ready',
        proof,
        review: null,
        reviewInvalidatedReason:
          'Review invalidated because the identity tier changed. Review again before registering.',
      }),
    )

    expect(screen.getByRole('alert')).toHaveTextContent(/identity tier changed/i)
    expect(screen.queryByRole('region', { name: 'Evidence processing review' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /review before registering/i })).toBeInTheDocument()
  })
})