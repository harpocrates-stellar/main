/**
 * StudioView cancel-button tests.
 * Renders the Evidence Studio with fixture hook returns so the Cancel button
 * visibility, label, click, and keyboard activation are deterministic.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StudioView } from './StudioView'
import { buildProofPreparationPreview } from '../proofPreparationPreview'
import type { UseEvidenceReturn } from '../hooks/useEvidence'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { ProofPackage } from '../types'

vi.mock('../harpocratesRegistry', () => ({}))
vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Future Network ; October 2022',
  getVerifierState: vi.fn().mockResolvedValue({ currentSetHash: 'a'.repeat(64), count: 1, verifiers: [] }),
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
    admissionState: null,
    uploadErrorKind: 'none',
    isRejectedUpload: false,
    isInvalidEvidence: false,
    handleEvidence: vi.fn(),
    retryEvidence: vi.fn(),
    registerProof: vi.fn(),
    revalidateNetworkMismatch: vi.fn(),
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

describe('StudioView – upload admission and queue state', () => {
  it('renders admission queue banner when upload is rejected by queue limits', () => {
    renderStudio(
      makeEvidence({
        stage: 'error',
        isRejectedUpload: true,
        admissionState: {
          status: 'rejected',
          reason: 'queue_full',
          message: 'Upload queue is full. Try again in 5s.',
          retryAfter: 5,
          retryable: true,
          actionHint: 'retry',
        },
      }),
    )

    expect(screen.getByTestId('admission-queue-banner')).toBeInTheDocument()
    expect(screen.getByTestId('admission-queue-title')).toHaveTextContent(/Rejected \(queue full\)/i)
    expect(screen.getByTestId('admission-queue-message')).toHaveTextContent('Upload queue is full. Try again in 5s.')
    expect(screen.getByTestId('admission-queue-retry-hint')).toHaveTextContent('5s')
    expect(screen.getByRole('button', { name: 'Retry upload' })).toBeInTheDocument()
    expect(screen.getByTestId('admission-state-value')).toHaveTextContent('REJECTED (queue_full)')
  })

  it('triggers retryUpload when Retry Upload button is clicked', async () => {
    const user = userEvent.setup()
    const retryUpload = vi.fn()
    renderStudio(
      makeEvidence({
        stage: 'error',
        isRejectedUpload: true,
        retryUpload,
        admissionState: {
          status: 'rejected',
          reason: 'identity_limit',
          message: 'Concurrent upload limit reached for tier.',
          retryAfter: 10,
          retryable: true,
          actionHint: 'retry',
        },
      }),
    )

    await user.click(screen.getByRole('button', { name: 'Retry upload' }))
    expect(retryUpload).toHaveBeenCalledTimes(1)
  })

  it('renders invalid evidence banner distinct from admission rejection', () => {
    renderStudio(
      makeEvidence({
        stage: 'error',
        isInvalidEvidence: true,
        isRejectedUpload: false,
        admissionState: null,
        message: 'Unsupported video container format.',
      }),
    )

    expect(screen.getByTestId('invalid-evidence-banner')).toBeInTheDocument()
    expect(screen.getByTestId('invalid-evidence-message')).toHaveTextContent('Unsupported video container format.')
    expect(screen.queryByTestId('admission-queue-banner')).not.toBeInTheDocument()
    expect(screen.getByTestId('admission-state-value')).toHaveTextContent('IDLE')
  })

  it('renders ADMITTED in data list when evidence proof is ready', () => {
    renderStudio(
      makeEvidence({
        stage: 'ready',
        proof,
        admissionState: {
          status: 'admitted',
          reason: null,
          message: 'Upload admitted and processed successfully.',
          retryAfter: null,
          retryable: false,
          actionHint: 'none',
        },
      }),
    )

    expect(screen.getByTestId('admission-state-value')).toHaveTextContent('ADMITTED')
  })
})
