/**
 * StudioView – RecoveryBanner tests.
 *
 * Verifies that interrupted-upload recovery choices remain visible after
 * navigation and that the correct buttons are rendered per category.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StudioView } from './StudioView'
import { buildProofPreparationPreview } from '../proofPreparationPreview'
import type { UseEvidenceReturn } from '../hooks/useEvidence'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { InterruptedUploadSession } from '../interruptedUpload'

// ---------------------------------------------------------------------------
// Module mocks — block the full import chain that leads to the pre-existing
// duplicate-function parse error in harpocratesRegistry.ts.  Every test file
// that directly renders StudioView needs these same mocks.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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

function noSession(): InterruptedUploadSession {
  return { category: 'none', fileName: null, interruptedAt: null }
}

function makeEvidence(overrides: Partial<UseEvidenceReturn> = {}): UseEvidenceReturn {
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
    message: 'Upload evidence to begin.',
    proofPreparation: buildProofPreparationPreview({ proof: null, tier: 'silent' }),
    registration: null,
    networkMismatch: null,
    isCancellable: false,
    handleEvidence: vi.fn(),
    registerProof: vi.fn(),
    cancelEvidence: vi.fn(),
    cancelProving: vi.fn(),
    interruptedSession: noSession(),
    resumeEvidence: vi.fn(),
    discardEvidence: vi.fn(),
    ...overrides,
  }
}

function renderStudio(evidence: UseEvidenceReturn = makeEvidence()) {
  return render(
    <StudioView
      wallet="GSOURCEGAUTH"
      evidence={evidence}
      verification={makeVerification()}
      provenanceRecord={null}
    />,
  )
}

// ---------------------------------------------------------------------------
// RecoveryBanner visibility
// ---------------------------------------------------------------------------

describe('StudioView – RecoveryBanner not shown when no interrupted session', () => {
  it('does not render the recovery region in idle state', () => {
    renderStudio(makeEvidence({ stage: 'idle', interruptedSession: noSession() }))
    expect(
      screen.queryByRole('region', { name: 'Interrupted upload recovery' }),
    ).not.toBeInTheDocument()
  })

  it('does not render the recovery region in ready state', () => {
    renderStudio(makeEvidence({ stage: 'ready', interruptedSession: noSession() }))
    expect(
      screen.queryByRole('region', { name: 'Interrupted upload recovery' }),
    ).not.toBeInTheDocument()
  })

  it('does not render the recovery region while hashing is in flight', () => {
    renderStudio(
      makeEvidence({
        stage: 'hashing',
        isCancellable: true,
        interruptedSession: noSession(),
      }),
    )
    expect(
      screen.queryByRole('region', { name: 'Interrupted upload recovery' }),
    ).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// RecoveryBanner – resumable
// ---------------------------------------------------------------------------

describe('StudioView – RecoveryBanner resumable', () => {
  let resumeEvidence: ReturnType<typeof vi.fn>
  let discardEvidence: ReturnType<typeof vi.fn>

  beforeEach(() => {
    resumeEvidence = vi.fn()
    discardEvidence = vi.fn()
  })

  function renderResumable(fileName = 'clip.mp4') {
    return renderStudio(
      makeEvidence({
        stage: 'cancelled',
        interruptedSession: {
          category: 'resumable',
          fileName,
          interruptedAt: Date.now() - 60_000,
        },
        resumeEvidence,
        discardEvidence,
      }),
    )
  }

  it('renders the recovery region with the resumable heading', () => {
    renderResumable()
    expect(
      screen.getByRole('region', { name: 'Interrupted upload recovery' }),
    ).toBeInTheDocument()
    expect(screen.getByText('Upload interrupted — resume?')).toBeInTheDocument()
  })

  it('shows the interrupted file name', () => {
    renderResumable('evidence-2026.mp4')
    expect(screen.getByText('evidence-2026.mp4')).toBeInTheDocument()
  })

  it('renders both Resume and Discard buttons', () => {
    renderResumable()
    expect(screen.getByRole('button', { name: /resume upload/i })).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /discard interrupted session/i }),
    ).toBeInTheDocument()
  })

  it('calls resumeEvidence when Resume is clicked', async () => {
    const user = userEvent.setup()
    renderResumable()
    await user.click(screen.getByRole('button', { name: /resume upload/i }))
    expect(resumeEvidence).toHaveBeenCalledTimes(1)
    expect(discardEvidence).not.toHaveBeenCalled()
  })

  it('calls discardEvidence when Discard is clicked', async () => {
    const user = userEvent.setup()
    renderResumable()
    await user.click(
      screen.getByRole('button', { name: /discard interrupted session/i }),
    )
    expect(discardEvidence).toHaveBeenCalledTimes(1)
    expect(resumeEvidence).not.toHaveBeenCalled()
  })

  it('Resume button is keyboard-activatable', async () => {
    const user = userEvent.setup()
    renderResumable()
    const btn = screen.getByRole('button', { name: /resume upload/i })
    btn.focus()
    await user.keyboard('{Enter}')
    expect(resumeEvidence).toHaveBeenCalledTimes(1)
  })

  it('Discard button is keyboard-activatable', async () => {
    const user = userEvent.setup()
    renderResumable()
    const btn = screen.getByRole('button', { name: /discard interrupted session/i })
    btn.focus()
    await user.keyboard('{Enter}')
    expect(discardEvidence).toHaveBeenCalledTimes(1)
  })

  it('survives a simulated navigation away and back (category stays visible)', () => {
    // useEvidence lives in App, not in StudioView, so unmounting/remounting
    // StudioView with the same evidence prop correctly re-renders the banner.
    const { unmount } = renderResumable('navigate-test.mp4')
    unmount()

    // Re-render with the same session (simulating user navigating back)
    renderResumable('navigate-test.mp4')
    expect(screen.getByText('navigate-test.mp4')).toBeInTheDocument()
    expect(screen.getByText('Upload interrupted — resume?')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// RecoveryBanner – source-changed
// ---------------------------------------------------------------------------

describe('StudioView – RecoveryBanner source-changed', () => {
  it('renders the source-changed heading with no Resume button', () => {
    const discardEvidence = vi.fn()
    renderStudio(
      makeEvidence({
        stage: 'cancelled',
        interruptedSession: {
          category: 'source-changed',
          fileName: 'old.mp4',
          interruptedAt: Date.now() - 10_000,
        },
        discardEvidence,
      }),
    )

    expect(
      screen.getByRole('region', { name: 'Interrupted upload recovery' }),
    ).toBeInTheDocument()
    expect(
      screen.getByText('Source file changed — previous session discarded'),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /resume/i })).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /discard interrupted session/i }),
    ).toBeInTheDocument()
  })

  it('calls discardEvidence when Start over is clicked for source-changed', async () => {
    const user = userEvent.setup()
    const discardEvidence = vi.fn()
    renderStudio(
      makeEvidence({
        stage: 'cancelled',
        interruptedSession: {
          category: 'source-changed',
          fileName: 'old.mp4',
          interruptedAt: Date.now() - 10_000,
        },
        discardEvidence,
      }),
    )

    await user.click(
      screen.getByRole('button', { name: /discard interrupted session/i }),
    )
    expect(discardEvidence).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// RecoveryBanner – expired
// ---------------------------------------------------------------------------

describe('StudioView – RecoveryBanner expired', () => {
  it('renders the expired heading with no Resume button', () => {
    renderStudio(
      makeEvidence({
        stage: 'cancelled',
        interruptedSession: {
          category: 'expired',
          fileName: 'old-clip.mp4',
          interruptedAt: Date.now() - 5 * 60 * 60 * 1000,
        },
        discardEvidence: vi.fn(),
      }),
    )

    expect(screen.getByText('Previous session expired')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /resume/i })).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /discard interrupted session/i }),
    ).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// RecoveryBanner – unrecoverable
// ---------------------------------------------------------------------------

describe('StudioView – RecoveryBanner unrecoverable', () => {
  it('renders the unrecoverable heading with no Resume button', () => {
    renderStudio(
      makeEvidence({
        stage: 'error',
        message: 'video payload exceeds size limit',
        interruptedSession: {
          category: 'unrecoverable',
          fileName: 'huge.mp4',
          interruptedAt: Date.now() - 5_000,
        },
        discardEvidence: vi.fn(),
      }),
    )

    expect(screen.getByText('Upload failed')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /resume/i })).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /discard interrupted session/i }),
    ).toBeInTheDocument()
  })
})
