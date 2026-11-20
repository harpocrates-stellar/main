/**
 * StudioView cancel-button tests.
 * Renders the Evidence Studio with fixture hook returns so the Cancel button
 * visibility, label, click, and keyboard activation are deterministic.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../workers/proofWorkerClient', () => ({
  ProofWorkerClient: class {},
  ProofWorkerError: class extends Error {},
}))

vi.mock('../hooks/useWallet', () => ({
  useWallet: () => ({ wallet: null, networkMismatch: null, connectWallet: vi.fn(), disconnectWallet: vi.fn() }),
}))

vi.mock('../stellar', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../stellar')>()
  return {
    ...actual,
    isDelegationActive: vi.fn(),
    getDelegation: vi.fn(),
  }
})

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StudioView } from './StudioView'
import {
  DELEGATION_SCOPE_REGISTER_SOURCE,
  DELEGATION_SCOPE_REGISTER_SEAL,
  isDelegationActive,
  getDelegation,
} from '../stellar'
import {
  methodForTier,
  argsForTier,
  normalizeRegisterProofInput,
  buildRegisterProofOperation,
} from '../harpocratesRegistry'
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
    message: 'Upload evidence to begin.',
    registration: null,
    networkMismatch: null,
    isCancellable: false,
    handleEvidence: vi.fn(),
    registerProof: vi.fn(),
    cancelEvidence: vi.fn(),
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
    const cancel = screen.getAllByRole('button', { name: 'Cancel proof generation' })[0]
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

    const cancel = screen.getAllByRole('button', { name: 'Cancel proof generation' })[0]
    cancel.focus()
    await user.keyboard('{Enter}')
    expect(cancelEvidence).toHaveBeenCalledTimes(1)
  })
})

import { StrKey } from '@stellar/stellar-sdk'

const TEST_WALLET = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1))
const GRANTOR_ADDRESS = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 2))
const TEST_CONTRACT = StrKey.encodeContract(Buffer.alloc(32, 3))

function makeSourceEvidence(overrides: Partial<UseEvidenceReturn> = {}): UseEvidenceReturn {
  return makeEvidence({
    selectedTier: 'source',
    selectedTierMeta: {
      id: 'source',
      title: 'Consistent Source',
      label: 'Persistent Identity',
      icon: vi.fn(),
      description: 'Public identity proof.',
    },
    stage: 'ready',
    proof: {
      fileName: 'clip.mp4',
      sourceHash: '1'.repeat(64),
      videoHash: '2'.repeat(64),
      metadataHash: '3'.repeat(64),
      proofId: '4'.repeat(64),
      timestamp: '2026-01-01T00:00:00.000Z',
      tier: 'source',
    },
    ...overrides,
  })
}

function makeSealEvidence(overrides: Partial<UseEvidenceReturn> = {}): UseEvidenceReturn {
  return makeEvidence({
    selectedTier: 'seal',
    selectedTierMeta: {
      id: 'seal',
      title: 'Public Seal',
      label: 'Public Seal',
      icon: vi.fn(),
      description: 'Official organization seal.',
    },
    stage: 'ready',
    proof: {
      fileName: 'clip.mp4',
      sourceHash: '1'.repeat(64),
      videoHash: '2'.repeat(64),
      metadataHash: '3'.repeat(64),
      proofId: '4'.repeat(64),
      timestamp: '2026-01-01T00:00:00.000Z',
      tier: 'seal',
    },
    ...overrides,
  })
}

describe('StudioView – delegated registration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('leaves direct registration unchanged when no grantor address is entered', async () => {
    const user = userEvent.setup()
    const registerProof = vi.fn()
    render(
      <StudioView
        wallet={TEST_WALLET}
        evidence={makeSourceEvidence({ registerProof })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const registerBtn = screen.getByRole('button', { name: 'Register proof' })
    expect(registerBtn).not.toBeDisabled()

    await user.click(registerBtn)
    expect(registerProof).toHaveBeenCalledTimes(1)
    expect(registerProof).toHaveBeenCalledWith(TEST_WALLET, undefined)
  })

  it('enables delegated registration and displays attribution & expiry when active grant exists for Tier 2', async () => {
    const user = userEvent.setup()
    const registerProof = vi.fn()
    vi.mocked(isDelegationActive).mockResolvedValue(true)
    vi.mocked(getDelegation).mockResolvedValue({
      grantor: GRANTOR_ADDRESS,
      delegate: TEST_WALLET,
      scope: DELEGATION_SCOPE_REGISTER_SOURCE,
      expiresAt: 2000000000,
    })

    render(
      <StudioView
        wallet={TEST_WALLET}
        evidence={makeSourceEvidence({ registerProof })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const grantorInput = screen.getByPlaceholderText(/leave empty for direct registration/i)
    await user.type(grantorInput, GRANTOR_ADDRESS)

    await waitFor(() => {
      expect(isDelegationActive).toHaveBeenCalledWith(
        expect.any(String),
        GRANTOR_ADDRESS,
        TEST_WALLET,
        DELEGATION_SCOPE_REGISTER_SOURCE,
      )
    })

    expect(
      screen.getByText(/Attribution: The registered proof will be attributed to grantor/i),
    ).toBeInTheDocument()
    expect(screen.getByText(GRANTOR_ADDRESS)).toBeInTheDocument()
    expect(screen.getByText(/Active delegation verified/i)).toBeInTheDocument()
    expect(screen.getByText(new RegExp(new Date(2000000000 * 1000).toISOString()))).toBeInTheDocument()

    const submitBtn = screen.getByRole('button', { name: 'Register proof (delegated)' })
    expect(submitBtn).not.toBeDisabled()

    await user.click(submitBtn)
    expect(registerProof).toHaveBeenCalledTimes(1)
    expect(registerProof).toHaveBeenCalledWith(TEST_WALLET, GRANTOR_ADDRESS)
  })

  it('enables delegated registration when active grant exists for Tier 3 Public Seal', async () => {
    const user = userEvent.setup()
    const registerProof = vi.fn()
    vi.mocked(isDelegationActive).mockResolvedValue(true)
    vi.mocked(getDelegation).mockResolvedValue({
      grantor: GRANTOR_ADDRESS,
      delegate: TEST_WALLET,
      scope: DELEGATION_SCOPE_REGISTER_SEAL,
      expiresAt: 2000000000,
    })

    render(
      <StudioView
        wallet={TEST_WALLET}
        evidence={makeSealEvidence({ registerProof })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const grantorInput = screen.getByPlaceholderText(/leave empty for direct registration/i)
    await user.type(grantorInput, GRANTOR_ADDRESS)

    await waitFor(() => {
      expect(isDelegationActive).toHaveBeenCalledWith(
        expect.any(String),
        GRANTOR_ADDRESS,
        TEST_WALLET,
        DELEGATION_SCOPE_REGISTER_SEAL,
      )
    })

    const submitBtn = screen.getByRole('button', { name: 'Register proof (delegated)' })
    expect(submitBtn).not.toBeDisabled()

    await user.click(submitBtn)
    expect(registerProof).toHaveBeenCalledWith(TEST_WALLET, GRANTOR_ADDRESS)
  })

  it('blocks submission and displays clear error message when grant is missing', async () => {
    const user = userEvent.setup()
    vi.mocked(isDelegationActive).mockResolvedValue(false)
    vi.mocked(getDelegation).mockResolvedValue(null)

    render(
      <StudioView
        wallet={TEST_WALLET}
        evidence={makeSourceEvidence()}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const grantorInput = screen.getByPlaceholderText(/leave empty for direct registration/i)
    await user.type(grantorInput, GRANTOR_ADDRESS)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(
        'No delegation grant found from this grantor to your wallet.',
      )
    })

    const submitBtn = screen.getByRole('button', { name: 'Register proof (delegated)' })
    expect(submitBtn).toBeDisabled()
  })

  it('blocks submission and displays clear error message when grant is expired', async () => {
    const user = userEvent.setup()
    vi.mocked(isDelegationActive).mockResolvedValue(false)
    vi.mocked(getDelegation).mockResolvedValue({
      grantor: GRANTOR_ADDRESS,
      delegate: TEST_WALLET,
      scope: DELEGATION_SCOPE_REGISTER_SOURCE,
      expiresAt: 1600000000, // Past timestamp
    })

    render(
      <StudioView
        wallet={TEST_WALLET}
        evidence={makeSourceEvidence()}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const grantorInput = screen.getByPlaceholderText(/leave empty for direct registration/i)
    await user.type(grantorInput, GRANTOR_ADDRESS)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/Delegation has expired/i)
    })

    const submitBtn = screen.getByRole('button', { name: 'Register proof (delegated)' })
    expect(submitBtn).toBeDisabled()
  })

  it('blocks submission and displays clear error message when grant has wrong scope', async () => {
    const user = userEvent.setup()
    vi.mocked(isDelegationActive).mockResolvedValue(false)
    vi.mocked(getDelegation).mockResolvedValue({
      grantor: GRANTOR_ADDRESS,
      delegate: TEST_WALLET,
      scope: DELEGATION_SCOPE_REGISTER_SEAL, // Wrong scope for source tier
      expiresAt: 2000000000,
    })

    render(
      <StudioView
        wallet={TEST_WALLET}
        evidence={makeSourceEvidence()}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const grantorInput = screen.getByPlaceholderText(/leave empty for direct registration/i)
    await user.type(grantorInput, GRANTOR_ADDRESS)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(
        'Delegation does not grant permission for Consistent Source registration.',
      )
    })

    const submitBtn = screen.getByRole('button', { name: 'Register proof (delegated)' })
    expect(submitBtn).toBeDisabled()
  })

  it('blocks submission and displays error when grantor address is invalid format', async () => {
    const user = userEvent.setup()

    render(
      <StudioView
        wallet={TEST_WALLET}
        evidence={makeSourceEvidence()}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const grantorInput = screen.getByPlaceholderText(/leave empty for direct registration/i)
    await user.type(grantorInput, 'invalid-stellar-address')

    expect(screen.getByRole('alert')).toHaveTextContent(
      'Grantor address must be a valid 56-character Stellar address',
    )

    const submitBtn = screen.getByRole('button', { name: 'Register proof (delegated)' })
    expect(submitBtn).toBeDisabled()
    expect(isDelegationActive).not.toHaveBeenCalled()
  })

  it('blocks submission and displays error when grantor is the connected wallet itself', async () => {
    const user = userEvent.setup()

    render(
      <StudioView
        wallet={TEST_WALLET}
        evidence={makeSourceEvidence()}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const grantorInput = screen.getByPlaceholderText(/leave empty for direct registration/i)
    await user.type(grantorInput, TEST_WALLET)

    expect(screen.getByRole('alert')).toHaveTextContent(
      'Grantor cannot be your own wallet address. Use direct registration instead.',
    )

    const submitBtn = screen.getByRole('button', { name: 'Register proof (delegated)' })
    expect(submitBtn).toBeDisabled()
    expect(isDelegationActive).not.toHaveBeenCalled()
  })

  it('does not display grantor input when Silent tier is selected', () => {
    render(
      <StudioView
        wallet={TEST_WALLET}
        evidence={makeEvidence({ selectedTier: 'silent' })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    expect(
      screen.queryByPlaceholderText(/leave empty for direct registration/i),
    ).not.toBeInTheDocument()
  })
})

describe('harpocratesRegistry – delegated transaction builders', () => {
  it('selects register_source for direct Tier 2 registration and register_source_delegated for delegated', () => {
    expect(methodForTier('source', false)).toBe('register_source')
    expect(methodForTier('source', true)).toBe('register_source_delegated')
  })

  it('selects register_seal for direct Tier 3 registration and register_seal_delegated for delegated', () => {
    expect(methodForTier('seal', false)).toBe('register_seal')
    expect(methodForTier('seal', true)).toBe('register_seal_delegated')
  })

  it('constructs correct arguments for delegated registration', () => {
    const input = normalizeRegisterProofInput({
      contractId: TEST_CONTRACT,
      publicKey: TEST_WALLET,
      grantor: GRANTOR_ADDRESS,
      videoHash: '1'.repeat(64),
      metadataHash: '2'.repeat(64),
      proofId: '3'.repeat(64),
      tier: 'source',
    })
    const args = argsForTier(input)
    expect(args).toHaveLength(5)
  })

  it('constructs correct arguments for direct registration', () => {
    const input = normalizeRegisterProofInput({
      contractId: TEST_CONTRACT,
      publicKey: TEST_WALLET,
      videoHash: '1'.repeat(64),
      metadataHash: '2'.repeat(64),
      proofId: '3'.repeat(64),
      tier: 'source',
    })
    const args = argsForTier(input)
    expect(args).toHaveLength(4)
  })

  it('builds a valid contract call operation for delegated registration', () => {
    const op = buildRegisterProofOperation(TEST_CONTRACT, {
      contractId: TEST_CONTRACT,
      publicKey: TEST_WALLET,
      grantor: GRANTOR_ADDRESS,
      videoHash: '1'.repeat(64),
      metadataHash: '2'.repeat(64),
      proofId: '3'.repeat(64),
      tier: 'source',
    })
    expect(op).toBeDefined()
  })
})