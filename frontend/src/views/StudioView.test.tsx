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
    networkRecovery: null,
    isCancellable: false,
    handleEvidence: vi.fn(),
    registerProof: vi.fn(),
    revalidateNetworkRecovery: vi.fn(),
    resumeAfterNetworkRecovery: vi.fn(),
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

  it('renders guided network mismatch recovery showing required vs wallet network and gates resume on fresh validation', async () => {
    const user = userEvent.setup()
    const revalidateNetworkRecovery = vi.fn().mockResolvedValue(true)
    const resumeAfterNetworkRecovery = vi.fn().mockResolvedValue(undefined)

    const { container, rerender } = renderStudio(
      makeEvidence({
        stage: 'ready',
        proof,
        networkMismatch: 'Wallet is on Mainnet but the contract is deployed on Testnet.',
        networkRecovery: {
          requiredNetwork: 'Testnet',
          requiredPassphrase: 'Test SDF Network ; September 2015',
          walletNetwork: 'Mainnet',
          walletPassphrase: 'Public Global Stellar Network ; September 2015',
          reason: 'Wallet is on Mainnet but the contract is deployed on Testnet.',
          remediation: 'Open Freighter, switch to Testnet, then reconnect your wallet.',
          blockedIntent: {
            proofId: proof.proofId,
            sourceHash: proof.sourceHash,
            videoHash: proof.videoHash,
            metadataHash: proof.metadataHash,
            tier: 'silent',
            wallet: 'GSOURCEGAUTH',
          },
          canResume: false,
          validationError: null,
          isRevalidating: false,
        },
        revalidateNetworkRecovery,
        resumeAfterNetworkRecovery,
      }),
    )

    expect(screen.getByTestId('required-network-label')).toHaveTextContent('Testnet')
    expect(screen.getByTestId('wallet-network-label')).toHaveTextContent('Mainnet')
    expect(screen.getByRole('button', { name: /resume registration/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /register proof/i })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: /verify network & intent/i }))
    expect(revalidateNetworkRecovery).toHaveBeenCalledWith('GSOURCEGAUTH')

    rerender(
      <StudioView
        wallet="GSOURCEGAUTH"
        evidence={makeEvidence({
          stage: 'ready',
          proof,
          networkMismatch: null,
          networkRecovery: {
            requiredNetwork: 'Testnet',
            requiredPassphrase: 'Test SDF Network ; September 2015',
            walletNetwork: 'Testnet',
            walletPassphrase: 'Test SDF Network ; September 2015',
            reason: 'Wallet connected to Testnet.',
            remediation: 'Evidence intent validated. You may now resume registration.',
            blockedIntent: {
              proofId: proof.proofId,
              sourceHash: proof.sourceHash,
              videoHash: proof.videoHash,
              metadataHash: proof.metadataHash,
              tier: 'silent',
              wallet: 'GSOURCEGAUTH',
            },
            canResume: true,
            validationError: null,
            isRevalidating: false,
          },
          revalidateNetworkRecovery,
          resumeAfterNetworkRecovery,
        })}
        verification={makeVerification()}
        provenanceRecord={null}
      />,
    )

    const resumeBtn = screen.getByRole('button', { name: /resume registration/i })
    expect(resumeBtn).toBeEnabled()
    await user.click(resumeBtn)
    expect(resumeAfterNetworkRecovery).toHaveBeenCalledWith('GSOURCEGAUTH')
    expectNoA11yViolations(await runAxe(container), 'studio guided network mismatch recovery')
  })
})