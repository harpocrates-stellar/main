import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../App.css'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { ChainProofRecord, Hex32 } from '../stellarTypes'
import { resolveIssuerTrust } from '../provenance/issuerTrust'
import { expectNoA11yViolations, runAxe } from '../test/axeA11y'

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Future Network ; October 2022',
  getProofByVideoHash: vi.fn(),
  WatchWalletChanges: vi.fn(),
  connectFreighter: vi.fn(),
  getWalletNetwork: vi.fn(),
}))

vi.mock('../components/ChainProofPanel', () => ({
  ChainProofPanel: () => <div data-testid="chain-proof-panel" />,
  formatProofExpiry: () => 'Never',
}))

vi.mock('../components/VerifierSetStatusPanel', () => ({
  VerifierSetStatusPanel: () => <div data-testid="verifier-set-status-panel" />,
}))

vi.mock('../provenance/ProvenanceCard', () => ({
  default: () => <div data-testid="provenance-card" />,
}))

const HASH_ONE = '1'.repeat(64) as Hex32
const META_ONE = 'a'.repeat(64) as Hex32
const VALID_ISSUER = 'GABCDEFGHIJKLMNOPQRSTUVWXYZ23456723456723456723456723456'

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: HASH_ONE,
    metadataHash: META_ONE,
    tier: 2,
    source: null,
    issuer: VALID_ISSUER,
    createdAt: '1750000000',
    expiresAt: 0,
    status: 1,
    ...overrides,
  }
}

function makeHook(overrides: Partial<UseVerificationReturn> = {}): UseVerificationReturn {
  return {
    verifyHash: HASH_ONE,
    verifyResult: 'Cryptographic proof verified against on-chain commitment.',
    events: [],
    chainProof: makeChainProof(),
    status: 'success',
    errorCode: null,
    isVerifying: false,
    offline: false,
    setOffline: vi.fn(),
    verifyEvidence: vi.fn(),
    loadEvents: vi.fn(),
    loadSharedVerification: vi.fn(),
    cancel: vi.fn(),
    retry: vi.fn(),
    clear: vi.fn(),
    ...overrides,
  }
}

describe('VerifyView unknown issuer trust vs invalid signature standing (#1138)', () => {
  it('explains unknown issuer trust separately from an invalid signature while keeping the underlying proof result visible', async () => {
    const unknownTrust = resolveIssuerTrust({
      issuer: VALID_ISSUER,
      lookup: { kind: 'missing' },
      expiresAt: 0,
    })

    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={null}
        issuerTrust={unknownTrust}
      />,
    )

    // Underlying proof result remains visible
    expect(
      screen.getByText(/cryptographic proof verified against on-chain commitment/i),
    ).toBeInTheDocument()
    expect(screen.getByTestId('standing-underlying-proof')).toHaveTextContent(
      /underlying cryptographic proof verified/i,
    )
    expect(screen.getByTestId('standing-reason-code')).toHaveTextContent(
      'ISSUER_UNKNOWN_UNREGISTERED',
    )
    expect(
      screen.getByText(/unknown issuer trust \(cryptographic signature is valid\)/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/not registered in the trusted issuer directory/i),
    ).toBeInTheDocument()

    expectNoA11yViolations(await runAxe(container), 'VerifyView unknown issuer standing')
  })

  it('maps invalid cryptographic signature or proof errors to SIGNATURE_OR_PROOF_INVALID and warns against authentication', async () => {
    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({
          status: 'error',
          verifyResult: 'Artifact verification failed: signature mismatch.',
          errorCode: 'INVALID_SIGNATURE',
          chainProof: makeChainProof(),
        })}
        provenanceRecord={null}
      />,
    )

    // Underlying error banner remains visible alongside signature standing copy
    expect(
      screen.getByText(/artifact verification failed: signature mismatch/i),
    ).toBeInTheDocument()
    expect(screen.getByTestId('standing-reason-code')).toHaveTextContent(
      'SIGNATURE_OR_PROOF_INVALID',
    )
    expect(screen.getByTestId('standing-underlying-proof')).toHaveTextContent(
      /cryptographic signature or proof failed verification/i,
    )
    expect(
      screen.getByText(/regardless of any claimed issuer address, the artifact cannot be authenticated/i),
    ).toBeInTheDocument()

    expectNoA11yViolations(await runAxe(container), 'VerifyView invalid signature standing')
  })

  it('maps revoked issuer and anonymous Silent Witness tiers to distinct stable reason codes', () => {
    const revokedTrust = resolveIssuerTrust({
      issuer: VALID_ISSUER,
      lookup: { kind: 'inactive' },
      expiresAt: 0,
    })

    const { rerender } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={null}
        issuerTrust={revokedTrust}
      />,
    )

    expect(screen.getByTestId('standing-reason-code')).toHaveTextContent(
      'ISSUER_REVOKED_AFTER_ISSUANCE',
    )
    expect(screen.getByTestId('standing-underlying-proof')).toHaveTextContent(
      /underlying cryptographic proof verified/i,
    )

    rerender(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({
          chainProof: makeChainProof({ tier: 0, issuer: null }),
        })}
        provenanceRecord={null}
      />,
    )

    expect(screen.getByTestId('standing-reason-code')).toHaveTextContent(
      'ANONYMOUS_TIER_NO_ISSUER',
    )
  })
})
