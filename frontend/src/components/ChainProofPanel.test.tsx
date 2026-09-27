import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { useIssuerTrust } from '../hooks/useIssuerTrust'
import type { ChainProofRecord } from '../stellarTypes'
import { STELLAR_STRKEY_LENGTH, type IssuerTrust } from '../provenance/issuerTrust'
import { ChainProofPanel } from './ChainProofPanel'

// The registry read lives in the hook and is covered by useIssuerTrust.test.ts.
// This suite pins the panel's wiring: which inputs reach the hook, and how the
// resolved trust is laid out next to the existing registry fields.
vi.mock('../hooks/useIssuerTrust', () => ({
  useIssuerTrust: vi.fn(),
}))

const mockedUseIssuerTrust = vi.mocked(useIssuerTrust)

const ISSUER = `G${'B'.repeat(STELLAR_STRKEY_LENGTH - 1)}`

const CHAIN_PROOF: ChainProofRecord = {
  videoHash: 'a'.repeat(64),
  metadataHash: 'b'.repeat(64),
  tier: 1,
  status: 1,
  createdAt: '123',
  expiresAt: 0,
  source: 'c'.repeat(64),
  issuer: ISSUER,
}

function trustStub(overrides: Partial<IssuerTrust> = {}): IssuerTrust {
  return {
    state: 'trusted',
    label: 'Issuer trusted',
    description: 'The registry lists this issuer as active.',
    severity: 'positive',
    issuer: ISSUER,
    ...overrides,
  }
}

beforeEach(() => {
  mockedUseIssuerTrust.mockReset()
  mockedUseIssuerTrust.mockReturnValue(trustStub())
})

describe('ChainProofPanel', () => {
  it('keeps the empty state and holds the lookup while no record is loaded', () => {
    render(<ChainProofPanel chainProof={null} />)

    expect(screen.getByText('No on-chain match loaded.')).toBeInTheDocument()
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(mockedUseIssuerTrust).toHaveBeenCalledWith({
      issuer: null,
      expiresAt: null,
      enabled: false,
    })
  })

  it('passes the record issuer and expiry to the lookup', () => {
    render(<ChainProofPanel chainProof={{ ...CHAIN_PROOF, expiresAt: 1_900_000_000 }} />)

    expect(mockedUseIssuerTrust).toHaveBeenCalledWith({
      issuer: ISSUER,
      expiresAt: 1_900_000_000,
      enabled: true,
    })
  })

  it('renders the badge on an issuer row beside the existing fields', () => {
    render(<ChainProofPanel chainProof={CHAIN_PROOF} />)

    expect(screen.getByText('Issuer')).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveAttribute('data-state', 'trusted')
    expect(screen.getByText('Issuer trusted')).toBeInTheDocument()
    expect(screen.getByText('Metadata')).toBeInTheDocument()
    expect(screen.getByText('Tier')).toBeInTheDocument()
  })

  it('renders a revoked badge even though the record itself is still registered', () => {
    mockedUseIssuerTrust.mockReturnValue(
      trustStub({
        state: 'revoked',
        label: 'Issuer revoked',
        severity: 'critical',
      }),
    )

    render(<ChainProofPanel chainProof={CHAIN_PROOF} />)

    const badge = screen.getByRole('status')
    expect(badge).toHaveAttribute('data-state', 'revoked')
    expect(badge).toHaveAttribute('data-severity', 'critical')
  })

  it('renders an unavailable badge without exposing the failure detail', () => {
    mockedUseIssuerTrust.mockReturnValue(
      trustStub({
        state: 'unavailable',
        label: 'Issuer lookup unavailable',
        description: 'The registry could not be read, so no trust decision was made.',
        severity: 'caution',
        issuer: ISSUER,
      }),
    )

    render(<ChainProofPanel chainProof={CHAIN_PROOF} />)

    expect(screen.getByRole('status')).toHaveAttribute('data-state', 'unavailable')
    expect(screen.getByText('Issuer lookup unavailable')).toBeInTheDocument()
  })

  it('renders no-issuer for a tier without an issuer address', () => {
    mockedUseIssuerTrust.mockReturnValue(
      trustStub({
        state: 'unsupported',
        label: 'No issuer',
        severity: 'neutral',
        issuer: null,
      }),
    )

    render(<ChainProofPanel chainProof={{ ...CHAIN_PROOF, issuer: null }} />)

    const badge = screen.getByRole('status')
    expect(badge).toHaveAttribute('data-state', 'unsupported')
    expect(badge.querySelector('code')).toBeNull()
  })
})
