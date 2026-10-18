import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { VerifierSetStatusPanel } from './VerifierSetStatusPanel'
import * as useVerifierStateModule from '../hooks/useVerifierState'

vi.mock('../hooks/useVerifierState')

describe('VerifierSetStatusPanel', () => {
  it('renders loading state', () => {
    vi.mocked(useVerifierStateModule.useVerifierState).mockReturnValue({
      loading: true,
      error: null,
      verifierState: null,
    })

    render(<VerifierSetStatusPanel />)
    expect(screen.getByText('Loading verifier status...')).toBeInTheDocument()
  })

  it('renders error state', () => {
    vi.mocked(useVerifierStateModule.useVerifierState).mockReturnValue({
      loading: false,
      error: new Error('Network error'),
      verifierState: null,
    })

    render(<VerifierSetStatusPanel />)
    expect(screen.getByText('Failed to load verifier state')).toBeInTheDocument()
  })

  it('renders not found state when state is null', () => {
    vi.mocked(useVerifierStateModule.useVerifierState).mockReturnValue({
      loading: false,
      error: null,
      verifierState: null,
    })

    render(<VerifierSetStatusPanel />)
    expect(screen.getByText('Verifier state not found on-chain.')).toBeInTheDocument()
  })

  it('renders verifier state with all fields', () => {
    vi.mocked(useVerifierStateModule.useVerifierState).mockReturnValue({
      loading: false,
      error: null,
      verifierState: {
        activeVerifier: 'CDX1234567890123456789012345678901234567890123456789ABCD',
        pendingVerifier: 'CBX1234567890123456789012345678901234567890123456789ABCD',
        previousVerifier: 'CAX1234567890123456789012345678901234567890123456789ABCD',
        activationLedger: '1000',
        overlapWindow: '100',
        rollbackWindow: '50',
        rollbackWindowEnd: '1050',
      },
    })

    render(<VerifierSetStatusPanel />)
    expect(screen.getByText('Active Verifier')).toBeInTheDocument()
    expect(screen.getByText('CDX12345...ABCD')).toBeInTheDocument()
    
    expect(screen.getByText('Pending Verifier')).toBeInTheDocument()
    expect(screen.getByText('CBX12345...ABCD')).toBeInTheDocument()
    
    expect(screen.getByText('Previous Verifier')).toBeInTheDocument()
    expect(screen.getByText('CAX12345...ABCD')).toBeInTheDocument()

    expect(screen.getByText('1000')).toBeInTheDocument() // activation ledger
    expect(screen.getByText('100 ledgers')).toBeInTheDocument() // overlap window
    expect(screen.getByText('Ledger 1050')).toBeInTheDocument() // rollback window end
  })

  it('renders missing optional fields gracefully', () => {
    vi.mocked(useVerifierStateModule.useVerifierState).mockReturnValue({
      loading: false,
      error: null,
      verifierState: {
        activeVerifier: null,
        pendingVerifier: null,
        previousVerifier: null,
        activationLedger: '0',
        overlapWindow: '0',
        rollbackWindow: '0',
        rollbackWindowEnd: '0',
      },
    })

    render(<VerifierSetStatusPanel />)
    expect(screen.getByText('Active Verifier')).toBeInTheDocument()
    expect(screen.getByText('None')).toBeInTheDocument()
    expect(screen.queryByText('Pending Verifier')).not.toBeInTheDocument()
    expect(screen.queryByText('Previous Verifier')).not.toBeInTheDocument()
    expect(screen.queryByText('Overlap Window')).not.toBeInTheDocument()
    expect(screen.queryByText('Rollback End')).not.toBeInTheDocument()
  })
})
