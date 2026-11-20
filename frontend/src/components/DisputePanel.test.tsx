import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { DisputePanel } from './DisputePanel'
import * as registry from '../harpocratesRegistry'

vi.mock('../harpocratesRegistry', async (importOriginal) => {
  const actual = await importOriginal<typeof registry>()
  return {
    ...actual,
    getOpenDisputeCount: vi.fn(),
    openDispute: vi.fn(),
    respondDispute: vi.fn(),
  }
})

describe('DisputePanel component', () => {
  const mockProofId = '11'.repeat(32)
  const mockWallet = 'GBBD57IFVLACRB4PO24564GTCWJMWVNWFRF27F2WEX6F52GPEAK76GFO'

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    vi.mocked(registry.getOpenDisputeCount).mockResolvedValue(2)
  })

  it('renders open dispute count from RPC', async () => {
    render(
      <DisputePanel
        proofId={mockProofId}
        wallet=""
        contractId="CTEST"
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('open-dispute-count')).toHaveTextContent('2 open')
    })
    expect(registry.getOpenDisputeCount).toHaveBeenCalledWith('CTEST', mockProofId, undefined)
  })

  it('prompts to connect wallet when disconnected', async () => {
    render(
      <DisputePanel
        proofId={mockProofId}
        wallet=""
        contractId="CTEST"
      />,
    )

    expect(screen.getByTestId('dispute-wallet-required')).toHaveTextContent(/connect your wallet/i)
    expect(screen.queryByTestId('open-dispute-form')).not.toBeInTheDocument()
  })

  it('renders form and guards when network mismatch is present', async () => {
    render(
      <DisputePanel
        proofId={mockProofId}
        wallet={mockWallet}
        networkMismatch="Connected to Public Global Stellar Network instead of Testnet."
        contractId="CTEST"
      />,
    )

    expect(screen.getByTestId('dispute-network-mismatch-guard')).toBeInTheDocument()
    const submitBtn = screen.getByRole('button', { name: /open dispute/i })
    expect(submitBtn).toBeDisabled()
  })

  it('enforces client-side validation for evidence hash format', async () => {
    const user = userEvent.setup()
    render(
      <DisputePanel
        proofId={mockProofId}
        wallet={mockWallet}
        contractId="CTEST"
      />,
    )

    const evidenceInput = screen.getByPlaceholderText(/64-character hex hash/i)
    const submitBtn = screen.getByRole('button', { name: /open dispute/i })

    // Input too short
    await user.type(evidenceInput, 'abc123')
    await user.click(submitBtn)

    expect(screen.getByTestId('open-validation-error')).toHaveTextContent(
      /evidence hash must be a 64-character/i,
    )
    expect(registry.openDispute).not.toHaveBeenCalled()
  })

  it('submits open dispute on happy path and shows confirmation', async () => {
    const user = userEvent.setup()
    vi.mocked(registry.openDispute).mockResolvedValue({
      hash: 'aa'.repeat(32),
      status: 'SUCCESS',
      txState: 'confirmed',
    })

    render(
      <DisputePanel
        proofId={mockProofId}
        wallet={mockWallet}
        contractId="CTEST"
      />,
    )

    const evidenceInput = screen.getByPlaceholderText(/64-character hex hash/i)
    await user.type(evidenceInput, 'ee'.repeat(32))

    const submitBtn = screen.getByRole('button', { name: /open dispute/i })
    await user.click(submitBtn)

    await waitFor(() => {
      expect(registry.openDispute).toHaveBeenCalledWith(
        expect.objectContaining({
          contractId: 'CTEST',
          publicKey: mockWallet,
          proofId: mockProofId,
          reason: registry.DisputeReason.ContentError,
          evidenceHash: 'ee'.repeat(32),
        }),
        expect.anything(),
      )
    })

    await waitFor(() => {
      expect(screen.getByTestId('tx-status-confirmed')).toHaveTextContent(/dispute transaction confirmed/i)
    })
  })

  it('surfaces contract cooldown error (#66) as actionable message', async () => {
    const user = userEvent.setup()
    vi.mocked(registry.openDispute).mockRejectedValue(
      new Error('HostError: Error(Contract, #66)'),
    )

    render(
      <DisputePanel
        proofId={mockProofId}
        wallet={mockWallet}
        contractId="CTEST"
      />,
    )

    const evidenceInput = screen.getByPlaceholderText(/64-character hex hash/i)
    await user.type(evidenceInput, 'ee'.repeat(32))

    await user.click(screen.getByRole('button', { name: /open dispute/i }))

    await waitFor(() => {
      const errorEl = screen.getByTestId('dispute-action-error')
      expect(errorEl.textContent?.toLowerCase()).toContain('cooldown')
    })
  })

  it('surfaces contract dispute cap error (#61) as actionable message', async () => {
    const user = userEvent.setup()
    vi.mocked(registry.openDispute).mockRejectedValue(
      new Error('HostError: Error(Contract, #61)'),
    )

    render(
      <DisputePanel
        proofId={mockProofId}
        wallet={mockWallet}
        contractId="CTEST"
      />,
    )

    const evidenceInput = screen.getByPlaceholderText(/64-character hex hash/i)
    await user.type(evidenceInput, 'ee'.repeat(32))

    await user.click(screen.getByRole('button', { name: /open dispute/i }))

    await waitFor(() => {
      const errorEl = screen.getByTestId('dispute-action-error')
      expect(errorEl.textContent?.toLowerCase()).toContain('maximum open disputes')
    })
  })

  it('allows responding to dispute and validates response inputs', async () => {
    const user = userEvent.setup()
    vi.mocked(registry.respondDispute).mockResolvedValue({
      hash: 'bb'.repeat(32),
      status: 'SUCCESS',
      txState: 'confirmed',
    })

    render(
      <DisputePanel
        proofId={mockProofId}
        wallet={mockWallet}
        contractId="CTEST"
      />,
    )

    // Switch to respond tab
    await user.click(screen.getByRole('tab', { name: /respond to dispute/i }))
    expect(screen.getByTestId('respond-dispute-form')).toBeInTheDocument()

    const disputeIdInput = screen.getByPlaceholderText(/64-character hex dispute id/i)
    const commitmentInput = screen.getByPlaceholderText(/64-character hex commitment/i)
    const submitBtn = screen.getByRole('button', { name: /respond to dispute/i })

    // Invalid dispute ID
    await user.type(disputeIdInput, 'short')
    await user.type(commitmentInput, 'dd'.repeat(32))
    await user.click(submitBtn)

    expect(screen.getByTestId('respond-validation-error')).toHaveTextContent(
      /dispute id must be a 64-character/i,
    )

    // Valid dispute ID
    await user.clear(disputeIdInput)
    await user.type(disputeIdInput, 'cc'.repeat(32))
    await user.click(submitBtn)

    await waitFor(() => {
      expect(registry.respondDispute).toHaveBeenCalledWith(
        expect.objectContaining({
          contractId: 'CTEST',
          publicKey: mockWallet,
          disputeId: 'cc'.repeat(32),
          responseCommitment: 'dd'.repeat(32),
        }),
        expect.anything(),
      )
    })
  })
})
