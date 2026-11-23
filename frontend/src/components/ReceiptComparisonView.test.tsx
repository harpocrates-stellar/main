import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { VerificationReceiptPayload } from '../verificationReceipt'
import { ReceiptComparisonView } from './ReceiptComparisonView'

const HEX_A = 'a'.repeat(64)
const HEX_B = 'b'.repeat(64)
const HEX_C = 'c'.repeat(64)
const HEX_D = 'd'.repeat(64)
const HEX_E = 'e'.repeat(64)

function makeReceipt(
  overrides: Partial<VerificationReceiptPayload> = {},
): VerificationReceiptPayload {
  return {
    protocol: 'harpocrates-verification-receipt',
    version: 1,
    result: 'verified',
    verifiedAt: '2026-05-01T10:00:00.000Z',
    proofId: HEX_A,
    videoHash: HEX_B,
    metadataHash: HEX_C,
    tier: 'source',
    networkPassphrase: 'Test SDF Network ; September 2015',
    contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4',
    ledgerSequence: 100500,
    transactionHash: HEX_D,
    circuitVersion: '0.25.0',
    verifierVersion: '1.2.0',
    signer: {
      keyId: 'verifier-key-2026-q1',
      algorithm: 'ECDSA_P256_SHA256',
    },
    ...overrides,
  }
}

describe('ReceiptComparisonView', () => {
  it('highlights changed trust and chain observations with exact UTC timestamps', () => {
    const receiptA = makeReceipt({
      result: 'verified',
      verifiedAt: '2026-05-01T10:00:00.000Z',
      ledgerSequence: 100500,
    })
    const receiptB = makeReceipt({
      result: 'unverified',
      verifiedAt: '2026-05-01T12:15:30.000Z',
      ledgerSequence: 100750,
      transactionHash: HEX_E,
    })

    render(<ReceiptComparisonView baseUrl="https://verify.harpocrates.example" />)

    fireEvent.change(screen.getByLabelText('Receipt A JSON or QR payload'), {
      target: { value: JSON.stringify(receiptA) },
    })
    fireEvent.change(screen.getByLabelText('Receipt B JSON or QR payload'), {
      target: { value: JSON.stringify(receiptB) },
    })

    expect(screen.getByTestId('receipt-a-timestamp')).toHaveTextContent('2026-05-01T10:00:00.000Z')
    expect(screen.getByTestId('receipt-b-timestamp')).toHaveTextContent('2026-05-01T12:15:30.000Z')
    expect(screen.getByTestId('receipt-time-delta')).toHaveTextContent('+2h 15m 30s')

    expect(screen.getByTestId('category-changed-trust')).toHaveTextContent('Changed')
    expect(screen.getByTestId('category-changed-chain')).toHaveTextContent('Changed')
    expect(screen.getByText(/trust changed, chain changed/i)).toBeInTheDocument()
  })

  it('rejects receipts containing private evidence metadata', () => {
    render(<ReceiptComparisonView />)

    fireEvent.change(screen.getByLabelText('Receipt A JSON or QR payload'), {
      target: {
        value: JSON.stringify({
          ...makeReceipt(),
          fileName: 'private-whistleblower-clip.mp4',
        }),
      },
    })

    expect(screen.getByRole('alert')).toHaveTextContent(/private evidence metadata/i)
  })

  it('copies a privacy-safe comparison link with only public fields', async () => {
    const user = userEvent.setup()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })

    const receiptA = makeReceipt()
    const receiptB = makeReceipt({ verifiedAt: '2026-05-01T11:00:00.000Z' })

    render(
      <ReceiptComparisonView
        initialLeft={receiptA}
        initialRight={receiptB}
        baseUrl="https://verify.harpocrates.example"
      />,
    )

    await user.click(screen.getByRole('button', { name: /copy comparison link/i }))

    expect(writeText).toHaveBeenCalledTimes(1)
    const copiedUrl = writeText.mock.calls[0][0] as string
    expect(copiedUrl.startsWith('https://verify.harpocrates.example#verify?compare=')).toBe(true)
    expect(copiedUrl).not.toMatch(/fileName|witness|nullifier|secret|media|stego/i)
    expect(screen.getByText(/comparison link copied/i)).toBeInTheDocument()
  })

  it('supports swapping and clearing receipts', async () => {
    const user = userEvent.setup()
    const receiptA = makeReceipt({ verifiedAt: '2026-05-01T10:00:00.000Z' })
    const receiptB = makeReceipt({ verifiedAt: '2026-05-01T11:00:00.000Z' })

    render(<ReceiptComparisonView initialLeft={receiptA} initialRight={receiptB} />)

    expect(screen.getByTestId('receipt-time-delta')).toHaveTextContent('+1h')

    await user.click(screen.getByRole('button', { name: /swap receipts/i }))
    expect(screen.getByTestId('receipt-time-delta')).toHaveTextContent('-1h')

    await user.click(screen.getByRole('button', { name: /clear receipt comparison/i }))
    expect(screen.queryByTestId('receipt-time-delta')).not.toBeInTheDocument()
  })
})
