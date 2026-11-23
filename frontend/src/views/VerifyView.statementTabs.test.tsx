import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import '../App.css'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'
import type { ChainProofRecord, Hex32 } from '../stellarTypes'
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

vi.mock('../components/DisputePanel', () => ({
  DisputePanel: () => <div data-testid="dispute-panel" />,
}))

vi.mock('../components/VerifierSetStatusPanel', () => ({
  VerifierSetStatusPanel: () => <div data-testid="verifier-set-status-panel" />,
}))

vi.mock('../provenance/ProvenanceCard', () => ({
  default: () => <div data-testid="provenance-card" />,
}))

const DIGEST_ONE = '1'.repeat(64) as Hex32
const DIGEST_TWO = '2'.repeat(64) as Hex32
const META_ONE = 'a'.repeat(64) as Hex32
const META_TWO = 'b'.repeat(64) as Hex32
const PROOF_ONE = `0x${'d'.repeat(64)}`
const PROOF_UNRELATED = `0x${'e'.repeat(64)}`
const PROOF_TWO = `0x${'f'.repeat(64)}`

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: DIGEST_ONE,
    metadataHash: META_ONE,
    tier: 1,
    source: 'GSRC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEF',
    issuer: 'GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEF',
    createdAt: '1750000000',
    expiresAt: 0,
    status: 1,
    ...overrides,
  }
}

function makeHook(overrides: Partial<UseVerificationReturn> = {}): UseVerificationReturn {
  return {
    verifyHash: DIGEST_ONE,
    verifyResult: 'Confirmed on Soroban.',
    events: [
      {
        id: 10,
        video_hash: '9'.repeat(64),
        proof_id: PROOF_UNRELATED,
        tier: 'seal',
        tx_hash: '8'.repeat(64),
        created_at: '2026-10-01T00:00:00Z',
      },
      {
        id: 11,
        video_hash: DIGEST_ONE,
        proof_id: PROOF_ONE,
        tier: 'source',
        tx_hash: '7'.repeat(64),
        created_at: '2026-10-01T01:00:00Z',
      },
    ],
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

describe('VerifyView verified statement digest across result tabs (#1140)', () => {
  it('preserves canonical statement digest and matching proof identity across all result tabs and keyboard navigation', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={null}
      />,
    )

    // Summary tab active by default
    expect(screen.getByRole('tab', { name: /summary/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(screen.getByTestId('tab-statement-digest')).toHaveTextContent(DIGEST_ONE)
    expect(screen.getByTestId('tab-proof-identity')).toHaveTextContent(PROOF_ONE)

    // Switch to Chain binding tab via click
    await user.click(screen.getByRole('tab', { name: /chain binding/i }))
    expect(screen.getByTestId('tab-statement-digest')).toHaveTextContent(DIGEST_ONE)
    expect(screen.getByTestId('tab-proof-identity')).toHaveTextContent(PROOF_ONE)

    // Switch to Event corroboration tab via ArrowRight keyboard navigation
    fireEvent.keyDown(screen.getByRole('tab', { name: /chain binding/i }), {
      key: 'ArrowRight',
    })
    expect(screen.getByRole('tab', { name: /event corroboration/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(screen.getByTestId('tab-statement-digest')).toHaveTextContent(DIGEST_ONE)
    expect(screen.getByTestId('tab-proof-identity')).toHaveTextContent(PROOF_ONE)
    // Only event #11 belongs to DIGEST_ONE; unrelated event #10 is excluded from the statement panel
    expect(screen.getByRole('button', { name: /inspect event #11/i })).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /inspect event #10/i }),
    ).not.toBeInTheDocument()

    const tabsSection = container.querySelector('.verification-result-tabs') as HTMLElement
    expectNoA11yViolations(await runAxe(tabsSection), 'VerifyView result tabs')
  })

  it('resets active tab and dependent commitment/event inspection views when the underlying statement changes', async () => {
    const user = userEvent.setup()
    const { rerender } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook()}
        provenanceRecord={null}
      />,
    )

    // Open dependent commitment details in Chain binding tab
    await user.click(screen.getByRole('tab', { name: /chain binding/i }))
    await user.click(screen.getByRole('button', { name: /inspect commitment digests/i }))
    expect(screen.getByTestId('dependent-commitment-details')).toHaveTextContent(META_ONE)

    // Select an event in Event corroboration tab
    await user.click(screen.getByRole('tab', { name: /event corroboration/i }))
    await user.click(screen.getByRole('button', { name: /inspect event #11/i }))
    expect(screen.getByTestId('dependent-selected-event')).toHaveTextContent('7'.repeat(64))

    // Change underlying statement digest -> dependent views and tab selection reset
    rerender(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({
          verifyHash: DIGEST_TWO,
          events: [
            {
              id: 22,
              video_hash: DIGEST_TWO,
              proof_id: PROOF_TWO,
              tier: 'silent',
              tx_hash: '6'.repeat(64),
              created_at: '2026-10-02T00:00:00Z',
            },
          ],
          chainProof: makeChainProof({
            videoHash: DIGEST_TWO,
            metadataHash: META_TWO,
          }),
        })}
        provenanceRecord={null}
      />,
    )

    expect(screen.getByRole('tab', { name: /summary/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(screen.getByTestId('tab-statement-digest')).toHaveTextContent(DIGEST_TWO)
    expect(screen.getByTestId('tab-proof-identity')).toHaveTextContent(PROOF_TWO)
    expect(
      screen.queryByTestId('dependent-commitment-details'),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByTestId('dependent-selected-event'),
    ).not.toBeInTheDocument()

    // Re-entering Chain binding tab confirms dependent expansion was reset
    await user.click(screen.getByRole('tab', { name: /chain binding/i }))
    expect(
      screen.queryByTestId('dependent-commitment-details'),
    ).not.toBeInTheDocument()
  })
})
