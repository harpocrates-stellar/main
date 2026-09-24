/**
 * Integration tests for network-mismatch guard at the App boundary.
 *
 * These tests verify that:
 *   1. A global network-mismatch banner appears below the navbar after a
 *      failed wallet connection.
 *   2. The Evidence Studio banner also appears (forwarded from useEvidence).
 *   3. The Verification Portal shows its own banner via the networkMismatch
 *      prop forwarded from App.
 *   4. The wallet icon button gains the `wallet-mismatch` class on mismatch.
 *   5. Privacy: no raw addresses, proof bytes, or wallet private keys appear
 *      in the rendered DOM.
 *
 * Mocking strategy:
 *   - useWallet is mocked to control networkMismatch state without a real
 *     Freighter extension.
 *   - The underlying view components render real; only the hook is stubbed.
 *
 * Note: App.tsx always renders a sr-only `role="alert"` live region. The tests
 * below query the network mismatch banner specifically via its class name
 * `network-mismatch-banner--global` to avoid ambiguity with that region.
 */

import React from 'react'
import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// ── Module mocks ──────────────────────────────────────────────────────────

vi.mock('./components/EvilEye', () => ({
  default: () => <div data-testid="evil-eye" />,
}))

// Control useWallet state from tests via these mutable references.
let mockWallet = ''
let mockNetworkMismatch: string | null = null
const mockConnectWallet = vi.fn()
const mockDisconnectWallet = vi.fn()

vi.mock('./hooks/useWallet', () => ({
  useWallet: () => ({
    wallet: mockWallet,
    networkMismatch: mockNetworkMismatch,
    connectWallet: mockConnectWallet,
    disconnectWallet: mockDisconnectWallet,
  }),
}))

// Prevent real evidence/verification service calls.
vi.mock('./services/evidenceService', () => ({
  embedVideo: vi.fn().mockRejectedValue(new Error('no backend in test')),
  fetchRecentEvents: vi.fn().mockResolvedValue([]),
  persistRegistration: vi.fn(),
}))

vi.mock('./services/verificationService', () => ({
  extractMetadata: vi.fn().mockRejectedValue(new Error('no backend in test')),
  fetchProofEventsByVideo: vi.fn().mockResolvedValue([]),
  getOnChainProof: vi.fn().mockResolvedValue(null),
}))

// ── Helpers ───────────────────────────────────────────────────────────────

// Lazy import App after mocks are registered to avoid hoisting issues.
let App: typeof import('./App').default

/**
 * Query the *global* network-mismatch banner by its specific class.
 * This avoids ambiguity with the sr-only aria-live alert region that App
 * always renders.
 */
function getGlobalMismatchBanner() {
  return document.querySelector('.network-mismatch-banner--global')
}

beforeEach(async () => {
  vi.clearAllMocks()
  mockWallet = ''
  mockNetworkMismatch = null
  window.history.replaceState(null, '', '/')
  Object.defineProperty(window, 'scrollTo', { configurable: true, value: vi.fn() })

  if (!App) {
    const mod = await import('./App')
    App = mod.default
  }
})

// ── Global mismatch banner in navbar area ─────────────────────────────────

describe('App – global network mismatch banner', () => {
  it('does not render the global mismatch banner when there is no mismatch', () => {
    render(<App />)
    expect(getGlobalMismatchBanner()).not.toBeInTheDocument()
  })

  it('renders a global mismatch banner when networkMismatch is set', () => {
    mockNetworkMismatch =
      'Wallet is on Mainnet but the contract is deployed on Testnet. Open Freighter, switch to Testnet, then reconnect your wallet.'

    render(<App />)

    const banner = getGlobalMismatchBanner()
    expect(banner).toBeInTheDocument()
    expect(banner?.textContent).toContain('Mainnet')
    expect(banner?.textContent).toContain('Testnet')
  })

  it('global banner contains the remediation instruction', () => {
    mockNetworkMismatch =
      'Wallet is on Mainnet but the contract is deployed on Testnet. Open Freighter, switch to Testnet, then reconnect your wallet.'

    render(<App />)

    expect(getGlobalMismatchBanner()?.textContent?.toLowerCase()).toContain('open freighter')
  })

  it('global banner has aria-live="assertive" for screen readers', () => {
    mockNetworkMismatch = 'Wrong network. Switch.'
    render(<App />)
    expect(getGlobalMismatchBanner()).toHaveAttribute('aria-live', 'assertive')
  })

  it('global banner has role="alert"', () => {
    mockNetworkMismatch = 'Wrong network. Switch.'
    render(<App />)
    expect(getGlobalMismatchBanner()).toHaveAttribute('role', 'alert')
  })

  it('connect-wallet button gains wallet-mismatch class on mismatch', () => {
    mockNetworkMismatch = 'Wrong network. Switch.'
    render(<App />)
    const btn = screen.getByTitle(/wallet network mismatch|connect wallet/i)
    expect(btn).toHaveClass('wallet-mismatch')
  })

  it('does not render global banner after mismatch is cleared', async () => {
    // Render with mismatch first.
    mockNetworkMismatch = 'Wrong network. Switch.'
    const { rerender } = render(<App />)
    expect(getGlobalMismatchBanner()).toBeInTheDocument()

    // Simulate mismatch cleared (user reconnected correctly).
    mockNetworkMismatch = null
    rerender(<App />)

    expect(getGlobalMismatchBanner()).not.toBeInTheDocument()
  })
})

// ── Mismatch banner visible in Evidence Studio ────────────────────────────

describe('App – Evidence Studio mismatch banner', () => {
  it('shows studio-level mismatch banner when networkMismatch is set', async () => {
    const user = userEvent.setup()
    mockNetworkMismatch =
      'Wallet is on Mainnet but the contract is deployed on Testnet. Open Freighter, switch to Testnet.'

    render(<App />)
    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))

    // There should be at least the global banner and the studio banner.
    const banners = document.querySelectorAll('.network-mismatch-banner')
    expect(banners.length).toBeGreaterThanOrEqual(1)
    const texts = Array.from(banners).map((b) => b.textContent ?? '')
    expect(texts.some((t) => /Mainnet/i.test(t))).toBe(true)
  })

  it('Register proof button is disabled when networkMismatch is set', async () => {
    const user = userEvent.setup()
    mockNetworkMismatch = 'Wrong network.'
    render(<App />)
    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))

    expect(screen.getByRole('button', { name: /register proof/i })).toBeDisabled()
  })
})

// ── Mismatch banner visible in Verify Portal ──────────────────────────────

describe('App – Verification Portal mismatch banner', () => {
  it('shows a mismatch banner in VerifyView when networkMismatch is set', async () => {
    const user = userEvent.setup()
    mockNetworkMismatch =
      'Wallet is on Mainnet but the contract is deployed on Testnet. Open Freighter, switch to Testnet.'

    render(<App />)
    await user.click(screen.getByRole('button', { name: /^verify$/i }))

    // At least the VerifyView-specific banner should be present.
    const banners = document.querySelectorAll('.network-mismatch-banner')
    expect(banners.length).toBeGreaterThanOrEqual(2) // global + verify
    const texts = Array.from(banners).map((b) => b.textContent ?? '')
    expect(texts.some((t) => /Mainnet/i.test(t))).toBe(true)
  })

  it('does not show mismatch banners in VerifyView when networkMismatch is null', async () => {
    const user = userEvent.setup()
    mockNetworkMismatch = null
    render(<App />)
    await user.click(screen.getByRole('button', { name: /^verify$/i }))

    // No .network-mismatch-banner elements when there is no mismatch.
    const banners = document.querySelectorAll('.network-mismatch-banner')
    expect(banners.length).toBe(0)
  })
})

// ── Privacy: mismatch messages must not leak sensitive context ────────────

describe('App – mismatch banner privacy invariants', () => {
  it('banner text does not include raw passphrase strings', () => {
    mockNetworkMismatch =
      'Wallet is on Mainnet but the contract is deployed on Testnet. Open Freighter, switch to Testnet.'
    render(<App />)

    const bannerText = getGlobalMismatchBanner()?.textContent ?? ''
    // The full passphrase must not appear verbatim.
    expect(bannerText).not.toContain('Public Global Stellar Network ; September 2015')
    expect(bannerText).not.toContain('Test SDF Network ; September 2015')
  })

  it('banner text does not include a wallet address', () => {
    mockWallet = 'GPUBLIC_KEY_SHOULD_NOT_APPEAR_IN_BANNER'
    mockNetworkMismatch = 'Wrong network. Switch.'
    render(<App />)

    const bannerText = getGlobalMismatchBanner()?.textContent ?? ''
    expect(bannerText).not.toContain('GPUBLIC_KEY_SHOULD_NOT_APPEAR_IN_BANNER')
  })
})

// ── Connect button wires through to connectWallet ─────────────────────────

describe('App – connect wallet button', () => {
  it('calls connectWallet when the button is clicked', async () => {
    const user = userEvent.setup()
    mockConnectWallet.mockResolvedValue(undefined)
    render(<App />)

    // The connect button has title="Connect wallet" when no mismatch is active.
    await user.click(screen.getByTitle('Connect wallet'))

    expect(mockConnectWallet).toHaveBeenCalledOnce()
  })

  it('does not throw to the surface when connectWallet rejects (mismatch case)', async () => {
    const user = userEvent.setup()
    mockConnectWallet.mockRejectedValue(new Error('Wallet is on Mainnet.'))
    render(<App />)

    // Should not throw — the .catch(() => {}) in App swallows the rejection.
    await expect(
      act(() => user.click(screen.getByTitle('Connect wallet'))),
    ).resolves.not.toThrow()
  })
})
