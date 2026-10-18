/**
 * Tests for the stellar adapter (connectFreighter / getWalletNetwork).
 * Mocks @stellar/freighter-api so no real extension or network is involved.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

const TESTNET = 'Test SDF Network ; September 2015'

// ── freighter-api mock ──────────────────────────────────────────────────────

const requestAccessMock = vi.fn()
const getNetworkMock = vi.fn()

vi.mock('@stellar/freighter-api', () => ({
  getNetwork: getNetworkMock,
  requestAccess: requestAccessMock,
}))

beforeEach(() => {
  requestAccessMock.mockReset()
  getNetworkMock.mockReset()
})

// ── connectFreighter ────────────────────────────────────────────────────────

describe('connectFreighter – success', () => {
  it('returns the connected address when requestAccess succeeds', async () => {
    requestAccessMock.mockResolvedValue({
      address: 'GABC123',
      error: undefined,
    })

    const { connectFreighter } = await import('./stellar')
    const address = await connectFreighter()

    expect(address).toBe('GABC123')
  })
})

describe('connectFreighter – error', () => {
  it('throws when requestAccess reports an error', async () => {
    requestAccessMock.mockResolvedValue({
      address: undefined,
      error: { message: 'User rejected the connection.' },
    })

    const { connectFreighter } = await import('./stellar')

    await expect(connectFreighter()).rejects.toThrow(
      'User rejected the connection.',
    )
  })
})

// ── getWalletNetwork ────────────────────────────────────────────────────────

describe('getWalletNetwork – success', () => {
  it('returns the network passphrase from getNetwork', async () => {
    getNetworkMock.mockResolvedValue({
      network: 'TESTNET',
      networkPassphrase: TESTNET,
      error: undefined,
    })

    const { getWalletNetwork } = await import('./stellar')
    const passphrase = await getWalletNetwork()

    expect(passphrase).toBe(TESTNET)
  })
})

describe('getWalletNetwork – error', () => {
  it('returns an empty string when getNetwork reports an error', async () => {
    getNetworkMock.mockResolvedValue({
      network: undefined,
      networkPassphrase: undefined,
      error: { message: 'Extension is locked.' },
    })

    const { getWalletNetwork } = await import('./stellar')
    const passphrase = await getWalletNetwork()

    expect(passphrase).toBe('')
  })

  it('returns an empty string when networkPassphrase is missing', async () => {
    getNetworkMock.mockResolvedValue({
      network: 'TESTNET',
      networkPassphrase: undefined,
      error: undefined,
    })

    const { getWalletNetwork } = await import('./stellar')
    const passphrase = await getWalletNetwork()

    expect(passphrase).toBe('')
  })
})