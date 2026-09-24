/**
 * Tests for useWallet hook.
 * Mocks stellar and networkGuard dynamic imports via vi.mock.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useWallet } from './useWallet'

const TESTNET = 'Test SDF Network ; September 2015'
const MAINNET = 'Public Global Stellar Network ; September 2015'

// ── WatchWalletChanges mock ───────────────────────────────────────────────
// We keep a reference to the most recently constructed watcher so individual
// tests can fire the callback to simulate mid-session network/account changes.
type WatchCallback = (params: {
  address: string
  network: string
  networkPassphrase: string
  error?: { message: string }
}) => void

class MockWatchWalletChanges {
  public cb: WatchCallback | null = null
  public stopped = false

  watch(cb: WatchCallback) {
    this.cb = cb
    return {}
  }

  fire(params: Parameters<WatchCallback>[0]) {
    this.cb?.(params)
  }

  stop() {
    this.stopped = true
  }
}

let latestWatcher: MockWatchWalletChanges | null = null

// ── Factory that creates the WatchWalletChanges constructor mock ──────────
// We define a stable mock factory rather than using vi.fn() so that
// vi.clearAllMocks() does not strip the constructor behaviour.
function makeWatcherCtor() {
  return function WatchWalletChangesMock(this: MockWatchWalletChanges) {
    const instance = new MockWatchWalletChanges()
    latestWatcher = instance
    // Copy methods onto `this` so `new WatchWalletChangesMock()` returns a proper
    // instance-like object and the hook can call instance.watch / instance.stop.
    Object.assign(this as object, instance)
    // Replace own methods with the instance's bound versions.
    ;(this as unknown as MockWatchWalletChanges).watch = instance.watch.bind(instance)
    ;(this as unknown as MockWatchWalletChanges).stop = instance.stop.bind(instance)
    ;(this as unknown as MockWatchWalletChanges).fire = instance.fire.bind(instance)
  }
}

// Mock the modules that useWallet imports dynamically.
vi.mock('../stellar', () => {
  return {
    connectFreighter: vi.fn(),
    getWalletNetwork: vi.fn(),
    CONTRACT_NETWORK_PASSPHRASE: TESTNET,
    get WatchWalletChanges() {
      return WatchWalletChangesCtor
    },
  }
})

vi.mock('../networkGuard', () => ({
  checkNetworkMatch: vi.fn(),
}))

// Stable constructor — replaced per-test by reassigning WatchWalletChangesCtor.
let WatchWalletChangesCtor: ReturnType<typeof makeWatcherCtor>
WatchWalletChangesCtor = makeWatcherCtor()

async function getStellarMock() {
  const mod = await import('../stellar')
  return mod as unknown as {
    connectFreighter: ReturnType<typeof vi.fn>
    getWalletNetwork: ReturnType<typeof vi.fn>
    CONTRACT_NETWORK_PASSPHRASE: string
  }
}

async function getNetworkGuardMock() {
  const mod = await import('../networkGuard')
  return mod as unknown as { checkNetworkMatch: ReturnType<typeof vi.fn> }
}

beforeEach(async () => {
  vi.clearAllMocks()
  latestWatcher = null
  WatchWalletChangesCtor = makeWatcherCtor()

  const stellar = await getStellarMock()
  stellar.connectFreighter.mockResolvedValue('GPUBLIC_KEY_123')
  stellar.getWalletNetwork.mockResolvedValue(TESTNET)

  const guard = await getNetworkGuardMock()
  guard.checkNetworkMatch.mockReset()
  guard.checkNetworkMatch.mockReturnValue({ ok: true })
})

// ── successful connection ─────────────────────────────────────────────────

describe('useWallet – successful connection', () => {
  it('sets wallet address after connecting', async () => {
    const { result } = renderHook(() => useWallet())

    await act(async () => {
      await result.current.connectWallet()
    })

    expect(result.current.wallet).toBe('GPUBLIC_KEY_123')
  })

  it('clears networkMismatch on a matching network', async () => {
    const { result } = renderHook(() => useWallet())

    await act(async () => {
      await result.current.connectWallet()
    })

    expect(result.current.networkMismatch).toBeNull()
  })

  it('exposes a disconnectWallet function that clears state', async () => {
    const { result } = renderHook(() => useWallet())

    await act(async () => {
      await result.current.connectWallet()
    })

    expect(result.current.wallet).toBe('GPUBLIC_KEY_123')

    act(() => {
      result.current.disconnectWallet()
    })

    expect(result.current.wallet).toBe('')
    expect(result.current.networkMismatch).toBeNull()
  })
})

// ── network mismatch ──────────────────────────────────────────────────────

describe('useWallet – network mismatch', () => {
  it('sets networkMismatch when the wallet is on the wrong network', async () => {
    const stellar = await getStellarMock()
    stellar.getWalletNetwork.mockResolvedValue(MAINNET)

    const guard = await getNetworkGuardMock()
    guard.checkNetworkMatch.mockReturnValue({
      ok: false,
      reason: 'Wallet is on Mainnet but the contract is deployed on Testnet.',
      remediation: 'Open Freighter, switch to Testnet, then reconnect.',
    })

    const { result } = renderHook(() => useWallet())

    await act(async () => {
      try {
        await result.current.connectWallet()
      } catch {
        // expected — mismatch throws
      }
    })

    expect(result.current.networkMismatch).toContain('Mainnet')
    expect(result.current.networkMismatch).toContain('Testnet')
  })

  it('still stores the wallet address even on mismatch', async () => {
    const guard = await getNetworkGuardMock()
    guard.checkNetworkMatch.mockReturnValue({
      ok: false,
      reason: 'Wrong network.',
      remediation: 'Switch.',
    })

    const { result } = renderHook(() => useWallet())

    await act(async () => {
      try {
        await result.current.connectWallet()
      } catch {
        // expected
      }
    })

    expect(result.current.wallet).toBe('GPUBLIC_KEY_123')
  })
})

// ── connectFreighter failure ──────────────────────────────────────────────

describe('useWallet – Freighter unavailable', () => {
  it('propagates the error from connectFreighter', async () => {
    const stellar = await getStellarMock()
    stellar.connectFreighter.mockRejectedValue(new Error('Freighter is not installed.'))

    const { result } = renderHook(() => useWallet())

    await expect(
      act(async () => {
        await result.current.connectWallet()
      }),
    ).rejects.toThrow('Freighter is not installed.')

    expect(result.current.wallet).toBe('')
  })
})

// ── mid-session network / account change (WatchWalletChanges) ────────────

describe('useWallet – mid-session wallet changes', () => {
  it('raises networkMismatch and clears wallet when watcher fires a network switch', async () => {
    const guard = await getNetworkGuardMock()
    // First call: initial connect succeeds; second call: network switched → mismatch
    guard.checkNetworkMatch
      .mockReturnValueOnce({ ok: true })
      .mockReturnValueOnce({
        ok: false,
        reason: 'Wallet is on Mainnet but the contract is deployed on Testnet.',
        remediation: 'Open Freighter, switch to Testnet, then reconnect.',
      })

    const { result } = renderHook(() => useWallet())

    await act(async () => {
      await result.current.connectWallet()
    })

    expect(result.current.wallet).toBe('GPUBLIC_KEY_123')
    expect(result.current.networkMismatch).toBeNull()
    expect(latestWatcher).not.toBeNull()

    // Simulate the watcher firing with a switched network.
    act(() => {
      latestWatcher!.fire({
        address: 'GPUBLIC_KEY_123',
        network: 'PUBLIC',
        networkPassphrase: MAINNET,
      })
    })

    expect(result.current.networkMismatch).toContain('Mainnet')
    // Wallet address cleared after network switch
    expect(result.current.wallet).toBe('')
  })

  it('reconnecting after fixing the network clears the mismatch', async () => {
    const guard = await getNetworkGuardMock()
    // First connect: mismatch; second connect: ok
    guard.checkNetworkMatch
      .mockReturnValueOnce({
        ok: false,
        reason: 'Wallet is on Mainnet but the contract is deployed on Testnet.',
        remediation: 'Switch.',
      })
      .mockReturnValueOnce({ ok: true })

    const { result } = renderHook(() => useWallet())

    // First connect attempt → mismatch
    await act(async () => {
      try {
        await result.current.connectWallet()
      } catch {
        // expected
      }
    })

    expect(result.current.networkMismatch).toBeTruthy()

    // User fixes network; second connect attempt → ok
    await act(async () => {
      await result.current.connectWallet()
    })

    expect(result.current.networkMismatch).toBeNull()
    expect(result.current.wallet).toBe('GPUBLIC_KEY_123')
  })

  it('raises mismatch when watcher fires an error (extension locked)', async () => {
    const guard = await getNetworkGuardMock()
    // connect: ok; watcher error callback: mismatch (empty passphrase)
    guard.checkNetworkMatch
      .mockReturnValueOnce({ ok: true })
      .mockReturnValueOnce({
        ok: false,
        reason: 'Freighter did not return a network. The extension may be locked or unavailable.',
        remediation: 'Unlock Freighter, make sure it is connected, then reconnect your wallet.',
      })

    const { result } = renderHook(() => useWallet())

    await act(async () => {
      await result.current.connectWallet()
    })

    expect(latestWatcher).not.toBeNull()

    act(() => {
      latestWatcher!.fire({
        address: '',
        network: '',
        networkPassphrase: '',
        error: { message: 'Extension locked' },
      })
    })

    expect(result.current.networkMismatch).toBeTruthy()
    expect(result.current.wallet).toBe('')
  })

  it('recovers automatically when the wallet returns to the expected network', async () => {
    const guard = await getNetworkGuardMock()
    guard.checkNetworkMatch
      .mockReturnValueOnce({ ok: true })
      .mockReturnValueOnce({
        ok: false,
        reason: 'Wallet is on Mainnet but the contract is deployed on Testnet.',
        remediation: 'Switch to Testnet.',
      })
      .mockReturnValueOnce({ ok: true })

    const { result } = renderHook(() => useWallet())
    await act(async () => {
      await result.current.connectWallet()
    })

    act(() => {
      latestWatcher!.fire({
        address: 'GPUBLIC_KEY_123',
        network: 'PUBLIC',
        networkPassphrase: MAINNET,
      })
    })
    expect(result.current.wallet).toBe('')
    expect(result.current.networkMismatch).toContain('Mainnet')

    act(() => {
      latestWatcher!.fire({
        address: 'GPUBLIC_KEY_123',
        network: 'TESTNET',
        networkPassphrase: TESTNET,
      })
    })
    expect(result.current.wallet).toBe('GPUBLIC_KEY_123')
    expect(result.current.networkMismatch).toBeNull()
  })

  it('ignores stale callbacks from a watcher replaced by a reconnect', async () => {
    const guard = await getNetworkGuardMock()
    guard.checkNetworkMatch.mockReturnValue({ ok: true })

    const { result } = renderHook(() => useWallet())
    await act(async () => {
      await result.current.connectWallet()
    })
    const firstWatcher = latestWatcher

    await act(async () => {
      await result.current.connectWallet()
    })
    const secondWatcher = latestWatcher

    act(() => {
      firstWatcher!.fire({
        address: 'STALE_ADDRESS',
        network: 'PUBLIC',
        networkPassphrase: MAINNET,
      })
    })
    expect(result.current.wallet).toBe('GPUBLIC_KEY_123')
    expect(result.current.networkMismatch).toBeNull()

    act(() => {
      secondWatcher!.fire({
        address: 'NEW_ADDRESS',
        network: 'TESTNET',
        networkPassphrase: TESTNET,
      })
    })
    expect(result.current.wallet).toBe('NEW_ADDRESS')
  })

  it('stops the watcher on unmount', async () => {
    const { result, unmount } = renderHook(() => useWallet())

    await act(async () => {
      await result.current.connectWallet()
    })

    const watcher = latestWatcher
    expect(watcher).not.toBeNull()
    expect(watcher?.stopped).toBe(false)

    unmount()

    expect(watcher?.stopped).toBe(true)
  })

  it('stops the previous watcher when connectWallet is called again', async () => {
    const { result } = renderHook(() => useWallet())

    await act(async () => {
      await result.current.connectWallet()
    })

    const firstWatcher = latestWatcher

    await act(async () => {
      await result.current.connectWallet()
    })

    // Old watcher stopped, new one started
    expect(firstWatcher?.stopped).toBe(true)
    expect(latestWatcher).not.toBe(firstWatcher)
  })
})
