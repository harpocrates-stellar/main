/**
 * useWallet — manages Freighter wallet connection and network validation.
 *
 * Network guard behaviour:
 *   1. On initial connect: `checkNetworkMatch` is called; mismatch sets
 *      `networkMismatch` and re-throws so the caller can surface a banner.
 *   2. While connected: `WatchWalletChanges` polls every 3 s and re-validates
 *      network/account changes. On a mid-session network switch the mismatch
 *      banner is raised and the wallet address is cleared until the user
 *      reconnects on the correct network.
 *
 * Privacy notes:
 *   - `networkMismatch` contains only human-readable network names (e.g.
 *     "Mainnet", "Testnet"); wallet addresses, private keys, and proof bytes
 *     are never included in the mismatch message.
 *   - The watcher is stopped on unmount and on disconnect.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

export type UseWalletReturn = {
  wallet: string
  networkMismatch: string | null
  connectWallet: () => Promise<void>
  disconnectWallet: () => void
}

export function useWallet(): UseWalletReturn {
  const [wallet, setWallet] = useState('')
  const [networkMismatch, setNetworkMismatch] = useState<string | null>(null)

  // Keep a ref to the active WatchWalletChanges instance so we can stop it on
  // unmount or reconnect without capturing stale closures.
  const watcherRef = useRef<{ stop: () => void } | null>(null)

  /** Stop any active watcher and release the ref. */
  function stopWatcher() {
    watcherRef.current?.stop()
    watcherRef.current = null
  }

  /** Disconnect: clear wallet state and stop background watcher. */
  const disconnectWallet = useCallback(() => {
    stopWatcher()
    setWallet('')
    setNetworkMismatch(null)
  }, [])

  async function connectWallet() {
    // Stop any previous watcher before establishing a new connection.
    stopWatcher()

    const stellar = await import('../stellar')
    const { connectFreighter, getWalletNetwork, CONTRACT_NETWORK_PASSPHRASE, WatchWalletChanges } = stellar
    const { checkNetworkMatch } = await import('../networkGuard')

    const publicKey = await connectFreighter()
    // Store the address before the network check so VerifyView and StudioView
    // can still show the truncated address even on mismatch (existing test
    // behaviour preserved).
    setWallet(publicKey)

    const walletPassphrase = await getWalletNetwork()
    const check = checkNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)
    if (check.ok) {
      setNetworkMismatch(null)
    } else {
      setNetworkMismatch(`${check.reason} ${check.remediation}`)
      throw new Error(check.reason)
    }

    // Start background watcher now that the connection is healthy.
    // Pass checkNetworkMatch and CONTRACT_NETWORK_PASSPHRASE directly from
    // the already-resolved import so the watcher doesn't need its own async import.
    const watcher = new WatchWalletChanges(3000)
    watcherRef.current = watcher

    watcher.watch(({ address, networkPassphrase, error }) => {
      if (error) {
        // Extension locked or unavailable during the watch period.
        const result = checkNetworkMatch('', CONTRACT_NETWORK_PASSPHRASE)
        if (!result.ok) {
          setNetworkMismatch(`${result.reason} ${result.remediation}`)
          setWallet('')
        }
        return
      }

      const result = checkNetworkMatch(networkPassphrase, CONTRACT_NETWORK_PASSPHRASE)
      if (!result.ok) {
        setNetworkMismatch(`${result.reason} ${result.remediation}`)
        // Clear the wallet so actions requiring a healthy connection are blocked.
        setWallet('')
      } else {
        // Network is healthy; update the address (user may have switched
        // accounts) and clear any stale mismatch.
        setWallet(address)
        setNetworkMismatch(null)
      }
    })
  }

  // Stop the watcher when the hook unmounts (component teardown).
  useEffect(() => {
    return () => {
      stopWatcher()
    }
  }, [])

  return { wallet, networkMismatch, connectWallet, disconnectWallet }
}
