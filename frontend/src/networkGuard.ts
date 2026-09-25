/**
 * Network mismatch detection for Harpocrates frontend.
 *
 * The contract is always deployed against a specific network passphrase
 * (currently Stellar Testnet). Before submitting a transaction we compare
 * the wallet's reported network passphrase with the one compiled into the
 * registry client. A mismatch must block submission so the user never
 * accidentally targets the wrong deployment.
 *
 * Privacy notes:
 *   - Error messages include only the public network name (Testnet, Mainnet,
 *     etc.), never wallet addresses, private keys, or any witness material.
 *   - `assertNetworkMatch` throws only a stable, non-identifying string so
 *     callers can safely surface it to the user or log it.
 */

/** All Stellar network passphrases that this app can interpret by name. */
const KNOWN_PASSPHRASES: Record<string, string> = {
  'Public Global Stellar Network ; September 2015': 'Mainnet',
  'Test SDF Network ; September 2015': 'Testnet',
  'Test SDF Future Network ; October 2022': 'Futurenet',
  'Local Sandbox Stellar Network ; September 2022': 'Sandbox',
  'Standalone Network ; February 2017': 'Standalone',
}

/** Human-readable name for a network passphrase, falling back to the raw value. */
export function networkName(passphrase: string): string {
  return KNOWN_PASSPHRASES[passphrase] ?? passphrase
}

export type NetworkCheckResult =
  | { ok: true }
  | { ok: false; reason: string; remediation: string }

/**
 * Compare the wallet's active network passphrase against the passphrase that
 * the deployed contract was built for.
 *
 * Accepts `null` or `undefined` in addition to empty string — all three
 * indicate that the wallet extension is unavailable or did not return a value.
 *
 * Returns `{ ok: true }` when they match, or `{ ok: false, reason, remediation }`
 * when they do not – including when the wallet returned an empty, null,
 * undefined, or unrecognised passphrase that cannot be safely compared.
 */
export function checkNetworkMatch(
  walletPassphrase: string | null | undefined,
  contractPassphrase: string,
): NetworkCheckResult {
  // Treat null, undefined, and blank strings uniformly: the wallet is
  // unavailable or locked and cannot be compared.
  const wallet = (walletPassphrase ?? '').trim()

  if (!wallet) {
    return {
      ok: false,
      reason: 'Freighter did not return a network. The extension may be locked or unavailable.',
      remediation:
        'Unlock Freighter, make sure it is connected to this site, then reconnect your wallet.',
    }
  }

  if (wallet === contractPassphrase) {
    return { ok: true }
  }

  const walletLabel = networkName(wallet)
  const contractLabel = networkName(contractPassphrase)

  return {
    ok: false,
    reason: `Wallet is on ${walletLabel} but the contract is deployed on ${contractLabel}.`,
    remediation: `Open Freighter, switch to ${contractLabel}, then reconnect your wallet.`,
  }
}

/**
 * Asserting variant of `checkNetworkMatch`.
 *
 * Throws a `NetworkMismatchError` when the wallets's network does not match
 * `contractPassphrase`. The error message is the same human-readable reason
 * string so callers can safely surface it without additional transformation.
 *
 * Usage:
 * ```ts
 * assertNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)
 * // proceeds only when networks match
 * ```
 */
export class NetworkMismatchError extends Error {
  readonly remediation: string

  constructor(reason: string, remediation: string) {
    super(reason)
    this.name = 'NetworkMismatchError'
    this.remediation = remediation
  }
}

export function assertNetworkMatch(
  walletPassphrase: string | null | undefined,
  contractPassphrase: string,
): void {
  const result = checkNetworkMatch(walletPassphrase, contractPassphrase)
  if (!result.ok) {
    throw new NetworkMismatchError(result.reason, result.remediation)
  }
}
