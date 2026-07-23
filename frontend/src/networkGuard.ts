/**
 * Network mismatch detection for Harpocrates frontend.
 *
 * The contract is always deployed against a specific network passphrase
 * (currently Stellar Testnet). Before submitting a transaction we compare
 * the wallet's reported network passphrase with the one compiled into the
 * registry client. A mismatch must block submission so the user never
 * accidentally targets the wrong deployment.
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
 * Returns `{ ok: true }` when they match, or `{ ok: false, reason, remediation }`
 * when they do not – including when the wallet returned an empty or unrecognised
 * passphrase that cannot be safely compared.
 */
export function checkNetworkMatch(
  walletPassphrase: string,
  contractPassphrase: string,
): NetworkCheckResult {
  const wallet = walletPassphrase.trim()

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
