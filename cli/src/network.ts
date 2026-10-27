import { Networks } from '@stellar/stellar-sdk'

/** Network used when `--network` is not given. */
export const DEFAULT_NETWORK_PASSPHRASE: string = Networks.TESTNET

const NETWORK_ALIASES: Record<string, string> = {
  testnet: Networks.TESTNET,
  mainnet: Networks.PUBLIC,
  public: Networks.PUBLIC,
  futurenet: Networks.FUTURENET,
}

/**
 * Resolves a `--network` value to a Stellar network passphrase.
 *
 * `testnet`, `mainnet` (or `public`) and `futurenet` map to the
 * `@stellar/stellar-sdk` `Networks.*` passphrases, matched case-insensitively
 * and ignoring surrounding whitespace. Any other value, including a full
 * custom passphrase, is returned unchanged.
 */
export function resolveNetwork(value: string): string {
  return NETWORK_ALIASES[value.trim().toLowerCase()] ?? value
}
