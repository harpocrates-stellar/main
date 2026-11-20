import type { VerificationResult } from './receipt.js'
import type { ProofManifest } from './manifest.js'
import type { ChainProofRecord, TransactionVerification } from './stellar-lookup.js'

/**
 * Compute the overall verification result from a chain record's status
 * and the transaction state.
 */
export function computeResult(
  chainRecord: { status: number } | null,
  txStatus: string,
): VerificationResult {
  if (txStatus === 'missing') return 'not_found'
  if (txStatus === 'failed') return 'failed'
  if (txStatus === 'pending') return 'pending'

  if (!chainRecord) return 'not_found'

  // Registry ProofRecord status values: 1 = registered, 2 = revoked, 3 = expired.
  switch (chainRecord.status) {
    case 1:
      return 'valid'
    case 2:
      return 'revoked'
    case 3:
      return 'expired'
    default:
      return 'error'
  }
}

/** Fail closed when the public manifest, transaction and registry disagree. */
export function classifyVerification(
  manifest: ProofManifest,
  transaction: TransactionVerification,
  chainRecord: ChainProofRecord | null,
  nowSeconds = Math.floor(Date.now() / 1000),
): VerificationResult {
  if (transaction.contractMatch === false) return 'contract_mismatch'
  const result = computeResult(chainRecord, transaction.status)
  if (!chainRecord) return result
  if (chainRecord.videoHash.toLowerCase() !== manifest.videoHash.toLowerCase() ||
      chainRecord.metadataHash.toLowerCase() !== manifest.metadataHash.toLowerCase() ||
      chainRecord.tier !== { silent: 1, source: 2, seal: 3 }[manifest.tier]) return 'error'
  if (result === 'valid' && chainRecord.expiresAt &&
      BigInt(chainRecord.expiresAt) > 0n &&
      BigInt(chainRecord.expiresAt) < BigInt(nowSeconds)) return 'expired'
  return result
}

/**
 * Known Stellar network passphrases mapped to human-readable names.
 */
const KNOWN_PASSPHRASES: Record<string, string> = {
  'Public Global Stellar Network ; September 2015': 'Mainnet',
  'Test SDF Network ; September 2015': 'Testnet',
  'Test SDF Future Network ; October 2022': 'Futurenet',
  'Local Sandbox Stellar Network ; September 2022': 'Sandbox',
  'Standalone Network ; February 2017': 'Standalone',
}

/**
 * Return a human-readable name for a network passphrase.
 */
export function networkName(passphrase: string): string {
  return KNOWN_PASSPHRASES[passphrase] ?? passphrase
}
