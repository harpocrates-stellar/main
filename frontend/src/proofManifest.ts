import type { IdentityTier } from './stellarTypes'

const MANIFEST_VERSION = 1

export type ProofManifest = {
  protocol: 'harpocrates'
  version: number
  proofId: string
  tier: IdentityTier
  network: string
  contractId: string
  transactionRef: string
  videoHash: string
  metadataHash: string
  sourceHash: string
  timestamp: string
}

type ProofManifestInput = {
  proofId: string
  tier: IdentityTier
  network: string
  contractId: string
  transactionRef: string
  videoHash: string
  metadataHash: string
  sourceHash: string
  timestamp: string
}

/**
 * Create a portable, versioned proof manifest from the supplied input.
 *
 * The output is a plain JSON-safe object with deterministic key ordering
 * (alphabetical) so that `JSON.stringify` always produces the same byte
 * sequence for identical inputs.  No seeds, private witness data, or other
 * secret material is included.
 */
export function createProofManifest(input: ProofManifestInput): ProofManifest {
  const manifest: ProofManifest = {
    protocol: 'harpocrates',
    version: MANIFEST_VERSION,
    proofId: input.proofId,
    tier: input.tier,
    network: input.network,
    contractId: input.contractId,
    transactionRef: input.transactionRef,
    videoHash: input.videoHash,
    metadataHash: input.metadataHash,
    sourceHash: input.sourceHash,
    timestamp: input.timestamp,
  }

  return manifest
}

/**
 * Serialise a proof manifest to a deterministic JSON string.
 *
 * Keys are sorted alphabetically so the output is stable across runs and
 * engines, which is critical for downstream hash verification.
 */
export function serializeManifest(manifest: ProofManifest): string {
  return JSON.stringify(manifest, Object.keys(manifest).sort())
}
