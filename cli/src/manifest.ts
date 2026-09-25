import type { IdentityTier } from './metadata.js'
import { ALLOWED_TIERS } from './metadata.js'

/**
 * Portable, versioned proof manifest matching the frontend `ProofManifest` type.
 *
 * Keys are alphabetically ordered so `JSON.stringify` is deterministic across
 * engines – critical for downstream hash verification.
 */
export type ProofManifest = {
  contractId: string
  metadataHash: string
  network: string
  proofId: string
  protocol: 'harpocrates'
  sourceHash: string
  tier: IdentityTier
  timestamp: string
  transactionRef: string
  version: number
  videoHash: string
  verifierScope?: string
  epoch?: number
  scopeName?: string
  selectiveDisclosure?: {
    schemaHash: string
    publicInputs: string
    predicateCommitment: string
    circuitVersion: number
  }
}

const MANIFEST_VERSION = 2

export type ManifestInput = {
  proofId: string
  tier: IdentityTier
  network: string
  contractId: string
  transactionRef: string
  videoHash: string
  metadataHash: string
  sourceHash: string
  timestamp: string
  verifierScope?: string
  epoch?: number
  scopeName?: string
  selectiveDisclosure?: ProofManifest['selectiveDisclosure']
}

/**
 * Create a portable, versioned proof manifest from the supplied input.
 *
 * The output is a plain JSON-safe object with deterministic key ordering
 * (alphabetical) so that `JSON.stringify` always produces the same byte
 * sequence for identical inputs.  No seeds, private witness data, or other
 * secret material is included.
 */
export function createProofManifest(input: ManifestInput): ProofManifest {
  const manifest: ProofManifest = {
    contractId: input.contractId,
    metadataHash: input.metadataHash,
    network: input.network,
    proofId: input.proofId,
    protocol: 'harpocrates',
    sourceHash: input.sourceHash,
    tier: input.tier,
    timestamp: input.timestamp,
    transactionRef: input.transactionRef,
    version: MANIFEST_VERSION,
    videoHash: input.videoHash,
    verifierScope: input.verifierScope ?? '0',
    epoch: input.epoch ?? 0,
  }
  if (input.scopeName) manifest.scopeName = input.scopeName
  if (input.selectiveDisclosure) manifest.selectiveDisclosure = input.selectiveDisclosure
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

/**
 * Parse and validate a serialised proof manifest.
 *
 * Returns the typed manifest on success or throws on invalid input.
 */
export function parseManifest(json: string): ProofManifest {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new Error('manifest is not valid JSON')
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('manifest must be a JSON object')
  }

  const m = parsed as Record<string, unknown>

  const fields = new Set([
    'contractId', 'metadataHash', 'network', 'proofId', 'protocol', 'sourceHash',
    'tier', 'timestamp', 'transactionRef', 'version', 'videoHash',
    'verifierScope', 'epoch', 'scopeName', 'selectiveDisclosure',
  ])
  if (Object.keys(m).some((key) => !fields.has(key))) {
    throw new Error('manifest contains unsupported fields')
  }

  if (m.protocol !== 'harpocrates') {
    throw new Error('manifest protocol must be "harpocrates"')
  }
  if (m.version !== 1 && m.version !== MANIFEST_VERSION) {
    throw new Error('unsupported manifest version')
  }

  // Reuse metadata validation for overlapping fields (tier, hex32 format).
  const tier = m.tier
  if (typeof tier !== 'string' || !ALLOWED_TIERS.has(tier)) {
    throw new Error(`manifest tier must be one of: ${[...ALLOWED_TIERS].join(', ')}`)
  }

  for (const field of ['proofId', 'network', 'contractId', 'transactionRef', 'videoHash', 'metadataHash', 'sourceHash', 'timestamp']) {
    if (typeof m[field] !== 'string' || !m[field]) {
      throw new Error(`manifest.${field} must be a non-empty string`)
    }
  }

  for (const field of ['proofId', 'videoHash', 'metadataHash', 'sourceHash', 'transactionRef']) {
    if (!/^[0-9a-fA-F]{64}$/.test(m[field] as string)) {
      throw new Error(`manifest.${field} must be a 32-byte hex string`)
    }
  }
  if (Number.isNaN(Date.parse(m.timestamp as string))) {
    throw new Error('manifest.timestamp must be a valid date')
  }
  if (m.version === 2 &&
      (typeof m.verifierScope !== 'string' || !/^(0|[1-9][0-9]*)$/.test(m.verifierScope) ||
       !Number.isSafeInteger(m.epoch) || (m.epoch as number) < 0)) {
    throw new Error('manifest scope or epoch is invalid')
  }
  if (m.scopeName !== undefined && (typeof m.scopeName !== 'string' || m.scopeName.length > 128)) {
    throw new Error('manifest scopeName is invalid')
  }
  if (m.selectiveDisclosure !== undefined) {
    const disclosure = m.selectiveDisclosure
    if (!disclosure || typeof disclosure !== 'object' || Array.isArray(disclosure) ||
        Object.keys(disclosure).some((key) => !['schemaHash', 'publicInputs', 'predicateCommitment', 'circuitVersion'].includes(key))) {
      throw new Error('manifest selectiveDisclosure is invalid')
    }
    const proof = disclosure as Record<string, unknown>
    if (typeof proof.schemaHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(proof.schemaHash) ||
        typeof proof.predicateCommitment !== 'string' || !/^[0-9a-fA-F]{64}$/.test(proof.predicateCommitment) ||
        typeof proof.publicInputs !== 'string' || !/^[0-9a-fA-F]*$/.test(proof.publicInputs) ||
        !Number.isSafeInteger(proof.circuitVersion)) {
      throw new Error('manifest selectiveDisclosure is invalid')
    }
  }

  return m as ProofManifest
}
