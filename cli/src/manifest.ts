import { createHash } from 'node:crypto'
import type { IdentityTier } from './metadata.js'
import { ALLOWED_TIERS } from './metadata.js'

export type ManifestExtensionValue =
  | string
  | number
  | boolean
  | null
  | ManifestExtensionValue[]
  | { [key: string]: ManifestExtensionValue }

export type ManifestExtensions = Record<string, ManifestExtensionValue>

export type ParseManifestOptions = {
  /** Extension identifiers whose required/critical semantics this caller understands. */
  supportedExtensions?: ReadonlySet<string>
}

export const MAX_MANIFEST_EXTENSIONS = 32
export const MAX_EXTENSION_DEPTH = 8

const EXTENSION_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$/
const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype'])
const FORBIDDEN_SENSITIVE_EXTENSION_KEYS = new Set([
  'authorization',
  'cookie',
  'credential',
  'credentialsecret',
  'nullifier',
  'nullifiersecret',
  'password',
  'private',
  'privatekey',
  'proof',
  'publicinputs',
  'rawbytes',
  'secret',
  'seed',
  'signcert',
  'token',
  'witness',
])

/**
 * Portable, versioned proof manifest matching the frontend `ProofManifest` type.
 *
 * Keys are alphabetically ordered so canonical serialization is deterministic
 * across engines – critical for downstream hash verification.
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
  extensions?: ManifestExtensions
  criticalExtensions?: string[]
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
  extensions?: ManifestExtensions
  criticalExtensions?: string[]
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
  if (input.extensions && Object.keys(input.extensions).length > 0) {
    manifest.extensions = validateAndCanonicalizeExtensions(input.extensions, input.criticalExtensions)
  }
  if (input.criticalExtensions && input.criticalExtensions.length > 0) {
    manifest.criticalExtensions = [...new Set(input.criticalExtensions)].sort()
  }
  return manifest
}

function isSensitiveExtensionKey(key: string): boolean {
  const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase()
  if (FORBIDDEN_SENSITIVE_EXTENSION_KEYS.has(normalized)) return true
  for (const token of ['secret', 'witness', 'private', 'credential', 'nullifier', 'seed']) {
    if (normalized.includes(token)) return true
  }
  return false
}

function canonicalizeExtensionValue(value: unknown, depth: number): ManifestExtensionValue {
  if (depth > MAX_EXTENSION_DEPTH) {
    throw new Error('manifest extension nesting exceeds maximum depth')
  }
  if (value === null) return null
  if (typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('manifest extension contains non-finite number')
    }
    return value
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeExtensionValue(item, depth + 1))
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const out: Record<string, ManifestExtensionValue> = {}
    for (const key of Object.keys(obj).sort()) {
      if (FORBIDDEN_OBJECT_KEYS.has(key)) {
        throw new Error('manifest extension contains prohibited object key')
      }
      if (isSensitiveExtensionKey(key)) {
        throw new Error('manifest extension contains prohibited sensitive field')
      }
      if (obj[key] !== undefined) {
        out[key] = canonicalizeExtensionValue(obj[key], depth + 1)
      }
    }
    return out
  }
  throw new Error('manifest extension contains unsupported value type')
}

function validateAndCanonicalizeExtensions(
  rawExtensions: unknown,
  rawCritical: unknown,
  supportedExtensions: ReadonlySet<string> = new Set(),
): ManifestExtensions {
  if (!rawExtensions || typeof rawExtensions !== 'object' || Array.isArray(rawExtensions)) {
    throw new Error('manifest extensions must be a JSON object')
  }
  const entries = Object.entries(rawExtensions as Record<string, unknown>)
  if (entries.length > MAX_MANIFEST_EXTENSIONS) {
    throw new Error(`manifest extensions exceed maximum count (${MAX_MANIFEST_EXTENSIONS})`)
  }

  const criticalSet = new Set<string>()
  if (rawCritical !== undefined) {
    if (!Array.isArray(rawCritical) || rawCritical.some((k) => typeof k !== 'string' || !EXTENSION_NAME_RE.test(k))) {
      throw new Error('manifest criticalExtensions must be an array of valid extension names')
    }
    for (const name of rawCritical as string[]) {
      if (!supportedExtensions.has(name)) {
        throw new Error(`unsupported required manifest extension: ${name}`)
      }
      criticalSet.add(name)
    }
  }

  const normalized: ManifestExtensions = {}
  for (const [name, rawVal] of entries.sort(([a], [b]) => a.localeCompare(b))) {
    if (FORBIDDEN_OBJECT_KEYS.has(name) || !EXTENSION_NAME_RE.test(name)) {
      throw new Error(`manifest extension name "${name}" is invalid`)
    }
    if (isSensitiveExtensionKey(name)) {
      throw new Error('manifest extension contains prohibited sensitive field')
    }
    if (rawVal !== null && typeof rawVal === 'object' && !Array.isArray(rawVal)) {
      const extObj = rawVal as Record<string, unknown>
      if (extObj.required !== undefined && typeof extObj.required !== 'boolean') {
        throw new Error(`manifest extension "${name}".required must be a boolean`)
      }
      if (extObj.critical !== undefined && typeof extObj.critical !== 'boolean') {
        throw new Error(`manifest extension "${name}".critical must be a boolean`)
      }
      if ((extObj.required === true || extObj.critical === true) && !supportedExtensions.has(name)) {
        throw new Error(`unsupported required manifest extension: ${name}`)
      }
    }
    normalized[name] = canonicalizeExtensionValue(rawVal, 1)
  }

  for (const reqName of criticalSet) {
    if (!Object.prototype.hasOwnProperty.call(normalized, reqName)) {
      throw new Error(`manifest criticalExtensions references missing extension: ${reqName}`)
    }
  }

  return normalized
}

function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalizeJson(item)).join(',') + ']'
  }
  const obj = value as Record<string, unknown>
  const parts: string[] = []
  for (const key of Object.keys(obj).sort()) {
    if (obj[key] !== undefined) {
      parts.push(JSON.stringify(key) + ':' + canonicalizeJson(obj[key]))
    }
  }
  return '{' + parts.join(',') + '}'
}

/**
 * Serialise a proof manifest to a deterministic JSON string.
 *
 * Keys are sorted alphabetically recursively so nested objects (including
 * `selectiveDisclosure` and optional `extensions`) remain intact and stable
 * across runs and engines.
 */
export function serializeManifest(manifest: ProofManifest): string {
  return canonicalizeJson(manifest)
}

/**
 * Compute the canonical SHA-256 digest of a manifest's critical statement
 * fields, excluding non-critical optional `extensions`. Adding or round-tripping
 * compatible optional extensions never changes this critical statement identity.
 */
export function manifestStatementHash(manifest: ProofManifest): string {
  const statement: Record<string, unknown> = {}
  for (const [key, val] of Object.entries(manifest)) {
    if (key === 'extensions' || key === 'criticalExtensions' || val === undefined) continue
    statement[key] = val
  }
  return createHash('sha256').update(canonicalizeJson(statement)).digest('hex')
}

/**
 * Normalize a parsed or raw proof manifest into canonical form: hex digests are
 * lowercased, critical statement fields are preserved verbatim, unknown
 * optional extensions are round-tripped in canonical key order, and unsupported
 * required extensions are rejected fail-closed.
 */
export function normalizeManifest(
  input: ProofManifest | string,
  options: ParseManifestOptions = {},
): ProofManifest {
  const parsed = typeof input === 'string' ? parseManifest(input, options) : parseManifest(serializeManifest(input), options)
  const normalized: ProofManifest = {
    contractId: parsed.contractId,
    metadataHash: parsed.metadataHash.toLowerCase(),
    network: parsed.network,
    proofId: parsed.proofId.toLowerCase(),
    protocol: 'harpocrates',
    sourceHash: parsed.sourceHash.toLowerCase(),
    tier: parsed.tier,
    timestamp: parsed.timestamp,
    transactionRef: parsed.transactionRef.toLowerCase(),
    version: parsed.version,
    videoHash: parsed.videoHash.toLowerCase(),
  }
  if (parsed.verifierScope !== undefined) normalized.verifierScope = parsed.verifierScope
  if (parsed.epoch !== undefined) normalized.epoch = parsed.epoch
  if (parsed.scopeName !== undefined) normalized.scopeName = parsed.scopeName
  if (parsed.selectiveDisclosure !== undefined) {
    normalized.selectiveDisclosure = {
      schemaHash: parsed.selectiveDisclosure.schemaHash.toLowerCase(),
      publicInputs: parsed.selectiveDisclosure.publicInputs.toLowerCase(),
      predicateCommitment: parsed.selectiveDisclosure.predicateCommitment.toLowerCase(),
      circuitVersion: parsed.selectiveDisclosure.circuitVersion,
    }
  }
  if (parsed.extensions && Object.keys(parsed.extensions).length > 0) {
    normalized.extensions = parsed.extensions
  }
  if (parsed.criticalExtensions && parsed.criticalExtensions.length > 0) {
    normalized.criticalExtensions = [...new Set(parsed.criticalExtensions)].sort()
  }
  return normalized
}

/**
 * Parse and validate a serialised proof manifest.
 *
 * Returns the typed manifest on success or throws on invalid input.
 */
export function parseManifest(json: string, options: ParseManifestOptions = {}): ProofManifest {
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
    'extensions', 'criticalExtensions',
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

  const out: Record<string, unknown> = { ...m }
  if (m.extensions !== undefined || m.criticalExtensions !== undefined) {
    const canonicalExtensions = validateAndCanonicalizeExtensions(
      m.extensions ?? {},
      m.criticalExtensions,
      options.supportedExtensions,
    )
    if (Object.keys(canonicalExtensions).length > 0) {
      out.extensions = canonicalExtensions
    } else {
      delete out.extensions
    }
    if (Array.isArray(m.criticalExtensions) && m.criticalExtensions.length > 0) {
      out.criticalExtensions = [...new Set(m.criticalExtensions as string[])].sort()
    } else {
      delete out.criticalExtensions
    }
  }

  return out as ProofManifest
}
