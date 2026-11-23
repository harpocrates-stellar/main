/**
 * receiptComparison — pure comparison and privacy-safe sharing logic for two
 * Harpocrates verification receipts.
 *
 * Trust & privacy boundary:
 * - Parses signed or unsigned verification receipts with fail-closed validation.
 * - Rejects inputs containing private evidence metadata or secret-looking keys
 *   (media, fileName, stego, witness, nullifier, seed, secret, credential, etc.).
 * - Highlights changed trust and chain observations with exact ISO-8601 UTC
 *   timestamps and elapsed delta.
 * - Generates privacy-safe comparison URLs (`#verify?compare=<base64url>`) that
 *   contain ONLY public registry identifiers and observation metadata, never
 *   private evidence metadata or raw signatures.
 */

import type { IdentityTier } from '../stellarTypes'
import {
  decodeReceiptFromQr,
  type VerificationReceiptPayload,
} from '../verificationReceipt'

export const COMPARISON_LINK_PROTOCOL = 'harpocrates-receipt-comparison' as const
export const COMPARISON_LINK_VERSION = 1 as const
export const MAX_RECEIPT_INPUT_BYTES = 8_192
export const MAX_COMPARISON_PAYLOAD_BYTES = 3_072
export const MAX_COMPARISON_URL_BYTES = 4_096

const PRIVATE_KEY_PATTERN =
  /(seed|secret|witness|nullifier|credential|private|proofBytes|publicInputs|fileName|file_name|media|stego|rawEvidence|raw_evidence|captureLocation|gps|exif|deviceSerial)/i

export type ReceiptParseErrorCode =
  | 'EMPTY_INPUT'
  | 'OVERSIZED_INPUT'
  | 'MALFORMED_RECEIPT'
  | 'UNSUPPORTED_PROTOCOL'
  | 'INVALID_DIGEST'
  | 'INVALID_TIMESTAMP'
  | 'INVALID_FIELD'
  | 'PRIVATE_METADATA_FORBIDDEN'

export type ReceiptParseResult =
  | { ok: true; receipt: VerificationReceiptPayload }
  | { ok: false; code: ReceiptParseErrorCode; message: string }

export type ObservationCategory = 'trust' | 'chain' | 'artifact'

export type ObservationSeverity = 'unchanged' | 'info' | 'warning' | 'critical'

export type ComparedObservation = {
  key: string
  label: string
  category: ObservationCategory
  leftValue: string
  rightValue: string
  changed: boolean
  severity: ObservationSeverity
  detail?: string
}

export type ReceiptComparisonResult = {
  left: VerificationReceiptPayload
  right: VerificationReceiptPayload
  sameArtifact: boolean
  leftTimestamp: string
  rightTimestamp: string
  timeDeltaMs: number
  timeDeltaLabel: string
  chronology: 'later' | 'earlier' | 'same'
  trustChanged: boolean
  chainChanged: boolean
  artifactChanged: boolean
  changedCount: number
  observations: ComparedObservation[]
}

export type PublicComparisonReceipt = {
  result: 'verified' | 'unverified'
  verifiedAt: string
  proofId: string
  videoHash: string
  metadataHash: string
  tier: IdentityTier
  networkPassphrase: string
  contractId: string
  ledgerSequence: number | null
  transactionHash: string | null
  circuitVersion: string
  verifierVersion: string
  signerKeyId: string
}

export type ReceiptComparisonSharePayload = {
  protocol: typeof COMPARISON_LINK_PROTOCOL
  version: typeof COMPARISON_LINK_VERSION
  left: PublicComparisonReceipt
  right: PublicComparisonReceipt
}

export type ComparisonShareErrorCode =
  | 'MALFORMED_INPUT'
  | 'MALFORMED_URL'
  | 'MISSING_PAYLOAD'
  | 'OVERSIZED_PAYLOAD'
  | 'OVERSIZED_URL'
  | 'UNSUPPORTED_PROTOCOL'
  | 'PRIVATE_METADATA_FORBIDDEN'
  | 'INVALID_FIELD'

export type ComparisonShareCreateResult =
  | { ok: true; url: string; payload: ReceiptComparisonSharePayload; encoded: string }
  | { ok: false; code: ComparisonShareErrorCode; message: string }

export type ComparisonShareParseResult =
  | { ok: true; left: VerificationReceiptPayload; right: VerificationReceiptPayload }
  | { ok: false; code: ComparisonShareErrorCode; message: string }

const PARSE_MESSAGES: Record<ReceiptParseErrorCode, string> = {
  EMPTY_INPUT: 'Receipt input is empty.',
  OVERSIZED_INPUT: 'Receipt input exceeds the 8 KB size limit.',
  MALFORMED_RECEIPT: 'Receipt could not be parsed as valid JSON or a QR receipt payload.',
  UNSUPPORTED_PROTOCOL: 'Unsupported verification receipt protocol or version.',
  INVALID_DIGEST: 'Receipt digests (videoHash, proofId, metadataHash, transactionHash) must be 32-byte hex strings.',
  INVALID_TIMESTAMP: 'Receipt verifiedAt must be a valid ISO-8601 timestamp.',
  INVALID_FIELD: 'Receipt is missing a required public field or contains an invalid value.',
  PRIVATE_METADATA_FORBIDDEN: 'Receipt contains private evidence metadata or secret fields and was rejected.',
}

const SHARE_MESSAGES: Record<ComparisonShareErrorCode, string> = {
  MALFORMED_INPUT: 'Comparison share input is incomplete or malformed.',
  MALFORMED_URL: 'Comparison share URL could not be parsed.',
  MISSING_PAYLOAD: 'Comparison URL is missing a comparison payload.',
  OVERSIZED_PAYLOAD: 'Comparison payload exceeds the size limit.',
  OVERSIZED_URL: 'Comparison URL exceeds the size limit.',
  UNSUPPORTED_PROTOCOL: 'Unsupported comparison link protocol or version.',
  PRIVATE_METADATA_FORBIDDEN: 'Comparison link contains forbidden private metadata.',
  INVALID_FIELD: 'Comparison link contains an invalid public field.',
}

/**
 * Parse a verification receipt from raw JSON or a QR-encoded base64url string.
 * Strips the signature (if present) and validates all required public fields.
 * Rejects any object containing private evidence metadata keys.
 */
export function parseReceiptInput(raw: string): ReceiptParseResult {
  if (typeof raw !== 'string' || !raw.trim()) {
    return parseFail('EMPTY_INPUT')
  }
  const trimmed = raw.trim()
  if (utf8(trimmed).byteLength > MAX_RECEIPT_INPUT_BYTES) {
    return parseFail('OVERSIZED_INPUT')
  }

  let parsed: unknown
  if (trimmed.startsWith('{')) {
    try {
      parsed = JSON.parse(trimmed) as unknown
    } catch {
      return parseFail('MALFORMED_RECEIPT')
    }
  } else {
    try {
      parsed = decodeReceiptFromQr(trimmed) as unknown
    } catch {
      return parseFail('MALFORMED_RECEIPT')
    }
  }

  return validateReceiptObject(parsed)
}

/**
 * Validate an already-parsed receipt object into a normalized
 * `VerificationReceiptPayload`. Rejects private metadata keys fail-closed.
 */
export function validateReceiptObject(value: unknown): ReceiptParseResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return parseFail('MALFORMED_RECEIPT')
  }
  const record = value as Record<string, unknown>

  if (containsForbiddenPrivateKey(record)) {
    return parseFail('PRIVATE_METADATA_FORBIDDEN')
  }

  if (
    record.protocol !== 'harpocrates-verification-receipt' ||
    record.version !== 1
  ) {
    return parseFail('UNSUPPORTED_PROTOCOL')
  }

  if (record.result !== 'verified' && record.result !== 'unverified') {
    return parseFail('INVALID_FIELD')
  }

  const verifiedAt = normalizeIsoTimestamp(record.verifiedAt)
  if (!verifiedAt) {
    return parseFail('INVALID_TIMESTAMP')
  }

  const proofId = normalizeHex32(record.proofId)
  const videoHash = normalizeHex32(record.videoHash)
  const metadataHash = normalizeHex32(record.metadataHash)
  if (!proofId || !videoHash || !metadataHash) {
    return parseFail('INVALID_DIGEST')
  }

  if (!isTier(record.tier)) {
    return parseFail('INVALID_FIELD')
  }

  const networkPassphrase = trimRequired(record.networkPassphrase)
  const contractId = trimRequired(record.contractId)
  const circuitVersion = trimRequired(record.circuitVersion)
  const verifierVersion = trimRequired(record.verifierVersion)
  if (!networkPassphrase || !contractId || !circuitVersion || !verifierVersion) {
    return parseFail('INVALID_FIELD')
  }

  if (
    record.ledgerSequence !== null &&
    (typeof record.ledgerSequence !== 'number' || !Number.isInteger(record.ledgerSequence) || record.ledgerSequence < 0)
  ) {
    return parseFail('INVALID_FIELD')
  }

  let transactionHash: string | null = null
  if (record.transactionHash !== null && record.transactionHash !== undefined && record.transactionHash !== '') {
    const normalizedTx = normalizeHex32(record.transactionHash)
    if (!normalizedTx) return parseFail('INVALID_DIGEST')
    transactionHash = normalizedTx
  }

  const signer = record.signer
  if (!signer || typeof signer !== 'object' || Array.isArray(signer)) {
    return parseFail('INVALID_FIELD')
  }
  const signerRecord = signer as Record<string, unknown>
  const keyId = trimRequired(signerRecord.keyId)
  if (!keyId || signerRecord.algorithm !== 'ECDSA_P256_SHA256') {
    return parseFail('INVALID_FIELD')
  }

  return {
    ok: true,
    receipt: {
      protocol: 'harpocrates-verification-receipt',
      version: 1,
      result: record.result,
      verifiedAt,
      proofId,
      videoHash,
      metadataHash,
      tier: record.tier,
      networkPassphrase,
      contractId,
      ledgerSequence: record.ledgerSequence,
      transactionHash,
      circuitVersion,
      verifierVersion,
      signer: {
        keyId,
        algorithm: 'ECDSA_P256_SHA256',
      },
    },
  }
}

/**
 * Compare two validated verification receipts and highlight changed trust,
 * chain, and artifact observations with exact timestamps.
 */
export function compareVerificationReceipts(
  left: VerificationReceiptPayload,
  right: VerificationReceiptPayload,
): ReceiptComparisonResult {
  const leftMs = new Date(left.verifiedAt).getTime()
  const rightMs = new Date(right.verifiedAt).getTime()
  const timeDeltaMs = rightMs - leftMs
  const chronology: 'later' | 'earlier' | 'same' =
    timeDeltaMs > 0 ? 'later' : timeDeltaMs < 0 ? 'earlier' : 'same'

  const ledgerDeltaDetail =
    left.ledgerSequence !== null &&
    right.ledgerSequence !== null &&
    left.ledgerSequence !== right.ledgerSequence
      ? `Ledger delta: ${right.ledgerSequence - left.ledgerSequence > 0 ? '+' : ''}${right.ledgerSequence - left.ledgerSequence}`
      : undefined

  const observations: ComparedObservation[] = [
    // Trust observations
    buildObservation({
      key: 'result',
      label: 'Trust Decision',
      category: 'trust',
      leftValue: left.result,
      rightValue: right.result,
      changedSeverity: 'critical',
      detail:
        left.result !== right.result
          ? `Changed from ${left.result} (${left.verifiedAt}) to ${right.result} (${right.verifiedAt})`
          : undefined,
    }),
    buildObservation({
      key: 'tier',
      label: 'Identity Tier',
      category: 'trust',
      leftValue: left.tier,
      rightValue: right.tier,
      changedSeverity: 'warning',
    }),
    buildObservation({
      key: 'signer.keyId',
      label: 'Receipt Signer Key',
      category: 'trust',
      leftValue: left.signer.keyId,
      rightValue: right.signer.keyId,
      changedSeverity: 'warning',
    }),
    buildObservation({
      key: 'circuitVersion',
      label: 'Circuit Version',
      category: 'trust',
      leftValue: left.circuitVersion,
      rightValue: right.circuitVersion,
      changedSeverity: 'info',
    }),
    buildObservation({
      key: 'verifierVersion',
      label: 'Verifier Version',
      category: 'trust',
      leftValue: left.verifierVersion,
      rightValue: right.verifierVersion,
      changedSeverity: 'info',
    }),

    // Chain observations
    buildObservation({
      key: 'networkPassphrase',
      label: 'Network Passphrase',
      category: 'chain',
      leftValue: left.networkPassphrase,
      rightValue: right.networkPassphrase,
      changedSeverity: 'critical',
    }),
    buildObservation({
      key: 'contractId',
      label: 'Registry Contract ID',
      category: 'chain',
      leftValue: left.contractId,
      rightValue: right.contractId,
      changedSeverity: 'critical',
    }),
    buildObservation({
      key: 'ledgerSequence',
      label: 'Ledger Sequence',
      category: 'chain',
      leftValue: left.ledgerSequence === null ? 'None' : String(left.ledgerSequence),
      rightValue: right.ledgerSequence === null ? 'None' : String(right.ledgerSequence),
      changedSeverity: 'info',
      detail: ledgerDeltaDetail,
    }),
    buildObservation({
      key: 'transactionHash',
      label: 'Transaction Hash',
      category: 'chain',
      leftValue: left.transactionHash ?? 'None',
      rightValue: right.transactionHash ?? 'None',
      changedSeverity: 'info',
    }),

    // Artifact identifiers
    buildObservation({
      key: 'videoHash',
      label: 'Video Hash',
      category: 'artifact',
      leftValue: left.videoHash,
      rightValue: right.videoHash,
      changedSeverity: 'critical',
    }),
    buildObservation({
      key: 'proofId',
      label: 'Proof ID',
      category: 'artifact',
      leftValue: left.proofId,
      rightValue: right.proofId,
      changedSeverity: 'warning',
    }),
    buildObservation({
      key: 'metadataHash',
      label: 'Metadata Hash',
      category: 'artifact',
      leftValue: left.metadataHash,
      rightValue: right.metadataHash,
      changedSeverity: 'warning',
    }),
  ]

  const trustChanged = observations.some((o) => o.category === 'trust' && o.changed)
  const chainChanged = observations.some((o) => o.category === 'chain' && o.changed)
  const artifactChanged = observations.some((o) => o.category === 'artifact' && o.changed)
  const changedCount = observations.filter((o) => o.changed).length

  return {
    left,
    right,
    sameArtifact: left.videoHash === right.videoHash,
    leftTimestamp: left.verifiedAt,
    rightTimestamp: right.verifiedAt,
    timeDeltaMs,
    timeDeltaLabel: formatTimeDelta(timeDeltaMs),
    chronology,
    trustChanged,
    chainChanged,
    artifactChanged,
    changedCount,
    observations,
  }
}

/**
 * Create a privacy-safe hash-routed comparison URL containing only public
 * receipt fields (no media, file names, witnesses, nullifiers, or signatures).
 */
export function createReceiptComparisonShareUrl(
  left: VerificationReceiptPayload,
  right: VerificationReceiptPayload,
  options?: { baseUrl?: string },
): ComparisonShareCreateResult {
  const leftValid = validateReceiptObject(left)
  const rightValid = validateReceiptObject(right)
  if (!leftValid.ok || !rightValid.ok) {
    return shareFail('MALFORMED_INPUT')
  }

  const payload: ReceiptComparisonSharePayload = {
    protocol: COMPARISON_LINK_PROTOCOL,
    version: COMPARISON_LINK_VERSION,
    left: toPublicComparisonReceipt(leftValid.receipt),
    right: toPublicComparisonReceipt(rightValid.receipt),
  }

  const canonical = canonicalize(payload)
  if (utf8(canonical).byteLength > MAX_COMPARISON_PAYLOAD_BYTES) {
    return shareFail('OVERSIZED_PAYLOAD')
  }

  const encoded = base64UrlEncode(utf8(canonical))
  if (utf8(encoded).byteLength > MAX_COMPARISON_PAYLOAD_BYTES) {
    return shareFail('OVERSIZED_PAYLOAD')
  }

  const base = resolveBaseUrl(options?.baseUrl)
  if (!base) {
    return shareFail('MALFORMED_URL')
  }

  const url = `${base}#verify?compare=${encoded}`
  if (utf8(url).byteLength > MAX_COMPARISON_URL_BYTES) {
    return shareFail('OVERSIZED_URL')
  }

  return { ok: true, url, payload, encoded }
}

/**
 * Parse a `#verify?compare=<base64url>` URL or hash fragment back into two
 * validated `VerificationReceiptPayload` objects.
 */
export function parseReceiptComparisonShareUrl(urlOrHash: string): ComparisonShareParseResult {
  if (typeof urlOrHash !== 'string' || !urlOrHash.trim()) {
    return shareFail('MALFORMED_URL')
  }
  if (utf8(urlOrHash).byteLength > MAX_COMPARISON_URL_BYTES) {
    return shareFail('OVERSIZED_URL')
  }

  let hash = urlOrHash.trim()
  try {
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(hash) || hash.startsWith('/') || hash.startsWith('?')) {
      const asUrl = hash.includes('://')
        ? new URL(hash)
        : new URL(hash, 'https://harpocrates.local/')
      hash = asUrl.hash || hash
    }
  } catch {
    return shareFail('MALFORMED_URL')
  }

  if (hash.startsWith('#')) hash = hash.slice(1)
  const qIndex = hash.indexOf('?')
  const query = qIndex >= 0 ? hash.slice(qIndex + 1) : ''
  const encoded = (() => {
    try {
      return new URLSearchParams(query).get('compare')
    } catch {
      return null
    }
  })()

  if (!encoded) return shareFail('MISSING_PAYLOAD')
  if (utf8(encoded).byteLength > MAX_COMPARISON_PAYLOAD_BYTES) {
    return shareFail('OVERSIZED_PAYLOAD')
  }

  let parsed: unknown
  try {
    const json = new TextDecoder().decode(base64UrlDecode(encoded))
    if (utf8(json).byteLength > MAX_COMPARISON_PAYLOAD_BYTES) {
      return shareFail('OVERSIZED_PAYLOAD')
    }
    parsed = JSON.parse(json) as unknown
  } catch {
    return shareFail('MALFORMED_INPUT')
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return shareFail('MALFORMED_INPUT')
  }
  const record = parsed as Record<string, unknown>

  if (containsForbiddenPrivateKey(record)) {
    return shareFail('PRIVATE_METADATA_FORBIDDEN')
  }

  if (
    record.protocol !== COMPARISON_LINK_PROTOCOL ||
    record.version !== COMPARISON_LINK_VERSION
  ) {
    return shareFail('UNSUPPORTED_PROTOCOL')
  }

  const left = fromPublicComparisonReceipt(record.left)
  const right = fromPublicComparisonReceipt(record.right)
  if (!left.ok || !right.ok) {
    return shareFail('INVALID_FIELD')
  }

  return { ok: true, left: left.receipt, right: right.receipt }
}

/** Format an elapsed millisecond delta into a human-readable signed string. */
export function formatTimeDelta(deltaMs: number): string {
  if (deltaMs === 0) return '0s (same timestamp)'
  const sign = deltaMs > 0 ? '+' : '-'
  const absSeconds = Math.floor(Math.abs(deltaMs) / 1000)
  const days = Math.floor(absSeconds / 86_400)
  const hours = Math.floor((absSeconds % 86_400) / 3_600)
  const minutes = Math.floor((absSeconds % 3_600) / 60)
  const seconds = absSeconds % 60

  const parts: string[] = []
  if (days > 0) parts.push(`${days}d`)
  if (hours > 0) parts.push(`${hours}h`)
  if (minutes > 0) parts.push(`${minutes}m`)
  if (seconds > 0 || parts.length === 0) parts.push(`${seconds}s`)
  return `${sign}${parts.join(' ')}`
}

function buildObservation(input: {
  key: string
  label: string
  category: ObservationCategory
  leftValue: string
  rightValue: string
  changedSeverity: Exclude<ObservationSeverity, 'unchanged'>
  detail?: string
}): ComparedObservation {
  const changed = input.leftValue !== input.rightValue
  return {
    key: input.key,
    label: input.label,
    category: input.category,
    leftValue: input.leftValue,
    rightValue: input.rightValue,
    changed,
    severity: changed ? input.changedSeverity : 'unchanged',
    detail: changed ? input.detail : undefined,
  }
}

function toPublicComparisonReceipt(receipt: VerificationReceiptPayload): PublicComparisonReceipt {
  return {
    result: receipt.result,
    verifiedAt: receipt.verifiedAt,
    proofId: receipt.proofId,
    videoHash: receipt.videoHash,
    metadataHash: receipt.metadataHash,
    tier: receipt.tier,
    networkPassphrase: receipt.networkPassphrase,
    contractId: receipt.contractId,
    ledgerSequence: receipt.ledgerSequence,
    transactionHash: receipt.transactionHash,
    circuitVersion: receipt.circuitVersion,
    verifierVersion: receipt.verifierVersion,
    signerKeyId: receipt.signer.keyId,
  }
}

function fromPublicComparisonReceipt(value: unknown): ReceiptParseResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return parseFail('MALFORMED_RECEIPT')
  }
  const r = value as Record<string, unknown>
  if (containsForbiddenPrivateKey(r)) {
    return parseFail('PRIVATE_METADATA_FORBIDDEN')
  }
  return validateReceiptObject({
    protocol: 'harpocrates-verification-receipt',
    version: 1,
    result: r.result,
    verifiedAt: r.verifiedAt,
    proofId: r.proofId,
    videoHash: r.videoHash,
    metadataHash: r.metadataHash,
    tier: r.tier,
    networkPassphrase: r.networkPassphrase,
    contractId: r.contractId,
    ledgerSequence: r.ledgerSequence,
    transactionHash: r.transactionHash,
    circuitVersion: r.circuitVersion,
    verifierVersion: r.verifierVersion,
    signer: {
      keyId: r.signerKeyId,
      algorithm: 'ECDSA_P256_SHA256',
    },
  })
}

function containsForbiddenPrivateKey(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false
  if (Array.isArray(value)) return value.some(containsForbiddenPrivateKey)
  const record = value as Record<string, unknown>
  for (const key of Object.keys(record)) {
    if (PRIVATE_KEY_PATTERN.test(key)) return true
    if (containsForbiddenPrivateKey(record[key])) return true
  }
  return false
}

function parseFail(code: ReceiptParseErrorCode): { ok: false; code: ReceiptParseErrorCode; message: string } {
  return { ok: false, code, message: PARSE_MESSAGES[code] }
}

function shareFail(code: ComparisonShareErrorCode): { ok: false; code: ComparisonShareErrorCode; message: string } {
  return { ok: false, code, message: SHARE_MESSAGES[code] }
}

function normalizeIsoTimestamp(value: unknown): string | null {
  if (typeof value !== 'string' || !value.trim()) return null
  const date = new Date(value.trim())
  if (Number.isNaN(date.getTime())) return null
  return date.toISOString()
}

function normalizeHex32(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(trimmed)) return null
  return trimmed
}

function trimRequired(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function isTier(value: unknown): value is IdentityTier {
  return value === 'silent' || value === 'source' || value === 'seal'
}

function resolveBaseUrl(override?: string): string | null {
  if (override !== undefined) {
    const trimmed = override.trim().replace(/\/$/, '')
    if (!trimmed) return null
    try {
      const u = new URL(trimmed)
      return `${u.origin}${u.pathname === '/' ? '' : u.pathname.replace(/\/$/, '')}`
    } catch {
      return null
    }
  }
  if (typeof window !== 'undefined' && window.location) {
    const { origin, pathname } = window.location
    const path = pathname === '/' ? '' : pathname.replace(/\/$/, '')
    return `${origin}${path}`
  }
  return null
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  const record = value as Record<string, unknown>
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`)
    .join(',')}}`
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

function base64UrlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url data')
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4)
  const binary = atob(padded)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}
