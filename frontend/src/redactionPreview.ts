/**
 * Privacy-safe redaction preview for Evidence Studio.
 *
 * Builds a public-boundary view of local evidence so operators can see what
 * would leave the trust boundary — without ever surfacing seeds, witness
 * proofs, private keys, or raw media. Pure / deterministic; safe to unit test.
 */

import type { ProofPackage } from './types'
import { shortHash } from './utils'

/** Preview schema version. Bump on incompatible field-shape changes. */
export const REDACTION_PREVIEW_VERSION = 1 as const

/** Stable placeholder shown for withheld material. Never replace with real values. */
export const REDACTED_PLACEHOLDER = '[REDACTED]' as const

/** Hard cap on serialized input size (bytes) to bound hostile / oversized packages. */
export const MAX_PREVIEW_INPUT_BYTES = 64 * 1024

export type RedactionReason =
  | 'secret'
  | 'witness'
  | 'media'
  | 'private_key'
  | 'not_disclosed'

export type RedactionErrorCode =
  | 'MISSING_EVIDENCE'
  | 'MALFORMED_EVIDENCE'
  | 'OVERSIZED_PAYLOAD'
  | 'UNSUPPORTED_TIER'

export type RedactionField = {
  key: string
  label: string
  /** Display value only — never full secrets. Truncated hashes or REDACTED. */
  value: string
  disclosed: boolean
  reason?: RedactionReason
}

export type RedactionPreviewOk = {
  ok: true
  version: typeof REDACTION_PREVIEW_VERSION
  fields: RedactionField[]
  disclosedCount: number
  redactedCount: number
  summary: string
}

export type RedactionPreviewErr = {
  ok: false
  code: RedactionErrorCode
  /** Stable, privacy-safe operator message — never embeds evidence values. */
  message: string
}

export type RedactionPreviewResult = RedactionPreviewOk | RedactionPreviewErr

/**
 * Optional local secrets that may sit beside a ProofPackage in Studio state.
 * These are always redacted and never appear in disclosed field values.
 */
export type RedactionPreviewSecrets = {
  credentialSeed?: string
  nullifierSeed?: string
  privateKey?: string
  mediaObjectUrl?: string
}

export type RedactionPreviewInput = {
  proof: ProofPackage | null | undefined
  secrets?: RedactionPreviewSecrets | null
}

const ERROR_MESSAGES: Record<RedactionErrorCode, string> = {
  MISSING_EVIDENCE: 'No evidence package is available to preview.',
  MALFORMED_EVIDENCE: 'Evidence package is malformed and cannot be previewed.',
  OVERSIZED_PAYLOAD: 'Evidence package exceeds the redaction preview size limit.',
  UNSUPPORTED_TIER: 'Evidence tier is not supported by the redaction preview.',
}

const SUPPORTED_TIERS = new Set(['source', 'seal', 'silent'])

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value != null && typeof value === 'object' && !Array.isArray(value)
}

function estimateBytes(value: unknown): number {
  try {
    return new TextEncoder().encode(JSON.stringify(value)).length
  } catch {
    return Number.POSITIVE_INFINITY
  }
}

function discloseHash(label: string, key: string, raw: string | undefined | null): RedactionField {
  if (!raw || typeof raw !== 'string') {
    return {
      key,
      label,
      value: 'Not generated',
      disclosed: true,
    }
  }
  return {
    key,
    label,
    value: shortHash(raw),
    disclosed: true,
  }
}

function redact(label: string, key: string, reason: RedactionReason): RedactionField {
  return {
    key,
    label,
    value: REDACTED_PLACEHOLDER,
    disclosed: false,
    reason,
  }
}

/**
 * Build a privacy-safe redaction preview for a local evidence package.
 *
 * Failure modes return stable codes/messages and never echo secrets, media,
 * witness proofs, or private keys.
 */
export function buildRedactionPreview(input: RedactionPreviewInput): RedactionPreviewResult {
  if (input == null || !isPlainObject(input as unknown)) {
    return { ok: false, code: 'MALFORMED_EVIDENCE', message: ERROR_MESSAGES.MALFORMED_EVIDENCE }
  }

  const byteLength = estimateBytes(input)
  if (byteLength > MAX_PREVIEW_INPUT_BYTES) {
    return { ok: false, code: 'OVERSIZED_PAYLOAD', message: ERROR_MESSAGES.OVERSIZED_PAYLOAD }
  }

  const proof = input.proof
  if (proof == null) {
    return { ok: false, code: 'MISSING_EVIDENCE', message: ERROR_MESSAGES.MISSING_EVIDENCE }
  }

  if (!isPlainObject(proof as unknown)) {
    return { ok: false, code: 'MALFORMED_EVIDENCE', message: ERROR_MESSAGES.MALFORMED_EVIDENCE }
  }

  const tier = proof.tier
  if (typeof tier !== 'string' || !SUPPORTED_TIERS.has(tier)) {
    return { ok: false, code: 'UNSUPPORTED_TIER', message: ERROR_MESSAGES.UNSUPPORTED_TIER }
  }

  if (typeof proof.fileName !== 'string' || typeof proof.timestamp !== 'string') {
    return { ok: false, code: 'MALFORMED_EVIDENCE', message: ERROR_MESSAGES.MALFORMED_EVIDENCE }
  }

  // Sanitize file name for display: basename only, strip control chars, bound length.
  const safeName = proof.fileName
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .split(/[/\\]/)
    .pop()
    ?.slice(0, 128) || 'evidence'

  const fields: RedactionField[] = [
    {
      key: 'fileName',
      label: 'File name',
      value: safeName,
      disclosed: true,
    },
    {
      key: 'tier',
      label: 'Identity tier',
      value: tier,
      disclosed: true,
    },
    {
      key: 'timestamp',
      label: 'Timestamp',
      value: proof.timestamp.slice(0, 64),
      disclosed: true,
    },
    discloseHash('Source hash', 'sourceHash', proof.sourceHash),
    discloseHash('Video hash', 'videoHash', proof.videoHash),
    discloseHash('Metadata hash', 'metadataHash', proof.metadataHash),
    discloseHash('Proof ID', 'proofId', proof.proofId),
    // Silent-witness material stays behind the public boundary.
    redact('Credential root', 'silentWitness.credentialRoot', 'witness'),
    redact('Nullifier', 'silentWitness.nullifier', 'witness'),
    redact('ZK proof bytes', 'silentWitness.proof', 'witness'),
    redact('Public inputs', 'silentWitness.publicInputs', 'witness'),
    // Local Studio secrets — always withheld.
    redact('Credential seed', 'secrets.credentialSeed', 'secret'),
    redact('Nullifier seed', 'secrets.nullifierSeed', 'secret'),
    redact('Private key', 'secrets.privateKey', 'private_key'),
    redact('Media object URL', 'secrets.mediaObjectUrl', 'media'),
  ]

  // If secrets were not even provided, the redacted rows still document the
  // boundary; presence must never change disclosed values.
  void input.secrets

  const disclosedCount = fields.filter((f) => f.disclosed).length
  const redactedCount = fields.length - disclosedCount

  return {
    ok: true,
    version: REDACTION_PREVIEW_VERSION,
    fields,
    disclosedCount,
    redactedCount,
    summary: `${disclosedCount} field${disclosedCount === 1 ? '' : 's'} disclosed · ${redactedCount} redacted at the public boundary`,
  }
}

/**
 * Privacy-safe log/telemetry payload derived from a preview result.
 * Contains codes and counts only — never field values or evidence material.
 */
export function toPrivacySafePreviewSignal(
  result: RedactionPreviewResult,
): Record<string, string | number | boolean> {
  if (!result.ok) {
    return {
      ok: false,
      code: result.code,
      version: REDACTION_PREVIEW_VERSION,
    }
  }
  return {
    ok: true,
    version: result.version,
    disclosedCount: result.disclosedCount,
    redactedCount: result.redactedCount,
  }
}

/** Map an error code to its stable operator message (for UI / tests). */
export function redactionErrorMessage(code: RedactionErrorCode): string {
  return ERROR_MESSAGES[code]
}
