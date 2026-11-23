/**
 * Pre-export privacy summary for Evidence Studio.
 *
 * Summarizes the metadata classes and public identifiers included in an
 * exported evidence artifact, and requires explicit operator acknowledgement
 * only for newly exposed sensitive fields. Pure / deterministic; safe to unit test.
 */

import type { IdentityTier, ProofPackage } from './types'
import { shortHash } from './utils'

/** Summary schema version. Bump on incompatible field-shape changes. */
export const EXPORT_PRIVACY_SUMMARY_VERSION = 1 as const

/** Hard cap on serialized input size (bytes) to bound hostile / oversized packages. */
export const MAX_EXPORT_PRIVACY_SUMMARY_BYTES = 64 * 1024

export type ExportPrivacyErrorCode =
  | 'MISSING_EVIDENCE'
  | 'MALFORMED_EVIDENCE'
  | 'OVERSIZED_PAYLOAD'
  | 'UNSUPPORTED_TIER'

export type MetadataClassKey =
  | 'container_file'
  | 'cryptographic_digests'
  | 'packaging_timestamp'
  | 'identity_tier'
  | 'silent_witness_proof'
  | 'time_attestation'

export type IncludedMetadataClass = {
  key: MetadataClassKey
  label: string
  description: string
  fields: string[]
}

export type PublicIdentifier = {
  key: string
  label: string
  /** Display value only — truncated hashes or sanitized identifiers, never secrets. */
  value: string
  sensitive: boolean
  sensitivityReason?: string
}

export type SensitiveExportField = {
  key: string
  label: string
  reason: string
  newlyExposed: boolean
}

export type ExportPrivacySummaryOk = {
  ok: true
  version: typeof EXPORT_PRIVACY_SUMMARY_VERSION
  tier: IdentityTier
  metadataClasses: IncludedMetadataClass[]
  publicIdentifiers: PublicIdentifier[]
  sensitiveFields: SensitiveExportField[]
  newlyExposedSensitiveFields: SensitiveExportField[]
  requiresAcknowledgement: boolean
  summary: string
}

export type ExportPrivacySummaryErr = {
  ok: false
  code: ExportPrivacyErrorCode
  /** Stable, privacy-safe operator message — never embeds evidence values. */
  message: string
}

export type ExportPrivacySummaryResult = ExportPrivacySummaryOk | ExportPrivacySummaryErr

export type ExportPrivacySummaryInput = {
  proof: ProofPackage | null | undefined
  wallet?: string | null
  acknowledgedSensitiveKeys?: ReadonlySet<string> | readonly string[] | null
}

const ERROR_MESSAGES: Record<ExportPrivacyErrorCode, string> = {
  MISSING_EVIDENCE: 'No evidence package is available to summarize before export.',
  MALFORMED_EVIDENCE: 'Evidence package is malformed and cannot be exported safely.',
  OVERSIZED_PAYLOAD: 'Evidence package exceeds the export privacy summary size limit.',
  UNSUPPORTED_TIER: 'Evidence tier is not supported by the export privacy summary.',
}

const SUPPORTED_TIERS = new Set<IdentityTier>(['silent', 'source', 'seal'])

const TIER_DESCRIPTIONS: Record<IdentityTier, string> = {
  silent: 'Anonymous credential tier with no public creator identity.',
  source: 'Pseudonymous wallet tier linking evidence to a recurring Stellar account.',
  seal: 'Institutional issuer tier signing evidence under a verified Stellar account.',
}

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

function toAcknowledgedSet(
  input: ReadonlySet<string> | readonly string[] | null | undefined,
): Set<string> {
  if (!input) return new Set<string>()
  if (input instanceof Set) return new Set(input)
  if (Array.isArray(input)) {
    return new Set(input.filter((item): item is string => typeof item === 'string'))
  }
  return new Set<string>()
}

function sanitizeFileName(raw: string): string {
  const stripped = Array.from(raw)
    .filter((ch) => {
      const code = ch.charCodeAt(0)
      return code >= 0x20 && code !== 0x7f
    })
    .join('')
  return (
    stripped
      .split(/[/\\]/)
      .pop()
      ?.slice(0, 128) || 'harpocrates-evidence.mp4'
  )
}

/**
 * Build a deterministic privacy summary for an evidence artifact prior to export.
 *
 * Failure modes return stable codes/messages (fail-closed) and never echo
 * seeds, private keys, or raw witness bytes.
 */
export function buildExportPrivacySummary(
  input: ExportPrivacySummaryInput,
): ExportPrivacySummaryResult {
  if (input == null || !isPlainObject(input as unknown)) {
    return { ok: false, code: 'MALFORMED_EVIDENCE', message: ERROR_MESSAGES.MALFORMED_EVIDENCE }
  }

  const byteLength = estimateBytes({
    proof: input.proof,
    wallet: input.wallet,
  })
  if (byteLength > MAX_EXPORT_PRIVACY_SUMMARY_BYTES) {
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
  if (typeof tier !== 'string' || !SUPPORTED_TIERS.has(tier as IdentityTier)) {
    return { ok: false, code: 'UNSUPPORTED_TIER', message: ERROR_MESSAGES.UNSUPPORTED_TIER }
  }

  if (
    typeof proof.fileName !== 'string' ||
    typeof proof.timestamp !== 'string' ||
    typeof proof.sourceHash !== 'string' ||
    typeof proof.videoHash !== 'string' ||
    typeof proof.metadataHash !== 'string' ||
    typeof proof.proofId !== 'string'
  ) {
    return { ok: false, code: 'MALFORMED_EVIDENCE', message: ERROR_MESSAGES.MALFORMED_EVIDENCE }
  }

  const safeFileName = sanitizeFileName(proof.fileName)
  const acknowledged = toAcknowledgedSet(input.acknowledgedSensitiveKeys)

  const metadataClasses: IncludedMetadataClass[] = [
    {
      key: 'container_file',
      label: 'Container & file metadata',
      description: `Embedded MP4 container packaged as ${safeFileName}.`,
      fields: ['fileName'],
    },
    {
      key: 'cryptographic_digests',
      label: 'Cryptographic digests',
      description: 'SHA-256 commitments binding the source media, embedded video, and metadata.',
      fields: ['sourceHash', 'videoHash', 'metadataHash', 'proofId'],
    },
    {
      key: 'packaging_timestamp',
      label: 'Packaging timestamp',
      description: `Local packaging timestamp (${proof.timestamp.slice(0, 64)}).`,
      fields: ['timestamp'],
    },
    {
      key: 'identity_tier',
      label: 'Identity tier metadata',
      description: TIER_DESCRIPTIONS[tier as IdentityTier],
      fields: ['tier'],
    },
  ]

  const publicIdentifiers: PublicIdentifier[] = [
    {
      key: 'proofId',
      label: 'Proof ID',
      value: shortHash(proof.proofId),
      sensitive: false,
    },
    {
      key: 'videoHash',
      label: 'Embedded video hash',
      value: shortHash(proof.videoHash),
      sensitive: false,
    },
    {
      key: 'metadataHash',
      label: 'Metadata hash',
      value: shortHash(proof.metadataHash),
      sensitive: false,
    },
    {
      key: 'sourceHash',
      label: 'Source file hash',
      value: shortHash(proof.sourceHash),
      sensitive: false,
    },
  ]

  if (tier === 'source' || tier === 'seal') {
    const walletDisplay =
      typeof input.wallet === 'string' && input.wallet.trim().length > 0
        ? shortHash(input.wallet.trim())
        : 'Connected Stellar wallet'
    publicIdentifiers.push({
      key: 'publicIdentity',
      label: tier === 'seal' ? 'Public Seal issuer account' : 'Consistent Source account',
      value: walletDisplay,
      sensitive: true,
      sensitivityReason:
        tier === 'seal'
          ? 'Links this exported artifact to a verified institutional Stellar issuer account.'
          : 'Links this exported artifact to a recurring pseudonymous Stellar account.',
    })
  }

  if (tier === 'silent' && proof.silentWitness) {
    metadataClasses.push({
      key: 'silent_witness_proof',
      label: 'Silent Witness proof metadata',
      description: 'Zero-knowledge replay-protection nullifier and credential Merkle root.',
      fields: ['silentWitness.nullifier', 'silentWitness.credentialRoot'],
    })
    publicIdentifiers.push(
      {
        key: 'silentWitness.nullifier',
        label: 'Epoch nullifier',
        value: shortHash(proof.silentWitness.nullifier),
        sensitive: true,
        sensitivityReason:
          'Epoch-scoped nullifier can correlate duplicate submissions within the same verifier scope.',
      },
      {
        key: 'silentWitness.credentialRoot',
        label: 'Credential root',
        value: shortHash(proof.silentWitness.credentialRoot),
        sensitive: true,
        sensitivityReason: 'Identifies the credential anonymity set used to generate the proof.',
      },
    )
  }

  if (proof.timeAttestation) {
    metadataClasses.push({
      key: 'time_attestation',
      label: 'Time attestation metadata',
      description: 'Externally anchored timestamp metadata attached to this evidence package.',
      fields: ['timeAttestation'],
    })
    const attestationLabel =
      typeof proof.timeAttestation.protocol === 'string' && proof.timeAttestation.protocol
        ? proof.timeAttestation.protocol
        : 'External time anchor'
    publicIdentifiers.push({
      key: 'timeAttestation',
      label: 'Time attestation anchor',
      value: attestationLabel.slice(0, 64),
      sensitive: true,
      sensitivityReason:
        'Discloses an externally verifiable capture or anchoring time window beyond local packaging time.',
    })
  }

  const sensitiveFields: SensitiveExportField[] = publicIdentifiers
    .filter((item) => item.sensitive)
    .map((item) => ({
      key: item.key,
      label: item.label,
      reason: item.sensitivityReason ?? 'Exposes additional sensitive metadata.',
      newlyExposed: !acknowledged.has(item.key),
    }))

  const newlyExposedSensitiveFields = sensitiveFields.filter((field) => field.newlyExposed)
  const requiresAcknowledgement = newlyExposedSensitiveFields.length > 0

  const summary = requiresAcknowledgement
    ? `${metadataClasses.length} metadata classes · ${publicIdentifiers.length} public identifiers · ${newlyExposedSensitiveFields.length} newly exposed sensitive field${newlyExposedSensitiveFields.length === 1 ? '' : 's'} require acknowledgement`
    : `${metadataClasses.length} metadata classes · ${publicIdentifiers.length} public identifiers · ready to export`

  return {
    ok: true,
    version: EXPORT_PRIVACY_SUMMARY_VERSION,
    tier: tier as IdentityTier,
    metadataClasses,
    publicIdentifiers,
    sensitiveFields,
    newlyExposedSensitiveFields,
    requiresAcknowledgement,
    summary,
  }
}

/** Map an error code to its stable operator message (for UI / tests). */
export function exportPrivacyErrorMessage(code: ExportPrivacyErrorCode): string {
  return ERROR_MESSAGES[code]
}
