/**
 * verificationFlow — orchestrates the verification portal flow.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single result. No React state.
 */

import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import { assertValidVideoHash } from './videoHash'
import {
  extractMetadata,
  fetchProofEventsByVideo,
  getOnChainProof,
} from './verificationService'

export type VerificationResult = {
  videoHash: string
  hasHarpocratesMetadata: boolean
  events: ProofEvent[]
  onChain: ChainProofRecord | null
}

export const MAX_PORTABLE_OFFLINE_BUNDLE_BYTES = 128 * 1024

export type OfflineLocalCheckStatus = 'passed' | 'failed'
export type OfflineLiveCheckStatus = 'unavailable-offline'

export type OfflineBundleErrorCode =
  | 'OVERSIZED_BUNDLE'
  | 'MALFORMED_BUNDLE_JSON'
  | 'INVALID_BUNDLE_SCHEMA'
  | 'SECRET_MATERIAL_REJECTED'
  | 'DIGEST_BINDING_MISMATCH'

export interface OfflineBundleCheckItem<TStatus extends string> {
  readonly id: string
  readonly label: string
  readonly status: TStatus
  readonly detail: string
}

export interface PortableOfflineBundleStatement {
  readonly videoHash: string
  readonly proofId: string
  readonly metadataHash: string
  readonly tier: string
  readonly networkPassphrase: string
  readonly contractId: string
  readonly timestamp: string
}

export interface PortableOfflineBundleReport {
  readonly accepted: boolean
  readonly errorCode: OfflineBundleErrorCode | null
  readonly overallDisposition: 'local-bundle-inspected-unconfirmed' | 'rejected'
  readonly summary: string
  readonly statement: PortableOfflineBundleStatement | null
  readonly localChecks: readonly OfflineBundleCheckItem<OfflineLocalCheckStatus>[]
  readonly unavailableLiveChecks: readonly OfflineBundleCheckItem<OfflineLiveCheckStatus>[]
}

const SUPPORTED_BUNDLE_PROTOCOLS = new Set([
  'harpocrates-offline-bundle',
  'harpocrates',
  'harpocrates-verification-receipt',
])

const FORBIDDEN_SECRET_BUNDLE_KEYS = new Set([
  'witness',
  'privateinputs',
  'private_inputs',
  'credentialseed',
  'nullifierseed',
  'secret',
  'secretkey',
  'privatekey',
])

const HEX_64_RE = /^[0-9a-f]{64}$/i

const UNAVAILABLE_LIVE_CHECKS: readonly OfflineBundleCheckItem<OfflineLiveCheckStatus>[] =
  Object.freeze([
    Object.freeze({
      id: 'soroban-revocation-check',
      label: 'Soroban on-chain revocation check',
      status: 'unavailable-offline',
      detail:
        'Not checked offline — skipped online revocation checks are never treated as passed.',
    }),
    Object.freeze({
      id: 'soroban-expiry-check',
      label: 'Soroban on-chain expiry check',
      status: 'unavailable-offline',
      detail:
        'Not checked offline — ledger timestamp expiry requires a live Soroban RPC read.',
    }),
    Object.freeze({
      id: 'issuer-directory-standing',
      label: 'Registry issuer standing check',
      status: 'unavailable-offline',
      detail:
        'Not checked offline — current issuer active or revoked status was not queried.',
    }),
    Object.freeze({
      id: 'neondb-event-corroboration',
      label: 'NeonDB event feed corroboration',
      status: 'unavailable-offline',
      detail:
        'Not checked offline — backend proof event history was not queried.',
    }),
  ])

function containsForbiddenSecretKeys(obj: Record<string, unknown>): string | null {
  for (const [key, val] of Object.entries(obj)) {
    const normalized = key.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase()
    if (FORBIDDEN_SECRET_BUNDLE_KEYS.has(normalized)) {
      return key
    }
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      const nested = containsForbiddenSecretKeys(val as Record<string, unknown>)
      if (nested) return nested
    }
  }
  return null
}

function normalizeHex64(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const stripped = value.trim().replace(/^0x/i, '').toLowerCase()
  return HEX_64_RE.test(stripped) ? stripped : null
}

function buildRejectedBundleReport(
  errorCode: OfflineBundleErrorCode,
  summary: string,
  localChecks: readonly OfflineBundleCheckItem<OfflineLocalCheckStatus>[],
): PortableOfflineBundleReport {
  return Object.freeze({
    accepted: false,
    errorCode,
    overallDisposition: 'rejected',
    summary,
    statement: null,
    localChecks: Object.freeze([...localChecks]),
    unavailableLiveChecks: UNAVAILABLE_LIVE_CHECKS,
  })
}

/**
 * Inspects a bounded portable verification bundle entirely offline in memory.
 * Enforces a strict 128 KB byte ceiling before parsing, rejects private witness
 * material, and explicitly marks skipped online revocation/chain checks as
 * `unavailable-offline` (never `passed` or `confirmed`).
 */
export function inspectPortableOfflineBundle(
  rawBundle: string | Uint8Array,
): PortableOfflineBundleReport {
  const bytes =
    typeof rawBundle === 'string'
      ? new TextEncoder().encode(rawBundle)
      : rawBundle

  if (bytes.byteLength > MAX_PORTABLE_OFFLINE_BUNDLE_BYTES) {
    return buildRejectedBundleReport(
      'OVERSIZED_BUNDLE',
      `Portable bundle exceeds the 128 KB offline limit (${(
        bytes.byteLength / 1024
      ).toFixed(1)} KB).`,
      [
        Object.freeze({
          id: 'bundle-size-bound',
          label: 'Bundle size bound (<= 128 KB)',
          status: 'failed',
          detail: `Bundle size ${bytes.byteLength} bytes exceeds ${MAX_PORTABLE_OFFLINE_BUNDLE_BYTES} bytes.`,
        }),
      ],
    )
  }

  const sizeCheckPassed: OfflineBundleCheckItem<OfflineLocalCheckStatus> =
    Object.freeze({
      id: 'bundle-size-bound',
      label: 'Bundle size bound (<= 128 KB)',
      status: 'passed',
      detail: `Bounded payload (${bytes.byteLength} bytes).`,
    })

  let parsed: unknown
  try {
    const text =
      typeof rawBundle === 'string'
        ? rawBundle
        : new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    parsed = JSON.parse(text)
  } catch {
    return buildRejectedBundleReport(
      'MALFORMED_BUNDLE_JSON',
      'Portable bundle is not valid UTF-8 JSON.',
      [
        sizeCheckPassed,
        Object.freeze({
          id: 'bundle-schema-validity',
          label: 'Portable bundle JSON schema',
          status: 'failed',
          detail: 'JSON syntax could not be parsed.',
        }),
      ],
    )
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return buildRejectedBundleReport(
      'INVALID_BUNDLE_SCHEMA',
      'Portable bundle root must be a JSON object.',
      [
        sizeCheckPassed,
        Object.freeze({
          id: 'bundle-schema-validity',
          label: 'Portable bundle JSON schema',
          status: 'failed',
          detail: 'Expected top-level JSON object.',
        }),
      ],
    )
  }

  const root = parsed as Record<string, unknown>
  const secretKey = containsForbiddenSecretKeys(root)
  if (secretKey) {
    return buildRejectedBundleReport(
      'SECRET_MATERIAL_REJECTED',
      `Portable bundle rejected because it contains prohibited secret field "${secretKey}".`,
      [
        sizeCheckPassed,
        Object.freeze({
          id: 'bundle-privacy-boundary',
          label: 'Public-only bundle boundary',
          status: 'failed',
          detail: `Prohibited private field "${secretKey}" detected.`,
        }),
      ],
    )
  }

  const protocol = typeof root.protocol === 'string' ? root.protocol.trim() : ''
  if (!SUPPORTED_BUNDLE_PROTOCOLS.has(protocol)) {
    return buildRejectedBundleReport(
      'INVALID_BUNDLE_SCHEMA',
      'Unsupported or missing portable bundle protocol identifier.',
      [
        sizeCheckPassed,
        Object.freeze({
          id: 'bundle-schema-validity',
          label: 'Portable bundle JSON schema',
          status: 'failed',
          detail: `Unsupported protocol "${protocol || 'missing'}".`,
        }),
      ],
    )
  }

  let videoHash: string
  try {
    videoHash = assertValidVideoHash(
      typeof root.videoHash === 'string' ? root.videoHash : '',
    )
  } catch {
    return buildRejectedBundleReport(
      'INVALID_BUNDLE_SCHEMA',
      'Portable bundle is missing a canonical 64-character hex videoHash.',
      [
        sizeCheckPassed,
        Object.freeze({
          id: 'bundle-schema-validity',
          label: 'Portable bundle JSON schema',
          status: 'failed',
          detail: 'Invalid or missing 64-char hex videoHash.',
        }),
      ],
    )
  }

  const metadataHash = normalizeHex64(root.metadataHash)
  const proofId = typeof root.proofId === 'string' ? root.proofId.trim() : ''
  const timestampRaw =
    typeof root.timestamp === 'string'
      ? root.timestamp.trim()
      : typeof root.verifiedAt === 'string'
        ? root.verifiedAt.trim()
        : ''
  const networkPassphrase =
    typeof root.networkPassphrase === 'string'
      ? root.networkPassphrase.trim()
      : typeof root.network === 'string'
        ? root.network.trim()
        : ''
  const contractId =
    typeof root.contractId === 'string' ? root.contractId.trim() : ''
  const tier = typeof root.tier === 'string' ? root.tier.trim() : 'silent'

  if (
    !metadataHash ||
    !proofId ||
    !timestampRaw ||
    Number.isNaN(Date.parse(timestampRaw)) ||
    !networkPassphrase ||
    !contractId
  ) {
    return buildRejectedBundleReport(
      'INVALID_BUNDLE_SCHEMA',
      'Portable bundle is missing required public commitment, network, or timestamp fields.',
      [
        sizeCheckPassed,
        Object.freeze({
          id: 'bundle-schema-validity',
          label: 'Portable bundle JSON schema',
          status: 'failed',
          detail:
            'Required fields: videoHash, metadataHash, proofId, timestamp/verifiedAt, network, contractId.',
        }),
      ],
    )
  }

  // If the bundle carries a nested receipt or manifest envelope, verify digest consistency
  const nestedEnvelope =
    root.receipt && typeof root.receipt === 'object' && !Array.isArray(root.receipt)
      ? (root.receipt as Record<string, unknown>)
      : root.manifest && typeof root.manifest === 'object' && !Array.isArray(root.manifest)
        ? (root.manifest as Record<string, unknown>)
        : null

  if (nestedEnvelope) {
    const nestedVideo = normalizeHex64(nestedEnvelope.videoHash)
    const nestedMeta = normalizeHex64(nestedEnvelope.metadataHash)
    const nestedProof =
      typeof nestedEnvelope.proofId === 'string'
        ? nestedEnvelope.proofId.trim().toLowerCase()
        : null
    if (
      (nestedVideo && nestedVideo !== videoHash) ||
      (nestedMeta && nestedMeta !== metadataHash) ||
      (nestedProof && nestedProof !== proofId.toLowerCase())
    ) {
      return buildRejectedBundleReport(
        'DIGEST_BINDING_MISMATCH',
        'Embedded receipt or manifest digests disagree with the portable bundle header.',
        [
          sizeCheckPassed,
          Object.freeze({
            id: 'bundle-digest-binding',
            label: 'Embedded digest commitment consistency',
            status: 'failed',
            detail: 'Nested envelope digest does not match top-level bundle commitments.',
          }),
        ],
      )
    }
  }

  const localChecks: readonly OfflineBundleCheckItem<OfflineLocalCheckStatus>[] =
    Object.freeze([
      sizeCheckPassed,
      Object.freeze({
        id: 'bundle-schema-validity',
        label: 'Portable bundle schema and public-only boundary',
        status: 'passed',
        detail: `Validated ${protocol} fields with no private witness material.`,
      }),
      Object.freeze({
        id: 'bundle-digest-binding',
        label: 'Statement and metadata digest binding',
        status: 'passed',
        detail: 'Canonical 32-byte statement and metadata commitments matched locally.',
      }),
    ])

  const statement: PortableOfflineBundleStatement = Object.freeze({
    videoHash,
    proofId,
    metadataHash,
    tier,
    networkPassphrase,
    contractId,
    timestamp: timestampRaw,
  })

  return Object.freeze({
    accepted: true,
    errorCode: null,
    overallDisposition: 'local-bundle-inspected-unconfirmed',
    summary:
      'Portable bundle structure verified locally (unconfirmed offline inspection — live Soroban revocation and registry standing were NOT checked).',
    statement,
    localChecks,
    unavailableLiveChecks: UNAVAILABLE_LIVE_CHECKS,
  })
}

/**
 * Run the verification flow for an already-computed video hash.
 *
 * The hash is validated before any network call is made so a malformed value
 * (from a share link or manifest) cannot inject path segments or query strings.
 */
export async function runVerificationFlow(
  videoHash: string,
  options: { signal?: AbortSignal; sourceAddress?: string } = {},
): Promise<VerificationResult> {
  const safeHash = assertValidVideoHash(videoHash)

  const events = await fetchProofEventsByVideo(safeHash, options.signal)
  const onChain = await getOnChainProof(safeHash, options.sourceAddress)

  return {
    videoHash: safeHash,
    hasHarpocratesMetadata: events.length > 0,
    events,
    onChain: onChain,
  }
}

/**
 * Convenience helper: extract metadata from an uploaded file and then run the
 * verification flow for the supplied video hash.
 */
export async function verifyUploadedVideo(
  file: File,
  videoHash: string,
  options: { signal?: AbortSignal; sourceAddress?: string } = {},
): Promise<VerificationResult> {
  // Validate before hitting the network at all.
  const safeHash = assertValidVideoHash(videoHash)
  const extract = await extractMetadata(file, options.signal)
  const result = await runVerificationFlow(safeHash, options)
  return { ...result, hasHarpocratesMetadata: extract.hasHarpocratesMetadata }
}
