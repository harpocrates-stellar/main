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

export type VerificationExportChainStatus =
  | 'confirmed'
  | 'revoked'
  | 'expired'
  | 'not_found'
  | 'not_checked'

export type VerificationFreshnessState = 'fresh' | 'stale' | 'unverified'

export type VerificationExportIncludedFields = {
  videoHash: string
  proofId: string | null
  metadataHash: string | null
  mode: 'offline' | 'online'
  status: string
  summary: string
  errorCode: string | null
  chainStatus: VerificationExportChainStatus
  tier: 'silent' | 'source' | 'seal' | null
  eventCount: number
  contractId: string | null
  network: string
}

export type VerificationExportFreshness = {
  capturedAt: string
  chainRecordCreatedAt: string | null
  latestEventAt: string | null
  state: VerificationFreshnessState
  maxAgeMs: number
}

export type VerificationExportPreview = {
  schema: 'harpocrates-verification-export-preview'
  version: 1
  trustContextRefreshedOnExport: false
  includedFields: VerificationExportIncludedFields
  freshness: VerificationExportFreshness
  unresolvedChecks: string[]
}

export type VerificationExportPreviewInput = {
  videoHash: string
  proofId?: string | null
  metadataHash?: string | null
  status: string
  summary: string
  errorCode?: string | null
  offline: boolean
  events: ProofEvent[]
  chainProof: ChainProofRecord | null
  contractId?: string | null
  network: string
  capturedAt?: string | Date
  now?: Date
  maxAgeMs?: number
}

export const DEFAULT_EXPORT_FRESHNESS_MAX_AGE_MS = 5 * 60 * 1000

function normalizeTier(
  eventTier: string | null | undefined,
  chainTier: number | undefined,
): 'silent' | 'source' | 'seal' | null {
  if (eventTier === 'silent' || eventTier === 'source' || eventTier === 'seal') {
    return eventTier
  }
  if (chainTier === 0) return 'silent'
  if (chainTier === 1) return 'source'
  if (chainTier === 2) return 'seal'
  return null
}

function resolveChainStatus(
  offline: boolean,
  chainProof: ChainProofRecord | null,
): VerificationExportChainStatus {
  if (offline) return 'not_checked'
  if (!chainProof) return 'not_found'
  if (chainProof.status === 2) return 'revoked'
  if (chainProof.status === 3) return 'expired'
  return 'confirmed'
}

function findLatestEventTimestamp(events: ProofEvent[]): string | null {
  let latestMs = -Infinity
  let latestIso: string | null = null
  for (const event of events) {
    if (!event.created_at) continue
    const parsed = Date.parse(event.created_at)
    if (!Number.isNaN(parsed) && parsed > latestMs) {
      latestMs = parsed
      latestIso = event.created_at
    }
  }
  return latestIso
}

export function evaluateVerificationFreshness(
  capturedAt: string,
  now: Date = new Date(),
  maxAgeMs: number = DEFAULT_EXPORT_FRESHNESS_MAX_AGE_MS,
  offline: boolean = false,
): VerificationFreshnessState {
  if (offline) return 'unverified'
  const capturedMs = Date.parse(capturedAt)
  if (Number.isNaN(capturedMs)) return 'unverified'
  const ageMs = now.getTime() - capturedMs
  if (ageMs < 0) return 'fresh'
  return ageMs > maxAgeMs ? 'stale' : 'fresh'
}

/**
 * Build a frozen, privacy-safe export preview snapshot from the currently
 * reviewed verification result. Never performs network calls or refreshes
 * trust context.
 */
export function buildVerificationExportPreview(
  input: VerificationExportPreviewInput,
): VerificationExportPreview {
  const status = input.status.trim()
  const videoHash = input.videoHash.trim()
  const summary = input.summary.trim()

  if (
    !status ||
    status === 'idle' ||
    status === 'validating' ||
    status === 'hashing' ||
    status === 'verifying'
  ) {
    throw new Error('Cannot build export preview while verification is idle or in progress.')
  }

  if (!videoHash && !summary) {
    throw new Error('Cannot build export preview without a reviewed verification result.')
  }

  const now = input.now ?? new Date()
  const capturedAtDate =
    input.capturedAt instanceof Date
      ? input.capturedAt
      : typeof input.capturedAt === 'string' && input.capturedAt.trim().length > 0
        ? new Date(input.capturedAt)
        : now
  const capturedAt = Number.isNaN(capturedAtDate.getTime())
    ? now.toISOString()
    : capturedAtDate.toISOString()
  const maxAgeMs = input.maxAgeMs ?? DEFAULT_EXPORT_FRESHNESS_MAX_AGE_MS

  const matchedEvent =
    input.events.find((event) => event.video_hash === videoHash && event.proof_id) ??
    input.events.find((event) => !!event.proof_id) ??
    input.events[0]

  const proofId = (input.proofId?.trim() || matchedEvent?.proof_id || null) ?? null
  const metadataHash = (input.metadataHash?.trim() || input.chainProof?.metadataHash || null) ?? null
  const chainStatus = resolveChainStatus(input.offline, input.chainProof)
  const tier = normalizeTier(matchedEvent?.tier, input.chainProof?.tier)
  const errorCode = input.errorCode?.trim() || null
  const contractId = input.contractId?.trim() || null

  const unresolvedChecks: string[] = []
  if (input.offline) {
    unresolvedChecks.push('On-chain Soroban registry status was not checked (offline mode).')
    unresolvedChecks.push('Backend NeonDB event feed was not queried (offline mode).')
  } else {
    if (!input.chainProof) {
      unresolvedChecks.push('No on-chain Soroban proof record was loaded.')
    } else if (input.chainProof.status === 2) {
      unresolvedChecks.push('On-chain proof record is revoked.')
    } else if (input.chainProof.status === 3) {
      unresolvedChecks.push('On-chain proof record is expired.')
    }
    if (input.events.length === 0) {
      unresolvedChecks.push('No corroborating backend NeonDB proof events were found.')
    }
  }

  if (errorCode) {
    unresolvedChecks.push(`Verification ended with error code: ${errorCode}.`)
  }
  if (!proofId) {
    unresolvedChecks.push('Proof ID could not be resolved.')
  }
  if (!metadataHash) {
    unresolvedChecks.push('Metadata hash could not be resolved.')
  }

  return {
    schema: 'harpocrates-verification-export-preview',
    version: 1,
    trustContextRefreshedOnExport: false,
    includedFields: {
      videoHash,
      proofId,
      metadataHash,
      mode: input.offline ? 'offline' : 'online',
      status,
      summary,
      errorCode,
      chainStatus,
      tier,
      eventCount: input.events.length,
      contractId,
      network: input.network,
    },
    freshness: {
      capturedAt,
      chainRecordCreatedAt: input.chainProof?.createdAt ?? null,
      latestEventAt: findLatestEventTimestamp(input.events),
      state: evaluateVerificationFreshness(capturedAt, now, maxAgeMs, input.offline),
      maxAgeMs,
    },
    unresolvedChecks,
  }
}

/**
 * Serialize the exact reviewed export preview snapshot as canonical JSON.
 */
export function serializeVerificationExportPreview(
  preview: VerificationExportPreview,
): string {
  return `${JSON.stringify(preview, null, 2)}\n`
}
