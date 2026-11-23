/**
 * verificationFlow — orchestrates the verification portal flow and maps
 * stable trust reason codes to accessible, privacy-safe copy.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single structured result with independent
 * trust dimensions, and bind cached verification results to their statement
 * and trust snapshot identity so incompatible context changes require a fresh
 * explicit verification result. No React state.
 */

import type { ChainProofRecord, IssuerRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import type { VerificationErrorCode, VerificationStatus } from '../hooks/useVerification'
import {
  isLookupEligibleIssuer,
  type IssuerTrustState,
} from '../provenance/issuerTrust'
import { assertValidVideoHash } from './videoHash'
import {
  extractMetadata,
  fetchProofEventsByVideo,
  getOnChainProof,
} from './verificationService'

export type ObservationSource = 'local' | 'backend' | 'soroban'

export type ObservationFreshness = 'fresh' | 'stale' | 'unknown'

export type SourceAgreement = 'aligned' | 'stale' | 'contradictory' | 'incomplete'

export type LedgerBounds = {
  minLedger: number | null
  maxLedger: number | null
  expiresAt: number | null
  observedAt: string | null
}

export type SourceObservation = {
  source: ObservationSource
  label: string
  freshness: ObservationFreshness
  ledgerBounds: LedgerBounds
  detail: string
}

export type ObservationDiagnostics = {
  agreement: SourceAgreement
  freshness: ObservationFreshness
  summary: string
  ledgerBounds: LedgerBounds
  disagreementReasons: string[]
  staleReasons: string[]
  sources: {
    backend: SourceObservation
    soroban: SourceObservation
  }
}

export type VerificationResult = {
  videoHash: string
  hasHarpocratesMetadata: boolean
  events: ProofEvent[]
  onChain: ChainProofRecord | null
  observations?: ObservationDiagnostics
}

/** Default threshold (24 hours) after which backend observations are marked stale. */
export const DEFAULT_OBSERVATION_STALE_MS = 24 * 60 * 60 * 1000

const CHAIN_TIER_MAP: Record<number, string> = {
  1: 'silent',
  2: 'source',
  3: 'seal',
}

function normaliseToken(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim().toLowerCase()
  return trimmed.length > 0 ? trimmed : null
}

function extractLedgerBoundsFromEvents(events: ProofEvent[]): LedgerBounds {
  let minLedger: number | null = null
  let maxLedger: number | null = null
  let latestMs: number | null = null
  let observedAt: string | null = null

  for (const event of events) {
    const anchors = event.time_attestation?.stellarAnchors ?? []
    for (const anchor of anchors) {
      if (Number.isSafeInteger(anchor.ledgerSequence) && anchor.ledgerSequence > 0) {
        minLedger = minLedger === null ? anchor.ledgerSequence : Math.min(minLedger, anchor.ledgerSequence)
        maxLedger = maxLedger === null ? anchor.ledgerSequence : Math.max(maxLedger, anchor.ledgerSequence)
      }
    }
    const parsed = Date.parse(event.created_at)
    if (!Number.isNaN(parsed) && (latestMs === null || parsed > latestMs)) {
      latestMs = parsed
      observedAt = event.created_at
    }
  }

  return {
    minLedger,
    maxLedger,
    expiresAt: null,
    observedAt,
  }
}

export function formatLedgerBounds(bounds: LedgerBounds): string {
  const parts: string[] = []
  if (bounds.minLedger !== null && bounds.maxLedger !== null) {
    parts.push(
      bounds.minLedger === bounds.maxLedger
        ? `Ledger #${bounds.minLedger}`
        : `Ledgers #${bounds.minLedger}–#${bounds.maxLedger}`,
    )
  }
  if (bounds.expiresAt !== null) {
    if (bounds.expiresAt === 0) {
      parts.push('No expiry bound')
    } else if (Number.isSafeInteger(bounds.expiresAt) && bounds.expiresAt > 0) {
      parts.push(`Expires ${new Date(bounds.expiresAt * 1000).toISOString().slice(0, 10)}`)
    }
  }
  return parts.length > 0 ? parts.join(' · ') : 'Ledger bounds unavailable'
}

/**
 * Evaluate observation freshness, ledger bounds, and source disagreements
 * across backend (NeonDB) events and Soroban on-chain records.
 */
export function evaluateVerificationObservations(input: {
  events: ProofEvent[]
  chainProof: ChainProofRecord | null
  errorCode?: string | null
  offline?: boolean
  nowMs?: number
  staleAfterMs?: number
}): ObservationDiagnostics {
  const nowMs = input.nowMs ?? Date.now()
  const staleAfterMs = input.staleAfterMs ?? DEFAULT_OBSERVATION_STALE_MS
  const { events, chainProof, errorCode = null, offline = false } = input

  const eventBounds = extractLedgerBoundsFromEvents(events)
  const chainExpiresAt = chainProof?.expiresAt ?? null
  const chainBounds: LedgerBounds = {
    minLedger: eventBounds.minLedger,
    maxLedger: eventBounds.maxLedger,
    expiresAt: chainExpiresAt,
    observedAt: chainProof?.createdAt ?? null,
  }
  const combinedBounds: LedgerBounds = {
    minLedger: eventBounds.minLedger,
    maxLedger: eventBounds.maxLedger,
    expiresAt: chainExpiresAt,
    observedAt: eventBounds.observedAt ?? chainProof?.createdAt ?? null,
  }

  const staleReasons: string[] = []
  const disagreementReasons: string[] = []

  // Backend freshness
  let backendFreshness: ObservationFreshness = 'unknown'
  if (events.length > 0 && eventBounds.observedAt) {
    const parsed = Date.parse(eventBounds.observedAt)
    if (!Number.isNaN(parsed)) {
      if (nowMs - parsed > staleAfterMs) {
        backendFreshness = 'stale'
        staleReasons.push('Backend event observation exceeds the freshness window.')
      } else {
        backendFreshness = 'fresh'
      }
    }
  }

  // Soroban freshness
  let sorobanFreshness: ObservationFreshness = 'unknown'
  if (chainProof) {
    const expiredByTimestamp =
      chainExpiresAt !== null &&
      Number.isSafeInteger(chainExpiresAt) &&
      chainExpiresAt > 0 &&
      chainExpiresAt * 1000 <= nowMs
    if (chainProof.status === 3 || errorCode === 'EXPIRED_EVIDENCE' || expiredByTimestamp) {
      sorobanFreshness = 'stale'
      staleReasons.push('Soroban registry record has passed its expiry ledger bound.')
    } else {
      sorobanFreshness = 'fresh'
    }
  } else if (errorCode === 'EXPIRED_EVIDENCE') {
    sorobanFreshness = 'stale'
    staleReasons.push('Soroban registry record has passed its expiry ledger bound.')
  }

  // Source disagreements (contradictory observations)
  if (errorCode === 'METADATA_ENVELOPE_MISMATCH') {
    disagreementReasons.push('Embedded metadata digest contradicts the on-chain envelope.')
  }

  if (chainProof && events.length > 0) {
    const chainTier = CHAIN_TIER_MAP[chainProof.tier] ?? null
    if (chainTier) {
      const mismatchedTier = events.some((event) => {
        const eventTier = normaliseToken(event.tier)
        return eventTier !== null && eventTier !== chainTier
      })
      if (mismatchedTier) {
        disagreementReasons.push('Backend tier observation disagrees with the Soroban registry tier.')
      }
    }

    const chainVideoHash = normaliseToken(chainProof.videoHash)
    if (chainVideoHash) {
      const mismatchedHash = events.some((event) => {
        const eventHash = normaliseToken(event.video_hash)
        return eventHash !== null && eventHash !== chainVideoHash
      })
      if (mismatchedHash) {
        disagreementReasons.push('Backend fingerprint observation disagrees with the Soroban registry record.')
      }
    }

    if (chainProof.status === 2 || errorCode === 'REVOKED_EVIDENCE') {
      const hasRevocationEvent = events.some((event) => /revok/i.test(event.event_type))
      if (!hasRevocationEvent) {
        disagreementReasons.push('Soroban registry reports revoked status while backend events show active registration.')
      }
    }
  }

  const overallFreshness: ObservationFreshness =
    backendFreshness === 'stale' || sorobanFreshness === 'stale'
      ? 'stale'
      : backendFreshness === 'fresh' || sorobanFreshness === 'fresh'
        ? 'fresh'
        : 'unknown'

  let agreement: SourceAgreement
  let summary: string

  if (disagreementReasons.length > 0) {
    agreement = 'contradictory'
    summary = disagreementReasons[0]
  } else if (staleReasons.length > 0) {
    agreement = 'stale'
    summary = staleReasons[0]
  } else if (!offline && events.length > 0 && chainProof) {
    agreement = 'aligned'
    summary = 'Backend and Soroban observations are fresh and aligned.'
  } else {
    agreement = 'incomplete'
    summary = offline
      ? 'Offline mode: only local browser observations are available.'
      : 'Waiting for corroborating backend and Soroban observations.'
  }

  return {
    agreement,
    freshness: overallFreshness,
    summary,
    ledgerBounds: combinedBounds,
    disagreementReasons,
    staleReasons,
    sources: {
      backend: {
        source: 'backend',
        label: 'Backend (NeonDB)',
        freshness: backendFreshness,
        ledgerBounds: eventBounds,
        detail:
          events.length > 0
            ? `${events.length} event${events.length === 1 ? '' : 's'} · ${formatLedgerBounds(eventBounds)}`
            : 'No backend observations',
      },
      soroban: {
        source: 'soroban',
        label: 'Soroban Registry',
        freshness: sorobanFreshness,
        ledgerBounds: chainBounds,
        detail: chainProof
          ? `Status ${chainProof.status} · ${formatLedgerBounds(chainBounds)}`
          : 'No Soroban observations',
      },
    },
  }
}

/**
 * Run the verification flow for an already-computed video hash.
 *
 * The hash is validated before any network call is made so a malformed value
 * (from a share link or manifest) cannot inject path segments or query strings.
 */
export async function runVerificationFlow(
  videoHash: string,
  options: VerificationFlowOptions = {},
): Promise<VerificationResult> {
  throwIfAborted(options.signal)
  const safeHash = assertValidVideoHash(videoHash)

  const events = await fetchProofEventsByVideo(safeHash, options.signal)
  throwIfAborted(options.signal)

  const onChain = await getOnChainProof(safeHash, options.sourceAddress)
  throwIfAborted(options.signal)

  const result: VerificationResult = {
    videoHash: safeHash,
    hasHarpocratesMetadata,
    events,
    onChain: onChain,
    observations: evaluateVerificationObservations({ events, chainProof: onChain }),
  }
  if (options.revision !== undefined) {
    result.revision = options.revision
  }
  return result
}

/**
 * Convenience helper: extract metadata from an uploaded file and then run the
 * verification flow for the supplied video hash.
 */
export async function verifyUploadedVideo(
  file: File,
  videoHash: string,
  options: VerificationFlowOptions = {},
): Promise<VerificationResult> {
  throwIfAborted(options.signal)
  // Validate before hitting the network at all.
  const safeHash = assertValidVideoHash(videoHash)
  const extract = await extractMetadata(file, options.signal)
  throwIfAborted(options.signal)
  const result = await runVerificationFlow(safeHash, options)
  const hasHarpocratesMetadata = extract.hasHarpocratesMetadata
  return {
    ...result,
    hasHarpocratesMetadata,
    trust: buildVerificationDimensions({
      hasHarpocratesMetadata,
      events: result.events,
      onChain: result.onChain,
      issuerRecord: options.issuerRecord,
      nowUnixSeconds: options.nowUnixSeconds,
    }),
  }
}
