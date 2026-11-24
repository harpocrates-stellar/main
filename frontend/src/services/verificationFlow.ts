/**
 * verificationFlow â€” orchestrates the verification portal flow and maps
 * stable trust reason codes to accessible, privacy-safe copy.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single structured result with independent
 * trust dimensions, and bind cached verification results to their statement
 * and trust snapshot identity so incompatible context changes require a fresh
 * explicit verification result. No React state.
 */

import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'

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
        : `Ledgers #${bounds.minLedger}â€“#${bounds.maxLedger}`,
    )
  }
  if (bounds.expiresAt !== null) {
    if (bounds.expiresAt === 0) {
      parts.push('No expiry bound')
    } else if (Number.isSafeInteger(bounds.expiresAt) && bounds.expiresAt > 0) {
      parts.push(`Expires ${new Date(bounds.expiresAt * 1000).toISOString().slice(0, 10)}`)
    }
  }
  return parts.length > 0 ? parts.join(' Â· ') : 'Ledger bounds unavailable'
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
            ? `${events.length} event${events.length === 1 ? '' : 's'} Â· ${formatLedgerBounds(eventBounds)}`
            : 'No backend observations',
      },
      soroban: {
        source: 'soroban',
        label: 'Soroban Registry',
        freshness: sorobanFreshness,
        ledgerBounds: chainBounds,
        detail: chainProof
          ? `Status ${chainProof.status} Â· ${formatLedgerBounds(chainBounds)}`
          : 'No Soroban observations',
      },
    },
  }
}

/**
 * Monotonically-incrementing revision guard used by stateful callers to
 * discard results from superseded verification runs.
 */
export function createVerificationRevisionGuard() {
  let seq = 0
  return {
    next(): number { return ++seq },
    current(): number { return seq },
    isCurrent(revision: number): boolean { return revision === seq },
    invalidate(): void { seq++ },
  }
}

export type TrustDimensionState = 'verified' | 'failed' | 'unverified' | 'not_applicable'

export type TrustDimension = {
  key: string
  label: string
  summary: string
  state: TrustDimensionState
}

export type TrustModel = {
  overall: TrustDimensionState
  hasFailure: boolean
  dimensions: Record<string, TrustDimension>
}

export type ResolvedStatementIdentity = {
  statementDigest: string | null
  proofId: string | null
  metadataHash: string | null
  matchingEvents: ProofEvent[]
}

/**
 * Resolve the canonical statement digest and proof identity from the
 * currently displayed verification context. Matching events are filtered
 * to those that share the resolved statement digest.
 */
export function resolveVerifiedStatementIdentity(input: {
  verifyHash: string
  videoHashInput: string
  proofIdInput: string
  events: ProofEvent[]
  chainProof: ChainProofRecord | null
}): ResolvedStatementIdentity {
  const statementDigest =
    input.verifyHash ||
    input.videoHashInput.trim() ||
    input.chainProof?.videoHash ||
    null

  const proofId =
    input.proofIdInput.trim() ||
    input.chainProof?.proofId ||
    input.events.find((e) => e.video_hash === statementDigest && e.proof_id)?.proof_id ||
    input.events.find((e) => !!e.proof_id)?.proof_id ||
    null

  const metadataHash = input.chainProof?.metadataHash ?? null

  const matchingEvents = statementDigest
    ? input.events.filter((e) => e.video_hash === statementDigest)
    : []

  return { statementDigest, proofId, metadataHash, matchingEvents }
}

/**
 * Map the current verification status and trust context into a
 * human-readable trust explanation string.
 *
 * Never labels skipped online revocation checks as passed: when
 * ``offline`` is true the result is always framed as a local check only.
 */
export function explainVerificationTrust(input: {
  status: string
  offline: boolean
  errorCode: string | null
  chainProof: ChainProofRecord | null
  events: ProofEvent[]
}): { label: string; detail: string; overall: TrustDimensionState } {
  if (input.offline) {
    return {
      label: 'Local check only',
      detail:
        'On-chain revocation status was not checked. This result cannot be treated as confirmed evidence.',
      overall: 'unverified',
    }
  }
  if (input.errorCode === 'REVOKED_EVIDENCE' || input.chainProof?.status === 2) {
    return {
      label: 'Revoked',
      detail: 'The on-chain record for this artifact has been revoked. Do not trust it.',
      overall: 'failed',
    }
  }
  if (input.errorCode === 'EXPIRED_EVIDENCE' || input.chainProof?.status === 3) {
    return {
      label: 'Expired',
      detail: 'The on-chain record for this artifact has expired.',
      overall: 'failed',
    }
  }
  if (input.status === 'success' && input.chainProof && input.events.length > 0) {
    return {
      label: 'Confirmed',
      detail: 'Backend and on-chain records are aligned.',
      overall: 'verified',
    }
  }
  if (input.status === 'success') {
    return {
      label: 'Partial',
      detail: 'Some verification sources were unavailable or produced no records.',
      overall: 'unverified',
    }
  }
  return {
    label: 'Not verified',
    detail: 'No confirmed trust decision was made.',
    overall: 'unverified',
  }
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

