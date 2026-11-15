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

export type TimelineStageId =
  | 'input'
  | 'hash'
  | 'database'
  | 'chain'
  | 'decision'

export interface TimelineLedgerBounds {
  readonly minLedger?: number | null
  readonly maxLedger?: number | null
  readonly observedLedger?: number | null
  readonly maxLedgerLag?: number
}

export interface TimelineProvenanceDiscrepancy {
  readonly field: string
  readonly manifestValue: string
  readonly chainValue: string
}

export interface AnalyzeTimelineObservationsInput {
  readonly status: string
  readonly verifyHash: string
  readonly events: readonly ProofEvent[]
  readonly chainProof: ChainProofRecord | null
  readonly errorCode?: string | null
  readonly offline?: boolean
  readonly ledgerBounds?: TimelineLedgerBounds | null
  readonly observedAtIso?: string | null
  readonly isStaleObservation?: boolean
  readonly maxObservationAgeMs?: number
  readonly nowMs?: number
  readonly provenanceMismatches?: readonly TimelineProvenanceDiscrepancy[]
}

export interface TimelineStageAnnotation {
  readonly stageId: TimelineStageId
  readonly observationSource: string
  readonly ledgerBoundsLabel: string
}

export interface ObservationFreshnessReport {
  readonly state: 'fresh' | 'stale' | 'unverified'
  readonly summary: string
}

export interface SourceDisagreementItem {
  readonly id: string
  readonly sources: readonly [string, string]
  readonly summary: string
}

export interface TimelineObservationAnalysis {
  readonly stageAnnotations: Readonly<Record<TimelineStageId, TimelineStageAnnotation>>
  readonly freshness: ObservationFreshnessReport
  readonly disagreements: readonly SourceDisagreementItem[]
  readonly hasContradiction: boolean
}

const DEFAULT_MAX_OBSERVATION_AGE_MS = 5 * 60 * 1000
const DEFAULT_MAX_LEDGER_LAG = 120

const TIER_NAME_TO_NUM: Readonly<Record<string, number>> = Object.freeze({
  silent: 0,
  source: 1,
  seal: 2,
})

function normalizeDigest(value: string | null | undefined): string {
  if (typeof value !== 'string') return ''
  return value.trim().replace(/^0x/i, '').toLowerCase()
}

function formatLedgerBounds(
  bounds: TimelineLedgerBounds | null | undefined,
  offline: boolean,
): string {
  if (offline) return 'Offline (no ledger read)'
  if (!bounds) return 'Unbounded ledger window'
  const min =
    typeof bounds.minLedger === 'number' && Number.isInteger(bounds.minLedger)
      ? bounds.minLedger
      : null
  const max =
    typeof bounds.maxLedger === 'number' && Number.isInteger(bounds.maxLedger)
      ? bounds.maxLedger
      : null
  const observed =
    typeof bounds.observedLedger === 'number' && Number.isInteger(bounds.observedLedger)
      ? bounds.observedLedger
      : null

  if (min !== null && max !== null) {
    return min === max ? `Ledger #${min}` : `Ledger #${min}..#${max}`
  }
  if (observed !== null && max !== null) {
    return `Observed at ledger #${observed} (head #${max})`
  }
  if (observed !== null) {
    return `Observed at ledger #${observed}`
  }
  if (min !== null) {
    return `From ledger #${min}`
  }
  if (max !== null) {
    return `Through ledger #${max}`
  }
  return 'Unbounded ledger window'
}

/**
 * Computes per-stage observation sources, ledger bounds, observation freshness,
 * and cross-source disagreements while keeping stale evidence strictly separate
 * from contradictory source observations.
 */
export function analyzeTimelineObservations(
  input: AnalyzeTimelineObservationsInput,
): TimelineObservationAnalysis {
  const offline = Boolean(input.offline)
  const chainLedgerLabel = formatLedgerBounds(input.ledgerBounds, offline)

  const stageAnnotations: Readonly<Record<TimelineStageId, TimelineStageAnnotation>> =
    Object.freeze({
      input: Object.freeze({
        stageId: 'input',
        observationSource: 'Local browser intake',
        ledgerBoundsLabel: 'Session-local (pre-ledger)',
      }),
      hash: Object.freeze({
        stageId: 'hash',
        observationSource: 'Browser Web Crypto SHA-256',
        ledgerBoundsLabel: 'Deterministic local digest',
      }),
      database: Object.freeze({
        stageId: 'database',
        observationSource: offline
          ? 'Skipped (offline mode)'
          : 'NeonDB proof event index',
        ledgerBoundsLabel: offline
          ? 'Offline (no index query)'
          : input.observedAtIso
            ? `Indexed through ${input.observedAtIso}`
            : 'Live event feed window',
      }),
      chain: Object.freeze({
        stageId: 'chain',
        observationSource: offline
          ? 'Skipped (offline mode)'
          : 'Soroban HarpocratesRegistry',
        ledgerBoundsLabel: chainLedgerLabel,
      }),
      decision: Object.freeze({
        stageId: 'decision',
        observationSource: offline
          ? 'Local envelope evaluator'
          : 'Multi-source portal corroborator',
        ledgerBoundsLabel: chainLedgerLabel,
      }),
    })

  // Evaluate freshness independently from source agreement
  const maxAgeMs = input.maxObservationAgeMs ?? DEFAULT_MAX_OBSERVATION_AGE_MS
  const nowMs = input.nowMs ?? Date.now()
  const observedMs =
    input.observedAtIso && !Number.isNaN(Date.parse(input.observedAtIso))
      ? Date.parse(input.observedAtIso)
      : null
  const ageExceeded = observedMs !== null && nowMs - observedMs > maxAgeMs

  const maxLag = input.ledgerBounds?.maxLedgerLag ?? DEFAULT_MAX_LEDGER_LAG
  const ledgerLagExceeded =
    typeof input.ledgerBounds?.maxLedger === 'number' &&
    typeof input.ledgerBounds?.observedLedger === 'number' &&
    input.ledgerBounds.maxLedger - input.ledgerBounds.observedLedger > maxLag

  const isStale = Boolean(input.isStaleObservation) || ageExceeded || ledgerLagExceeded

  let freshness: ObservationFreshnessReport
  if (offline) {
    freshness = Object.freeze({
      state: 'unverified',
      summary:
        'Live observation freshness was not checked in offline mode.',
    })
  } else if (isStale) {
    freshness = Object.freeze({
      state: 'stale',
      summary:
        'Stale observation: one or more snapshots exceed the freshness window or ledger lag bound. Re-query live sources; staleness reflects aged data rather than contradictory evidence.',
    })
  } else if (input.chainProof || input.events.length > 0 || observedMs !== null) {
    freshness = Object.freeze({
      state: 'fresh',
      summary: input.observedAtIso
        ? `Fresh observation within configured bounds (${input.observedAtIso}).`
        : 'Fresh observation within active portal session.',
    })
  } else {
    freshness = Object.freeze({
      state: 'unverified',
      summary: 'Awaiting live source observations.',
    })
  }

  // Evaluate contradictory observations across sources independently of staleness
  const disagreements: SourceDisagreementItem[] = []
  const normalizedHash = normalizeDigest(input.verifyHash)

  if (input.errorCode === 'METADATA_ENVELOPE_MISMATCH') {
    disagreements.push(
      Object.freeze({
        id: 'envelope-vs-chain-metadata',
        sources: Object.freeze([
          'Embedded artifact envelope',
          'Soroban HarpocratesRegistry',
        ] as const),
        summary:
          'Contradictory observation: embedded metadata commitment disagrees with the on-chain metadata envelope.',
      }),
    )
  }

  if (normalizedHash && input.chainProof) {
    const chainHash = normalizeDigest(input.chainProof.videoHash)
    if (chainHash && chainHash !== normalizedHash) {
      disagreements.push(
        Object.freeze({
          id: 'local-hash-vs-chain-hash',
          sources: Object.freeze([
            'Browser Web Crypto SHA-256',
            'Soroban HarpocratesRegistry',
          ] as const),
          summary:
            'Contradictory observation: local artifact SHA-256 digest differs from the returned Soroban proof record digest.',
        }),
      )
    }
  }

  if (input.chainProof && input.events.length > 0) {
    const matchingEvents = normalizedHash
      ? input.events.filter(
          (ev) => normalizeDigest(ev.video_hash) === normalizedHash,
        )
      : input.events

    for (const ev of matchingEvents) {
      const expectedTier = ev.tier ? TIER_NAME_TO_NUM[ev.tier] : undefined
      if (expectedTier !== undefined && expectedTier !== input.chainProof.tier) {
        disagreements.push(
          Object.freeze({
            id: `db-vs-chain-tier-${ev.id}`,
            sources: Object.freeze([
              'NeonDB proof event index',
              'Soroban HarpocratesRegistry',
            ] as const),
            summary: `Contradictory observation: NeonDB event #${ev.id} reports tier "${ev.tier}" while Soroban records tier ${input.chainProof.tier}.`,
          }),
        )
      }
      const evProofId = normalizeDigest(ev.proof_id)
      const chainProofId = normalizeDigest(input.chainProof.proofId)
      if (evProofId && chainProofId && evProofId !== chainProofId) {
        disagreements.push(
          Object.freeze({
            id: `db-vs-chain-proof-id-${ev.id}`,
            sources: Object.freeze([
              'NeonDB proof event index',
              'Soroban HarpocratesRegistry',
            ] as const),
            summary: `Contradictory observation: NeonDB event #${ev.id} proof ID disagrees with the Soroban registry proof ID.`,
          }),
        )
      }
    }
  }

  if (
    !offline &&
    !input.chainProof &&
    input.status !== 'verifying' &&
    input.status !== 'hashing' &&
    input.events.some((ev) => Boolean(ev.tx_hash))
  ) {
    disagreements.push(
      Object.freeze({
        id: 'db-anchored-tx-missing-on-chain',
        sources: Object.freeze([
          'NeonDB proof event index',
          'Soroban HarpocratesRegistry',
        ] as const),
        summary:
          'Contradictory observation: NeonDB lists an anchored Stellar transaction, but Soroban returned no matching registry record.',
      }),
    )
  }

  for (const mismatch of input.provenanceMismatches ?? []) {
    disagreements.push(
      Object.freeze({
        id: `provenance-mismatch-${mismatch.field}`,
        sources: Object.freeze([
          'Portable proof manifest',
          'Soroban HarpocratesRegistry',
        ] as const),
        summary: `Contradictory observation: manifest ${mismatch.field} disagrees with the Soroban registry value.`,
      }),
    )
  }

  const frozenDisagreements = Object.freeze(disagreements)

  return Object.freeze({
    stageAnnotations,
    freshness,
    disagreements: frozenDisagreements,
    hasContradiction: frozenDisagreements.length > 0,
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
