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

export interface VerificationExportPreviewField {
  readonly key: string
  readonly label: string
  readonly value: string
}

export interface VerificationUnresolvedCheck {
  readonly id: string
  readonly label: string
  readonly reason: string
}

export type ExportFreshnessState = 'fresh' | 'stale' | 'unverified'

export interface VerificationExportPreviewInput {
  readonly statementHash: string
  readonly proofId?: string | null
  readonly metadataHash?: string | null
  readonly status: string
  readonly verdictSummary: string
  readonly errorCode?: string | null
  readonly networkPassphrase: string
  readonly contractId: string
  readonly offline: boolean
  readonly networkMismatch?: string | null
  readonly chainProof: ChainProofRecord | null
  readonly events: readonly ProofEvent[]
  readonly observedAtIso?: string | null
  readonly isStaleObservation?: boolean
  readonly reviewedAtIso?: string
}

export interface FrozenReviewedVerificationExport {
  readonly protocol: 'harpocrates-verification-export'
  readonly schemaVersion: 1
  readonly reviewedAtIso: string
  readonly snapshotFingerprint: string
  readonly statementHash: string
  readonly proofId: string | null
  readonly metadataHash: string | null
  readonly verificationStatus: string
  readonly verdictSummary: string
  readonly freshness: {
    readonly state: ExportFreshnessState
    readonly label: string
    readonly observedAtIso: string | null
  }
  readonly trustContext: {
    readonly networkPassphrase: string
    readonly contractId: string
    readonly offline: boolean
    readonly chainStatusLabel: string
    readonly issuer: string | null
    readonly corroboratedEventCount: number
  }
  readonly includedFields: readonly VerificationExportPreviewField[]
  readonly unresolvedChecks: readonly VerificationUnresolvedCheck[]
}

function normalizeOptionalString(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

function describeChainStatus(
  offline: boolean,
  chainProof: ChainProofRecord | null,
): string {
  if (offline) return 'Not checked (offline)'
  if (!chainProof) return 'Not loaded'
  if (chainProof.status === 2) return 'Revoked'
  if (chainProof.status === 3) return 'Expired'
  return 'Confirmed'
}

export function computeExportContextFingerprint(
  input: VerificationExportPreviewInput,
): string {
  return JSON.stringify({
    statementHash: input.statementHash.trim().toLowerCase(),
    proofId: normalizeOptionalString(input.proofId)?.toLowerCase() ?? null,
    metadataHash: normalizeOptionalString(input.metadataHash)?.toLowerCase() ?? null,
    status: input.status,
    verdictSummary: input.verdictSummary,
    errorCode: input.errorCode ?? null,
    networkPassphrase: input.networkPassphrase.trim(),
    contractId: input.contractId.trim(),
    offline: Boolean(input.offline),
    networkMismatch: normalizeOptionalString(input.networkMismatch),
    chainStatus: input.chainProof?.status ?? null,
    issuer: normalizeOptionalString(input.chainProof?.issuer),
    eventCount: input.events.length,
    observedAtIso: normalizeOptionalString(input.observedAtIso),
    isStaleObservation: Boolean(input.isStaleObservation),
  })
}

/**
 * Captures and deep-freezes an immutable snapshot of the user-reviewed
 * verification result, including explicit field inventory, freshness state,
 * and unresolved checks. Never contacts network endpoints or includes private
 * filenames/notes.
 */
export function freezeReviewedVerificationExport(
  input: VerificationExportPreviewInput,
): FrozenReviewedVerificationExport {
  const statementHash = input.statementHash.trim().toLowerCase()
  const proofId = normalizeOptionalString(input.proofId)
  const metadataHash =
    normalizeOptionalString(input.metadataHash) ??
    normalizeOptionalString(input.chainProof?.metadataHash)
  const networkPassphrase = input.networkPassphrase.trim()
  const contractId = input.contractId.trim()
  const offline = Boolean(input.offline)
  const chainStatusLabel = describeChainStatus(offline, input.chainProof)
  const issuer = normalizeOptionalString(input.chainProof?.issuer)
  const corroboratedEventCount = offline ? 0 : input.events.length
  const observedAtIso =
    normalizeOptionalString(input.observedAtIso) ??
    (input.chainProof?.createdAt
      ? new Date(Number(input.chainProof.createdAt) * 1000).toISOString()
      : null)
  const reviewedAtIso =
    normalizeOptionalString(input.reviewedAtIso) ?? new Date().toISOString()

  let freshnessState: ExportFreshnessState = 'unverified'
  let freshnessLabel = 'Unverified live freshness (incomplete or offline check)'
  if (input.isStaleObservation) {
    freshnessState = 'stale'
    freshnessLabel = 'Stale registry observation — captured earlier and not refreshed'
  } else if (
    !offline &&
    input.status === 'success' &&
    input.chainProof?.status === 1 &&
    !normalizeOptionalString(input.networkMismatch)
  ) {
    freshnessState = 'fresh'
    freshnessLabel = observedAtIso
      ? `Fresh online registry observation (${observedAtIso})`
      : 'Fresh online registry observation'
  } else if (offline) {
    freshnessState = 'unverified'
    freshnessLabel = 'Offline local inspection only — live registry freshness not checked'
  }

  const unresolvedList: VerificationUnresolvedCheck[] = []
  if (offline) {
    unresolvedList.push(
      Object.freeze({
        id: 'soroban-registry-check',
        label: 'Soroban registry standing',
        reason: 'Skipped in offline mode; revocation and expiry were not checked on-chain.',
      }),
      Object.freeze({
        id: 'neondb-event-corroboration',
        label: 'NeonDB event corroboration',
        reason: 'Skipped in offline mode; backend proof events were not queried.',
      }),
    )
  } else {
    if (!input.chainProof) {
      unresolvedList.push(
        Object.freeze({
          id: 'soroban-registry-record',
          label: 'Soroban registry record',
          reason: 'No on-chain proof record was loaded for this statement.',
        }),
      )
    }
    if (input.events.length === 0) {
      unresolvedList.push(
        Object.freeze({
          id: 'neondb-event-corroboration',
          label: 'NeonDB event corroboration',
          reason: 'No corroborated proof events were returned for this statement.',
        }),
      )
    }
  }

  const mismatch = normalizeOptionalString(input.networkMismatch)
  if (mismatch) {
    unresolvedList.push(
      Object.freeze({
        id: 'wallet-network-alignment',
        label: 'Wallet network alignment',
        reason: mismatch,
      }),
    )
  }

  if (!metadataHash) {
    unresolvedList.push(
      Object.freeze({
        id: 'metadata-commitment',
        label: 'Metadata commitment digest',
        reason: 'Public metadata commitment digest was not resolved.',
      }),
    )
  }

  if (input.status !== 'success') {
    unresolvedList.push(
      Object.freeze({
        id: 'terminal-verification-decision',
        label: 'Confirmed verification decision',
        reason: input.errorCode
          ? `Verification ended with error code ${input.errorCode}.`
          : `Verification status is "${input.status}".`,
      }),
    )
  }

  const includedFields: readonly VerificationExportPreviewField[] = Object.freeze([
    Object.freeze({
      key: 'statementHash',
      label: 'Statement video hash',
      value: statementHash || 'Unavailable',
    }),
    Object.freeze({
      key: 'proofId',
      label: 'Proof ID',
      value: proofId ?? 'Unavailable',
    }),
    Object.freeze({
      key: 'metadataHash',
      label: 'Metadata commitment',
      value: metadataHash ?? 'Unavailable',
    }),
    Object.freeze({
      key: 'verificationStatus',
      label: 'Verification status',
      value: input.status,
    }),
    Object.freeze({
      key: 'verdictSummary',
      label: 'Reviewed verdict',
      value: input.verdictSummary,
    }),
    Object.freeze({
      key: 'networkPassphrase',
      label: 'Stellar network',
      value: networkPassphrase || 'Unconfigured',
    }),
    Object.freeze({
      key: 'contractId',
      label: 'Registry contract ID',
      value: contractId || 'Unconfigured',
    }),
    Object.freeze({
      key: 'verificationMode',
      label: 'Verification mode',
      value: offline ? 'offline-local' : 'online-registry',
    }),
    Object.freeze({
      key: 'chainStatusLabel',
      label: 'Chain standing',
      value: chainStatusLabel,
    }),
    Object.freeze({
      key: 'corroboratedEventCount',
      label: 'Corroborated events',
      value: String(corroboratedEventCount),
    }),
  ])

  const unresolvedChecks: readonly VerificationUnresolvedCheck[] =
    Object.freeze(unresolvedList)

  const freshness = Object.freeze({
    state: freshnessState,
    label: freshnessLabel,
    observedAtIso,
  })

  const trustContext = Object.freeze({
    networkPassphrase,
    contractId,
    offline,
    chainStatusLabel,
    issuer,
    corroboratedEventCount,
  })

  return Object.freeze({
    protocol: 'harpocrates-verification-export' as const,
    schemaVersion: 1 as const,
    reviewedAtIso,
    snapshotFingerprint: computeExportContextFingerprint(input),
    statementHash,
    proofId,
    metadataHash,
    verificationStatus: input.status,
    verdictSummary: input.verdictSummary,
    freshness,
    trustContext,
    includedFields,
    unresolvedChecks,
  })
}

/**
 * Serializes ONLY the previously reviewed frozen export snapshot.
 * Guarantees zero silent trust-context refresh and zero network I/O.
 */
export function serializeReviewedVerificationExport(
  frozenSnapshot: FrozenReviewedVerificationExport,
): string {
  const payload = {
    protocol: frozenSnapshot.protocol,
    schemaVersion: frozenSnapshot.schemaVersion,
    reviewedAtIso: frozenSnapshot.reviewedAtIso,
    statementHash: frozenSnapshot.statementHash,
    proofId: frozenSnapshot.proofId,
    metadataHash: frozenSnapshot.metadataHash,
    verificationStatus: frozenSnapshot.verificationStatus,
    verdictSummary: frozenSnapshot.verdictSummary,
    freshness: frozenSnapshot.freshness,
    trustContext: frozenSnapshot.trustContext,
    includedFieldKeys: frozenSnapshot.includedFields.map((field) => field.key),
    unresolvedChecks: frozenSnapshot.unresolvedChecks,
  }
  return JSON.stringify(payload, null, 2)
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
