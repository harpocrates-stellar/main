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

export type StaleSnapshotReasonCode =
  | 'MISSING_SNAPSHOT'
  | 'STATEMENT_CHANGED'
  | 'NETWORK_CONTEXT_CHANGED'
  | 'CONTRACT_CONTEXT_CHANGED'
  | 'VERIFICATION_MODE_CHANGED'
  | 'TRUST_STANDING_CHANGED'

export interface StatementAndTrustSnapshotInput {
  readonly videoHash: string
  readonly proofId?: string | null
  readonly metadataHash?: string | null
  readonly networkPassphrase: string
  readonly contractId: string
  readonly offline: boolean
  readonly networkMismatch?: string | null
  readonly chainStatus?: number | null
  readonly issuer?: string | null
}

export interface VerificationResultSnapshotBinding {
  readonly snapshotKey: string
  readonly statementIdentity: {
    readonly videoHash: string
    readonly proofId: string
    readonly metadataHash: string
  }
  readonly trustContextIdentity: {
    readonly networkPassphrase: string
    readonly contractId: string
    readonly offline: boolean
    readonly hasNetworkMismatch: boolean
    readonly chainStatus: number | null
    readonly issuer: string
  }
}

export type CachedVerificationFreshness =
  | { readonly fresh: true; readonly reason: null; readonly message: null }
  | {
      readonly fresh: false
      readonly reason: StaleSnapshotReasonCode
      readonly message: string
    }

function normalizeIdentityField(value: string | null | undefined): string {
  if (typeof value !== 'string') return ''
  return value.trim().replace(/^0x/i, '').toLowerCase()
}

function normalizeCaseSensitiveField(value: string | null | undefined): string {
  if (typeof value !== 'string') return ''
  return value.trim()
}

/**
 * Binds a completed verification result to both its public statement identity
 * (`videoHash`, `proofId`, `metadataHash`) and the active trust snapshot
 * (`networkPassphrase`, `contractId`, `offline`, `chainStatus`, `issuer`).
 */
export function createVerificationResultSnapshotBinding(
  input: StatementAndTrustSnapshotInput,
): VerificationResultSnapshotBinding {
  const statementIdentity = Object.freeze({
    videoHash: normalizeIdentityField(input.videoHash),
    proofId: normalizeIdentityField(input.proofId),
    metadataHash: normalizeIdentityField(input.metadataHash),
  })

  const trustContextIdentity = Object.freeze({
    networkPassphrase: normalizeCaseSensitiveField(input.networkPassphrase),
    contractId: normalizeCaseSensitiveField(input.contractId),
    offline: Boolean(input.offline),
    hasNetworkMismatch: Boolean(input.networkMismatch && input.networkMismatch.trim()),
    chainStatus: input.chainStatus ?? null,
    issuer: normalizeCaseSensitiveField(input.issuer),
  })

  const snapshotKey = JSON.stringify({
    s: statementIdentity,
    t: trustContextIdentity,
  })

  return Object.freeze({
    snapshotKey,
    statementIdentity,
    trustContextIdentity,
  })
}

const STALE_SNAPSHOT_MESSAGES: Readonly<Record<StaleSnapshotReasonCode, string>> =
  Object.freeze({
    MISSING_SNAPSHOT:
      'Cached verification result lacks a bound trust snapshot. Run a fresh verification check.',
    STATEMENT_CHANGED:
      'Statement inputs changed since the last check. Run a fresh verification before trusting this artifact.',
    NETWORK_CONTEXT_CHANGED:
      'Stellar network context changed since the last check. Run a fresh verification on the active network.',
    CONTRACT_CONTEXT_CHANGED:
      'Registry contract context changed since the last check. Run a fresh verification.',
    VERIFICATION_MODE_CHANGED:
      'Verification mode switched between online and offline. Run a fresh check in the selected mode.',
    TRUST_STANDING_CHANGED:
      'Chain or issuer trust standing changed since the last check. Run a fresh verification.',
  })

/**
 * Evaluates whether a cached success result remains valid for the currently
 * displayed statement and trust context. Fails closed on any incompatible change.
 */
export function evaluateCachedVerificationFreshness(
  boundSnapshot: VerificationResultSnapshotBinding | null,
  currentInput: StatementAndTrustSnapshotInput,
): CachedVerificationFreshness {
  if (!boundSnapshot) {
    return Object.freeze({
      fresh: false,
      reason: 'MISSING_SNAPSHOT',
      message: STALE_SNAPSHOT_MESSAGES.MISSING_SNAPSHOT,
    })
  }

  const current = createVerificationResultSnapshotBinding(currentInput)

  if (
    current.statementIdentity.videoHash !== boundSnapshot.statementIdentity.videoHash ||
    current.statementIdentity.proofId !== boundSnapshot.statementIdentity.proofId ||
    current.statementIdentity.metadataHash !== boundSnapshot.statementIdentity.metadataHash
  ) {
    return Object.freeze({
      fresh: false,
      reason: 'STATEMENT_CHANGED',
      message: STALE_SNAPSHOT_MESSAGES.STATEMENT_CHANGED,
    })
  }

  if (
    current.trustContextIdentity.hasNetworkMismatch ||
    current.trustContextIdentity.networkPassphrase !==
      boundSnapshot.trustContextIdentity.networkPassphrase
  ) {
    return Object.freeze({
      fresh: false,
      reason: 'NETWORK_CONTEXT_CHANGED',
      message: STALE_SNAPSHOT_MESSAGES.NETWORK_CONTEXT_CHANGED,
    })
  }

  if (
    current.trustContextIdentity.contractId !==
    boundSnapshot.trustContextIdentity.contractId
  ) {
    return Object.freeze({
      fresh: false,
      reason: 'CONTRACT_CONTEXT_CHANGED',
      message: STALE_SNAPSHOT_MESSAGES.CONTRACT_CONTEXT_CHANGED,
    })
  }

  if (current.trustContextIdentity.offline !== boundSnapshot.trustContextIdentity.offline) {
    return Object.freeze({
      fresh: false,
      reason: 'VERIFICATION_MODE_CHANGED',
      message: STALE_SNAPSHOT_MESSAGES.VERIFICATION_MODE_CHANGED,
    })
  }

  if (
    current.trustContextIdentity.chainStatus !==
      boundSnapshot.trustContextIdentity.chainStatus ||
    current.trustContextIdentity.issuer !== boundSnapshot.trustContextIdentity.issuer
  ) {
    return Object.freeze({
      fresh: false,
      reason: 'TRUST_STANDING_CHANGED',
      message: STALE_SNAPSHOT_MESSAGES.TRUST_STANDING_CHANGED,
    })
  }

  return Object.freeze({
    fresh: true,
    reason: null,
    message: null,
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
