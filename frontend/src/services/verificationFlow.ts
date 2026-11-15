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

export type VerificationResultTabId = 'summary' | 'chain' | 'corroboration'

export interface StatementIdentityResolutionInput {
  readonly verifyHash: string
  readonly videoHashInput?: string
  readonly proofIdInput?: string
  readonly events: readonly ProofEvent[]
  readonly chainProof: ChainProofRecord | null
  readonly metadataHashOverride?: string | null
}

export interface ResolvedVerifiedStatementIdentity {
  readonly statementKey: string
  readonly statementDigest: string
  readonly proofId: string | null
  readonly metadataHash: string | null
  readonly chainSource: string | null
  readonly matchingEvents: readonly ProofEvent[]
}

function normalizeHexDigest(value: string | null | undefined): string {
  if (typeof value !== 'string') return ''
  return value.trim().replace(/^0x/i, '').toLowerCase()
}

function normalizeProofId(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.startsWith('0x') || trimmed.startsWith('0X')
    ? `0x${trimmed.slice(2).toLowerCase()}`
    : trimmed.toLowerCase()
}

/**
 * Resolves a single canonical statement digest and proof identity shared across
 * all verification result tabs and panels. Never borrows proof identifiers from
 * events belonging to a different statement digest.
 */
export function resolveVerifiedStatementIdentity(
  input: StatementIdentityResolutionInput,
): ResolvedVerifiedStatementIdentity {
  const verifiedDigest = normalizeHexDigest(input.verifyHash)
  const typedDigest = normalizeHexDigest(input.videoHashInput)
  const chainDigest = normalizeHexDigest(input.chainProof?.videoHash)

  // Prefer the active verified digest when present; fall back to chain or form input
  const statementDigest = verifiedDigest || chainDigest || typedDigest

  const matchingEvents = statementDigest
    ? Object.freeze(
        input.events.filter(
          (event) => normalizeHexDigest(event.video_hash) === statementDigest,
        ),
      )
    : Object.freeze([] as ProofEvent[])

  const matchedEventProofId = normalizeProofId(
    matchingEvents.find((event) => Boolean(event.proof_id))?.proof_id,
  )
  const typedProofId =
    !verifiedDigest || !typedDigest || typedDigest === statementDigest
      ? normalizeProofId(input.proofIdInput)
      : null

  const chainProofId =
    input.chainProof && (!statementDigest || chainDigest === statementDigest)
      ? normalizeProofId(input.chainProof.proofId)
      : null

  const proofId = matchedEventProofId ?? chainProofId ?? typedProofId

  const chainMatchesStatement =
    Boolean(input.chainProof) &&
    (!statementDigest || chainDigest === statementDigest)

  const metadataHash =
    (chainMatchesStatement
      ? normalizeHexDigest(input.chainProof?.metadataHash)
      : '') ||
    normalizeHexDigest(input.metadataHashOverride) ||
    null

  const chainSource =
    chainMatchesStatement && input.chainProof?.source
      ? input.chainProof.source.trim()
      : null

  const statementKey = statementDigest || '__empty_statement__'

  return Object.freeze({
    statementKey,
    statementDigest,
    proofId,
    metadataHash,
    chainSource,
    matchingEvents,
  })
}

/**
 * Determines whether dependent tab views and selections must reset because the
 * underlying verified statement digest changed.
 */
export function shouldResetDependentTabState(
  previousStatementKey: string,
  nextStatementKey: string,
): boolean {
  return previousStatementKey !== nextStatementKey
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
