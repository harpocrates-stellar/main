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

export type VerificationFlowOptions = {
  signal?: AbortSignal
  sourceAddress?: string
  /** Optional monotonic request revision bound to the returned result. */
  revision?: number
}

export type VerificationResult = {
  videoHash: string
  hasHarpocratesMetadata: boolean
  events: ProofEvent[]
  onChain: ChainProofRecord | null
  /** Request revision supplied by the caller, when revision-bound. */
  revision?: number
}

/**
 * Tracks monotonically increasing verification request revisions so late
 * asynchronous results from cancelled or superseded selections can be ignored.
 */
export type VerificationRevisionGuard = {
  /** Advance to a new active revision and return its identifier. */
  next: () => number
  /** Invalidate any in-flight revision (e.g. on cancel or clear) and return the new revision. */
  invalidate: () => number
  /** Return the current revision identifier. */
  current: () => number
  /** True only when `revision` is still the active revision. */
  isCurrent: (revision: number) => boolean
}

export function createVerificationRevisionGuard(): VerificationRevisionGuard {
  let activeRevision = 0
  return {
    next() {
      activeRevision += 1
      return activeRevision
    },
    invalidate() {
      activeRevision += 1
      return activeRevision
    },
    current() {
      return activeRevision
    },
    isCurrent(revision: number) {
      return revision > 0 && revision === activeRevision
    },
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new DOMException('Aborted', 'AbortError')
  }
}

export type VerificationResultTabId = 'summary' | 'chain' | 'corroboration'

export interface StatementIdentityResolutionInput {
  verifyHash?: string | null
  videoHashInput?: string | null
  proofIdInput?: string | null
  events?: ProofEvent[] | null
  chainProof?: ChainProofRecord | null
}

export interface ResolvedVerifiedStatementIdentity {
  statementDigest: string
  statementKey: string
  proofId: string | null
  metadataHash: string | null
  chainSource: string | null
  matchingEvents: ProofEvent[]
}

function normalizeDigest(value?: string | null): string {
  if (!value) return ''
  const trimmed = value.trim()
  if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
    return trimmed.slice(2).toLowerCase()
  }
  return trimmed.toLowerCase()
}

function normalizeProofId(value?: string | null): string | null {
  if (!value) return null
  const trimmed = value.trim()
  if (!trimmed) return null
  if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
    return `0x${trimmed.slice(2).toLowerCase()}`
  }
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return `0x${trimmed.toLowerCase()}`
  }
  return trimmed
}

export function shouldResetDependentTabState(
  previousStatementKey: string,
  nextStatementKey: string,
): boolean {
  return previousStatementKey !== nextStatementKey
}

export function resolveVerifiedStatementIdentity(
  input: StatementIdentityResolutionInput,
): ResolvedVerifiedStatementIdentity {
  const statementDigest = normalizeDigest(input.verifyHash)
  const statementKey = statementDigest || '__empty_statement__'

  if (!statementDigest) {
    return {
      statementDigest: '',
      statementKey: '__empty_statement__',
      proofId: null,
      metadataHash: null,
      chainSource: null,
      matchingEvents: [],
    }
  }

  const matchingEvents = (input.events || []).filter(
    (event) => normalizeDigest(event.video_hash) === statementDigest,
  )

  let resolvedProofId: string | null = null

  for (const event of matchingEvents) {
    if (event.proof_id && event.proof_id.trim()) {
      resolvedProofId = normalizeProofId(event.proof_id)
      break
    }
  }

  const chainProof = input.chainProof
  const chainMatches = !!(chainProof && normalizeDigest(chainProof.videoHash) === statementDigest)

  if (!resolvedProofId && chainMatches && chainProof?.proofId) {
    resolvedProofId = normalizeProofId(chainProof.proofId)
  }

  if (!resolvedProofId && input.proofIdInput) {
    const videoInput = normalizeDigest(input.videoHashInput)
    if (!videoInput || videoInput === statementDigest) {
      resolvedProofId = normalizeProofId(input.proofIdInput)
    }
  }

  const metadataHash = chainMatches && chainProof?.metadataHash ? chainProof.metadataHash : null
  const chainSource = chainMatches && chainProof?.source ? chainProof.source : null

  return {
    statementDigest,
    statementKey,
    proofId: resolvedProofId,
    metadataHash,
    chainSource,
    matchingEvents,
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
    onChain,
    trust: buildVerificationDimensions({
      hasHarpocratesMetadata,
      events,
      onChain,
      issuerRecord: options.issuerRecord,
      nowUnixSeconds: options.nowUnixSeconds,
    }),
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
