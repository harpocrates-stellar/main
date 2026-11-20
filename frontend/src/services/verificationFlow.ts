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
    hasHarpocratesMetadata: events.length > 0,
    events,
    onChain: onChain,
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
  return { ...result, hasHarpocratesMetadata: extract.hasHarpocratesMetadata }
}
