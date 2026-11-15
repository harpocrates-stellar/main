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

export type StaleRevisionReason =
  | 'REQUEST_CANCELLED'
  | 'SUPERSEDED_BY_NEWER_SELECTION'
  | 'STALE_REVISION'

export interface VerificationRequestTicket {
  readonly revision: number
  readonly selectionKey: string
  readonly controller: AbortController
}

export type RevisionCommitCheck =
  | { readonly allowed: true; readonly reason: null }
  | { readonly allowed: false; readonly reason: StaleRevisionReason }

export interface VerificationRevisionGate {
  beginRequest(selectionKey: string): VerificationRequestTicket
  selectEvidence(selectionKey: string): number
  cancelActive(): number
  reset(): number
  canCommit(ticket: Pick<VerificationRequestTicket, 'revision' | 'selectionKey'>): RevisionCommitCheck
  currentRevision(): number
  activeSelection(): string
}

function normalizeSelectionKey(selectionKey: string): string {
  return selectionKey.trim().toLowerCase()
}

/**
 * Monotonic request-revision coordinator that binds asynchronous verification
 * operations to both a monotonic request revision and the active evidence
 * selection identity. Cancelled or superseded requests can never overwrite a
 * newer selection when their promises settle late.
 */
export function createVerificationRevisionGate(): VerificationRevisionGate {
  let revision = 0
  let activeSelectionKey = ''
  let activeController: AbortController | null = null
  const cancelledRevisions = new Set<number>()

  return {
    beginRequest(selectionKey: string): VerificationRequestTicket {
      activeController?.abort()
      revision += 1
      const normalized = normalizeSelectionKey(selectionKey)
      activeSelectionKey = normalized
      const controller = new AbortController()
      activeController = controller
      return Object.freeze({
        revision,
        selectionKey: normalized,
        controller,
      })
    },

    selectEvidence(selectionKey: string): number {
      activeController?.abort()
      activeController = null
      revision += 1
      activeSelectionKey = normalizeSelectionKey(selectionKey)
      return revision
    },

    cancelActive(): number {
      if (revision > 0) {
        cancelledRevisions.add(revision)
      }
      activeController?.abort()
      activeController = null
      revision += 1
      return revision
    },

    reset(): number {
      if (revision > 0) {
        cancelledRevisions.add(revision)
      }
      activeController?.abort()
      activeController = null
      revision += 1
      activeSelectionKey = ''
      return revision
    },

    canCommit(
      ticket: Pick<VerificationRequestTicket, 'revision' | 'selectionKey'>,
    ): RevisionCommitCheck {
      if (cancelledRevisions.has(ticket.revision)) {
        return Object.freeze({
          allowed: false,
          reason: 'REQUEST_CANCELLED',
        })
      }
      const normalizedTicketSelection = normalizeSelectionKey(ticket.selectionKey)
      if (
        activeSelectionKey &&
        normalizedTicketSelection &&
        normalizedTicketSelection !== activeSelectionKey
      ) {
        return Object.freeze({
          allowed: false,
          reason: 'SUPERSEDED_BY_NEWER_SELECTION',
        })
      }
      if (ticket.revision !== revision) {
        return Object.freeze({
          allowed: false,
          reason: activeSelectionKey !== normalizedTicketSelection
            ? 'SUPERSEDED_BY_NEWER_SELECTION'
            : 'STALE_REVISION',
        })
      }
      return Object.freeze({
        allowed: true,
        reason: null,
      })
    },

    currentRevision(): number {
      return revision
    },

    activeSelection(): string {
      return activeSelectionKey
    },
  }
}

export type RevisionBoundFlowOutcome =
  | {
      readonly committed: true
      readonly revision: number
      readonly result: VerificationResult
    }
  | {
      readonly committed: false
      readonly revision: number
      readonly ignoredReason: StaleRevisionReason
    }

/**
 * Executes `runVerificationFlow` bound to a revision ticket and ignores late
 * results if the request was cancelled or superseded by a newer selection.
 */
export async function runRevisionBoundVerificationFlow(
  gate: VerificationRevisionGate,
  videoHash: string,
  options: { sourceAddress?: string } = {},
): Promise<RevisionBoundFlowOutcome> {
  const safeHash = assertValidVideoHash(videoHash)
  const ticket = gate.beginRequest(safeHash)
  try {
    const result = await runVerificationFlow(safeHash, {
      signal: ticket.controller.signal,
      sourceAddress: options.sourceAddress,
    })
    const commitCheck = gate.canCommit(ticket)
    if (!commitCheck.allowed) {
      return Object.freeze({
        committed: false,
        revision: ticket.revision,
        ignoredReason: commitCheck.reason,
      })
    }
    return Object.freeze({
      committed: true,
      revision: ticket.revision,
      result,
    })
  } catch (error) {
    const commitCheck = gate.canCommit(ticket)
    if (!commitCheck.allowed) {
      return Object.freeze({
        committed: false,
        revision: ticket.revision,
        ignoredReason: commitCheck.reason,
      })
    }
    throw error
  }
}

/**
 * Executes `verifyUploadedVideo` bound to a revision ticket so cancelling or
 * changing the selected file discards late async extraction/chain responses.
 */
export async function runRevisionBoundUploadedVideoVerification(
  gate: VerificationRevisionGate,
  file: File,
  videoHash: string,
  options: { sourceAddress?: string } = {},
): Promise<RevisionBoundFlowOutcome> {
  const safeHash = assertValidVideoHash(videoHash)
  const ticket = gate.beginRequest(
    `upload:${safeHash}:${file.name}:${file.size}:${file.lastModified}`,
  )
  try {
    const result = await verifyUploadedVideo(file, safeHash, {
      signal: ticket.controller.signal,
      sourceAddress: options.sourceAddress,
    })
    const commitCheck = gate.canCommit(ticket)
    if (!commitCheck.allowed) {
      return Object.freeze({
        committed: false,
        revision: ticket.revision,
        ignoredReason: commitCheck.reason,
      })
    }
    return Object.freeze({
      committed: true,
      revision: ticket.revision,
      result,
    })
  } catch (error) {
    const commitCheck = gate.canCommit(ticket)
    if (!commitCheck.allowed) {
      return Object.freeze({
        committed: false,
        revision: ticket.revision,
        ignoredReason: commitCheck.reason,
      })
    }
    throw error
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
