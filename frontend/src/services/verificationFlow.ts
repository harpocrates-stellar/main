/**
 * verificationFlow — orchestrates the verification portal flow.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single result. No React state.
 */

import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import type { VerificationErrorCode, VerificationStatus } from '../hooks/useVerification'
import { shortHash } from '../utils'
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

export type DetailSectionState = 'verified' | 'attention' | 'unavailable' | 'pending'

export type VerificationDetailSectionId =
  | 'public-input-checks'
  | 'chain-observations'
  | 'trust-reasons'

export interface VerificationDetailRow {
  readonly label: string
  readonly value: string
  readonly status: DetailSectionState
}

export interface VerificationDetailSection {
  readonly id: VerificationDetailSectionId
  readonly heading: string
  readonly summary: string
  readonly state: DetailSectionState
  readonly rows: readonly VerificationDetailRow[]
}

export interface VerificationDetailExplorerInput {
  readonly status: VerificationStatus
  readonly offline: boolean
  readonly verifyHash: string
  readonly proofId?: string | null
  readonly metadataHash?: string | null
  readonly events: readonly ProofEvent[]
  readonly chainProof: ChainProofRecord | null
  readonly errorCode: VerificationErrorCode | null
}

export interface VerificationDetailExplorerModel {
  readonly hasActiveInspection: boolean
  readonly sections: readonly [
    VerificationDetailSection,
    VerificationDetailSection,
    VerificationDetailSection,
  ]
}

const HEX_64_RE = /^(?:0x)?[0-9a-fA-F]{64}$/

function formatSafeDigest(digest: string | null | undefined): string {
  if (!digest || !digest.trim()) return 'Not provided'
  const normalized = digest.trim().replace(/^0x/i, '').toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    return 'Malformed digest format'
  }
  return shortHash(normalized)
}

function formatChainTier(tier: number | undefined): string {
  if (tier === 0) return 'Tier 0 (Silent Witness)'
  if (tier === 1) return 'Tier 1 (Source)'
  if (tier === 2) return 'Tier 2 (Seal)'
  return 'Unrecorded'
}

function formatChainStatusLabel(chainProof: ChainProofRecord | null, offline: boolean): string {
  if (offline) return 'Not checked (offline mode)'
  if (!chainProof) return 'No matching on-chain record'
  if (chainProof.status === 2) return 'Revoked on-chain'
  if (chainProof.status === 3) return 'Expired on-chain'
  return 'Registered on-chain'
}

/**
 * Builds a privacy-safe, deterministic 3-section model for the keyboard-accessible
 * verification detail explorer without exposing raw filenames or secret inputs.
 */
export function buildVerificationDetailExplorerModel(
  input: VerificationDetailExplorerInput,
): VerificationDetailExplorerModel {
  const {
    status,
    offline,
    verifyHash,
    proofId,
    metadataHash,
    events,
    chainProof,
    errorCode,
  } = input

  const hasHash = HEX_64_RE.test(verifyHash.trim())
  const resolvedProofId =
    proofId?.trim() ||
    events.find((ev) => Boolean(ev.proof_id))?.proof_id ||
    chainProof?.proofId ||
    null
  const resolvedMetadataHash = chainProof?.metadataHash ?? metadataHash ?? null
  const hasValidProofId = Boolean(resolvedProofId && HEX_64_RE.test(resolvedProofId))
  const metadataMismatch = errorCode === 'METADATA_ENVELOPE_MISMATCH'

  const hasActiveInspection =
    status !== 'idle' ||
    Boolean(verifyHash.trim()) ||
    events.length > 0 ||
    chainProof !== null

  // 1. Public-input checks
  const publicInputState: DetailSectionState = !hasActiveInspection
    ? 'pending'
    : metadataMismatch || errorCode === 'INVALID_EVIDENCE'
      ? 'attention'
      : hasHash
        ? 'verified'
        : 'attention'

  const publicInputSummary =
    publicInputState === 'pending'
      ? 'Awaiting artifact or manifest inputs'
      : metadataMismatch
        ? 'Metadata commitment mismatch detected'
        : hasHash
          ? 'Public digests formatted and bound'
          : 'Public input validation incomplete'

  const publicInputRows: readonly VerificationDetailRow[] = Object.freeze([
    {
      label: 'Statement digest (video SHA-256)',
      value: formatSafeDigest(verifyHash),
      status: hasHash ? 'verified' : hasActiveInspection ? 'attention' : 'pending',
    },
    {
      label: 'Proof identifier binding',
      value: resolvedProofId ? formatSafeDigest(resolvedProofId) : 'Not bound',
      status: hasValidProofId ? 'verified' : hasActiveInspection ? 'unavailable' : 'pending',
    },
    {
      label: 'Metadata commitment check',
      value: metadataMismatch
        ? 'Mismatch against bound envelope'
        : resolvedMetadataHash
          ? formatSafeDigest(resolvedMetadataHash)
          : offline
            ? 'Checked locally against embedded envelope'
            : 'No on-chain metadata commitment',
      status: metadataMismatch
        ? 'attention'
        : resolvedMetadataHash
          ? 'verified'
          : hasActiveInspection
            ? 'unavailable'
            : 'pending',
    },
  ])

  const publicInputSection: VerificationDetailSection = Object.freeze({
    id: 'public-input-checks',
    heading: 'Public-input checks',
    summary: publicInputSummary,
    state: publicInputState,
    rows: publicInputRows,
  })

  // 2. Chain observations
  const chainRevokedOrExpired =
    chainProof?.status === 2 ||
    chainProof?.status === 3 ||
    errorCode === 'REVOKED_EVIDENCE' ||
    errorCode === 'EXPIRED_EVIDENCE'

  const chainSectionState: DetailSectionState = !hasActiveInspection
    ? 'pending'
    : offline
      ? 'unavailable'
      : chainRevokedOrExpired
        ? 'attention'
        : chainProof && events.length > 0
          ? 'verified'
          : 'attention'

  const chainSummary = !hasActiveInspection
    ? 'No chain lookup performed yet'
    : offline
      ? 'Skipped in offline local mode'
      : chainRevokedOrExpired
        ? 'Chain record is revoked or expired'
        : chainProof
          ? `Registry match (${events.length} corroborating event${events.length === 1 ? '' : 's'})`
          : 'No active on-chain proof record'

  const chainRows: readonly VerificationDetailRow[] = Object.freeze([
    {
      label: 'Soroban registry standing',
      value: formatChainStatusLabel(chainProof, offline),
      status: offline
        ? 'unavailable'
        : chainRevokedOrExpired
          ? 'attention'
          : chainProof
            ? 'verified'
            : hasActiveInspection
              ? 'attention'
              : 'pending',
    },
    {
      label: 'Registered identity tier',
      value: offline
        ? 'Not checked (offline mode)'
        : chainProof
          ? formatChainTier(chainProof.tier)
          : 'Unrecorded',
      status: offline ? 'unavailable' : chainProof ? 'verified' : 'pending',
    },
    {
      label: 'Backend event corroboration',
      value: offline
        ? 'Not queried (offline mode)'
        : `${events.length} matching event${events.length === 1 ? '' : 's'}`,
      status: offline
        ? 'unavailable'
        : events.length > 0
          ? 'verified'
          : hasActiveInspection
            ? 'attention'
            : 'pending',
    },
  ])

  const chainSection: VerificationDetailSection = Object.freeze({
    id: 'chain-observations',
    heading: 'Chain observations',
    summary: chainSummary,
    state: chainSectionState,
    rows: chainRows,
  })

  // 3. Trust reasons
  let trustState: DetailSectionState = 'pending'
  let trustSummary = 'Run verification to evaluate trust standing'
  let primaryReason = 'No verification checks have completed yet.'
  let revocationStanding = 'Pending online inspection'

  if (hasActiveInspection) {
    if (status === 'cancelled' || errorCode === 'CANCELLED') {
      trustState = 'attention'
      trustSummary = 'Verification cancelled before completion'
      primaryReason = 'User cancelled inspection; no trust decision was recorded.'
      revocationStanding = 'Unresolved (cancelled)'
    } else if (offline) {
      trustState = status === 'error' ? 'attention' : 'unavailable'
      trustSummary =
        status === 'error'
          ? 'Local structural check failed'
          : 'Local structural check only (unconfirmed online)'
      primaryReason =
        status === 'error'
          ? 'Embedded envelope failed local validation or binding.'
          : 'Offline mode verifies local structure only and never grants online trust.'
      revocationStanding = 'Not checked in offline mode'
    } else if (errorCode === 'REVOKED_EVIDENCE' || chainProof?.status === 2) {
      trustState = 'attention'
      trustSummary = 'Rejected: on-chain record revoked'
      primaryReason = 'Registry marked this proof revoked; do not trust this artifact.'
      revocationStanding = 'Revoked on-chain'
    } else if (errorCode === 'EXPIRED_EVIDENCE' || chainProof?.status === 3) {
      trustState = 'attention'
      trustSummary = 'Rejected: on-chain record expired'
      primaryReason = 'Registry validity window has elapsed for this proof.'
      revocationStanding = 'Expired on-chain'
    } else if (metadataMismatch) {
      trustState = 'attention'
      trustSummary = 'Rejected: metadata commitment mismatch'
      primaryReason =
        'Extracted metadata digest does not match the on-chain commitment bound to this proof.'
      revocationStanding = 'Integrity check failed'
    } else if (status === 'error') {
      trustState = 'attention'
      trustSummary = `Unconfirmed (${errorCode ?? 'VERIFICATION_FAILED'})`
      primaryReason = 'Verification failed or required services were unavailable.'
      revocationStanding = 'Unresolved due to verification error'
    } else if (status === 'success' && chainProof && events.length > 0) {
      trustState = 'verified'
      trustSummary = 'Corroborated across public inputs, events, and chain'
      primaryReason =
        'Public digests, backend event history, and active Soroban registry record agree.'
      revocationStanding = 'Active (not revoked or expired)'
    } else if (status === 'success') {
      trustState = 'attention'
      trustSummary = 'Unconfirmed: incomplete multi-source corroboration'
      primaryReason =
        'At least one required corroboration source (embedded metadata, events, or chain) is missing.'
      revocationStanding = chainProof ? 'Active on-chain' : 'No on-chain record to check'
    } else {
      trustState = 'pending'
      trustSummary = 'Verification in progress'
      primaryReason = 'Collecting public-input, database, and Soroban registry observations.'
      revocationStanding = 'Checking…'
    }
  }

  const trustRows: readonly VerificationDetailRow[] = Object.freeze([
    {
      label: 'Trust rationale',
      value: primaryReason,
      status: trustState,
    },
    {
      label: 'Revocation and expiry standing',
      value: revocationStanding,
      status: trustState,
    },
    {
      label: 'Diagnostic code',
      value: errorCode ?? 'NONE',
      status: errorCode ? 'attention' : trustState,
    },
  ])

  const trustSection: VerificationDetailSection = Object.freeze({
    id: 'trust-reasons',
    heading: 'Trust reasons',
    summary: trustSummary,
    state: trustState,
    rows: trustRows,
  })

  const sections: readonly [
    VerificationDetailSection,
    VerificationDetailSection,
    VerificationDetailSection,
  ] = Object.freeze([publicInputSection, chainSection, trustSection] as const)

  return Object.freeze({
    hasActiveInspection,
    sections,
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
