/**
 * verificationFlow — orchestrates the verification portal flow and maps
 * stable trust reason codes to accessible, privacy-safe copy.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single result, and separate institutional
 * issuer trust standing from underlying proof/signature validity. No React state.
 */

import type { ChainProofRecord } from '../stellarTypes'
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

/**
 * Stable trust reason codes surfaced by the verification portal.
 *
 * Unknown issuer trust (`UNKNOWN_ISSUER`) is intentionally distinct from a
 * cryptographic proof or signature failure (`INVALID_SIGNATURE`) and from a
 * registry read outage (`ISSUER_LOOKUP_UNAVAILABLE`).
 */
export type TrustReasonCode =
  | 'TRUSTED_ISSUER'
  | 'UNKNOWN_ISSUER'
  | 'REVOKED_ISSUER'
  | 'EXPIRED_ENDORSEMENT'
  | 'INVALID_SIGNATURE'
  | 'MALFORMED_ISSUER'
  | 'ISSUER_LOOKUP_UNAVAILABLE'
  | 'NO_ISSUER_REQUIRED'
  | 'ISSUER_CHECK_PENDING'
  | 'OFFLINE_NOT_CHECKED'

export type TrustReasonSeverity = 'positive' | 'neutral' | 'caution' | 'critical'

export type TrustReasonCopy = {
  code: TrustReasonCode
  /** Short, accessible heading for the trust assessment. */
  heading: string
  /** Plain-language explanation of the issuer trust standing. */
  explanation: string
  /** Explicit guidance separating issuer trust from cryptographic signature validity. */
  signatureDistinction: string
  severity: TrustReasonSeverity
  /** True when the reason indicates a critical/tampered failure rather than a trust caveat. */
  isAlert: boolean
}

export const TRUST_REASON_COPY: Readonly<Record<TrustReasonCode, TrustReasonCopy>> = {
  TRUSTED_ISSUER: {
    code: 'TRUSTED_ISSUER',
    heading: 'Trusted registry issuer',
    explanation:
      'The on-chain registry lists this issuer as active, so institutional endorsement is current.',
    signatureDistinction:
      'Issuer standing is confirmed independently alongside the underlying proof result.',
    severity: 'positive',
    isAlert: false,
  },
  UNKNOWN_ISSUER: {
    code: 'UNKNOWN_ISSUER',
    heading: 'Unknown issuer (not in trust registry)',
    explanation:
      'This issuer address is not registered in the on-chain institutional allowlist, so institutional endorsement cannot be confirmed.',
    signatureDistinction:
      'This is an issuer trust gap, not an invalid signature. Review the underlying proof result above to see whether the artifact proof itself verified.',
    severity: 'caution',
    isAlert: false,
  },
  REVOKED_ISSUER: {
    code: 'REVOKED_ISSUER',
    heading: 'Issuer revoked in registry',
    explanation:
      'The on-chain registry lists this issuer as revoked. Institutional endorsement has been withdrawn.',
    signatureDistinction:
      'Revocation reflects withdrawn issuer standing, even when the underlying proof record remains registered on chain.',
    severity: 'critical',
    isAlert: true,
  },
  EXPIRED_ENDORSEMENT: {
    code: 'EXPIRED_ENDORSEMENT',
    heading: 'Issuer endorsement expired',
    explanation:
      'The issuer remains active, but this proof record has passed its endorsement expiry window.',
    signatureDistinction:
      'Expiry ends current institutional endorsement without implying the original signature was invalid.',
    severity: 'caution',
    isAlert: false,
  },
  INVALID_SIGNATURE: {
    code: 'INVALID_SIGNATURE',
    heading: 'Invalid signature or proof binding',
    explanation:
      'The cryptographic signature or proof binding failed verification. Do not treat this artifact as authentic.',
    signatureDistinction:
      'This is a cryptographic verification failure, separate from whether an issuer is listed in the trust registry.',
    severity: 'critical',
    isAlert: true,
  },
  MALFORMED_ISSUER: {
    code: 'MALFORMED_ISSUER',
    heading: 'Issuer address cannot be checked',
    explanation:
      'The issuer address on the chain record is malformed or oversized and cannot match any Stellar registry issuer.',
    signatureDistinction:
      'Issuer trust could not be evaluated; inspect the underlying proof result separately.',
    severity: 'caution',
    isAlert: false,
  },
  ISSUER_LOOKUP_UNAVAILABLE: {
    code: 'ISSUER_LOOKUP_UNAVAILABLE',
    heading: 'Issuer trust lookup unavailable',
    explanation:
      'The on-chain issuer registry could not be read, so no institutional trust decision was made.',
    signatureDistinction:
      'A registry lookup outage is neither an unknown issuer nor an invalid signature. The underlying proof result remains visible above.',
    severity: 'caution',
    isAlert: false,
  },
  NO_ISSUER_REQUIRED: {
    code: 'NO_ISSUER_REQUIRED',
    heading: 'No institutional issuer on this tier',
    explanation:
      'This identity tier does not carry an institutional issuer endorsement.',
    signatureDistinction:
      'Verification for this tier relies on the underlying proof result rather than an institutional issuer registry entry.',
    severity: 'neutral',
    isAlert: false,
  },
  ISSUER_CHECK_PENDING: {
    code: 'ISSUER_CHECK_PENDING',
    heading: 'Checking issuer trust registry',
    explanation:
      'Querying the on-chain registry to check institutional issuer standing.',
    signatureDistinction:
      'Issuer trust is resolved separately from the underlying proof result.',
    severity: 'neutral',
    isAlert: false,
  },
  OFFLINE_NOT_CHECKED: {
    code: 'OFFLINE_NOT_CHECKED',
    heading: 'Issuer trust not checked (offline)',
    explanation:
      'Offline local mode does not query the Stellar registry, so no institutional trust decision was made.',
    signatureDistinction:
      'Only local structural checks ran; neither on-chain issuer trust nor registry status was verified.',
    severity: 'neutral',
    isAlert: false,
  },
}

/** Return the canonical, privacy-safe copy for a stable trust reason code. */
export function getTrustReasonCopy(code: TrustReasonCode): TrustReasonCopy {
  return TRUST_REASON_COPY[code]
}

export type ResolveTrustReasonInput = {
  /** Whether verification ran in offline local-only mode. */
  offline?: boolean
  /** Current verification lifecycle status. */
  status?: VerificationStatus
  /** Stable verification error code, if any. */
  errorCode?: VerificationErrorCode | null
  /** Resolved issuer trust state from `resolveIssuerTrust` / `useIssuerTrust`. */
  issuerTrustState?: IssuerTrustState | null
  /** On-chain proof record, if one was loaded. */
  chainProof?: ChainProofRecord | null
}

function mapIssuerTrustState(state: IssuerTrustState): TrustReasonCode {
  switch (state) {
    case 'trusted':
      return 'TRUSTED_ISSUER'
    case 'unknown':
      return 'UNKNOWN_ISSUER'
    case 'revoked':
      return 'REVOKED_ISSUER'
    case 'expired':
      return 'EXPIRED_ENDORSEMENT'
    case 'malformed':
    case 'oversized':
      return 'MALFORMED_ISSUER'
    case 'unavailable':
      return 'ISSUER_LOOKUP_UNAVAILABLE'
    case 'checking':
      return 'ISSUER_CHECK_PENDING'
    case 'unsupported':
      return 'NO_ISSUER_REQUIRED'
  }
}

/**
 * Resolve a stable `TrustReasonCode` from verification observations.
 *
 * Precedence is fail-closed:
 * 1. Cryptographic signature / proof binding failure (`INVALID_EVIDENCE` or
 *    `METADATA_ENVELOPE_MISMATCH`) always yields `INVALID_SIGNATURE` and is
 *    never downgraded to an issuer trust caveat.
 * 2. Offline mode yields `OFFLINE_NOT_CHECKED` when no local signature failure occurred.
 * 3. Resolved issuer trust state maps 1:1 to its stable reason code.
 * 4. If no lookup state was supplied, a loaded chain record falls back to
 *    address-shape classification (`NO_ISSUER_REQUIRED`, `MALFORMED_ISSUER`,
 *    or `ISSUER_CHECK_PENDING`).
 */
export function resolveTrustReasonCode(input: ResolveTrustReasonInput): TrustReasonCode | null {
  if (input.errorCode === 'INVALID_EVIDENCE' || input.errorCode === 'METADATA_ENVELOPE_MISMATCH') {
    return 'INVALID_SIGNATURE'
  }

  if (input.offline) {
    return 'OFFLINE_NOT_CHECKED'
  }

  if (input.issuerTrustState) {
    return mapIssuerTrustState(input.issuerTrustState)
  }

  if (!input.chainProof) {
    return null
  }

  const issuer = input.chainProof.issuer
  if (issuer === null || issuer === undefined || issuer.trim() === '') {
    return 'NO_ISSUER_REQUIRED'
  }

  if (!isLookupEligibleIssuer(issuer)) {
    return 'MALFORMED_ISSUER'
  }

  return 'ISSUER_CHECK_PENDING'
}

/** Resolve and format the accessible trust explanation for a verification result. */
export function explainVerificationTrust(input: ResolveTrustReasonInput): TrustReasonCopy | null {
  const code = resolveTrustReasonCode(input)
  return code ? getTrustReasonCopy(code) : null
}

export type VerificationResult = {
  videoHash: string
  hasHarpocratesMetadata: boolean
  events: ProofEvent[]
  onChain: ChainProofRecord | null
  trustReasonCode?: TrustReasonCode | null
  trustExplanation?: TrustReasonCopy | null
}

export type RunVerificationFlowOptions = {
  signal?: AbortSignal
  sourceAddress?: string
  issuerTrustState?: IssuerTrustState | null
  errorCode?: VerificationErrorCode | null
}

/**
 * Run the verification flow for an already-computed video hash.
 *
 * The hash is validated before any network call is made so a malformed value
 * (from a share link or manifest) cannot inject path segments or query strings.
 */
export async function runVerificationFlow(
  videoHash: string,
  options: RunVerificationFlowOptions = {},
): Promise<VerificationResult> {
  const safeHash = assertValidVideoHash(videoHash)

  const events = await fetchProofEventsByVideo(safeHash, options.signal)
  const onChain = await getOnChainProof(safeHash, options.sourceAddress)
  const trustReasonCode = resolveTrustReasonCode({
    chainProof: onChain,
    issuerTrustState: options.issuerTrustState,
    errorCode: options.errorCode,
  })
  const trustExplanation = trustReasonCode ? getTrustReasonCopy(trustReasonCode) : null

  return {
    videoHash: safeHash,
    hasHarpocratesMetadata: events.length > 0,
    events,
    onChain,
    trustReasonCode,
    trustExplanation,
  }
}

/**
 * Convenience helper: extract metadata from an uploaded file and then run the
 * verification flow for the supplied video hash.
 */
export async function verifyUploadedVideo(
  file: File,
  videoHash: string,
  options: RunVerificationFlowOptions = {},
): Promise<VerificationResult> {
  // Validate before hitting the network at all.
  const safeHash = assertValidVideoHash(videoHash)
  const extract = await extractMetadata(file, options.signal)
  const result = await runVerificationFlow(safeHash, options)
  return { ...result, hasHarpocratesMetadata: extract.hasHarpocratesMetadata }
}
