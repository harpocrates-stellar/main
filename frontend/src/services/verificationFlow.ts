/**
 * verificationFlow — orchestrates the verification portal flow.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single result. No React state.
 */

import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import {
  resolveIssuerTrust,
  type IssuerLookupOutcome,
  type IssuerTrust,
} from '../provenance/issuerTrust'
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

export type VerificationTrustReasonCode =
  | 'SIGNATURE_OR_PROOF_INVALID'
  | 'ISSUER_UNKNOWN_UNREGISTERED'
  | 'ISSUER_TRUSTED_REGISTERED'
  | 'ISSUER_REVOKED_AFTER_ISSUANCE'
  | 'ISSUER_ENDORSEMENT_EXPIRED'
  | 'ISSUER_ADDRESS_INVALID'
  | 'ISSUER_DIRECTORY_UNAVAILABLE'
  | 'ANONYMOUS_TIER_NO_ISSUER'
  | 'PROOF_RECORD_REVOKED_OR_EXPIRED'

export type TrustStandingCategory =
  | 'cryptographic-signature'
  | 'issuer-trust-directory'
  | 'proof-lifecycle'
  | 'anonymous-tier'

export interface TrustReasonCopyEntry {
  readonly code: VerificationTrustReasonCode
  readonly category: TrustStandingCategory
  readonly headline: string
  readonly accessibleExplanation: string
  readonly underlyingProofStatus: 'valid' | 'invalid' | 'revoked-or-expired'
  readonly underlyingProofLabel: string
}

export const TRUST_REASON_ACCESSIBLE_COPY: Readonly<
  Record<VerificationTrustReasonCode, TrustReasonCopyEntry>
> = Object.freeze({
  SIGNATURE_OR_PROOF_INVALID: Object.freeze({
    code: 'SIGNATURE_OR_PROOF_INVALID',
    category: 'cryptographic-signature',
    headline: 'Invalid cryptographic signature or proof',
    accessibleExplanation:
      'Cryptographic verification failed: the signature or zero-knowledge proof does not match the artifact digest. Regardless of any claimed issuer address, the artifact cannot be authenticated.',
    underlyingProofStatus: 'invalid',
    underlyingProofLabel: 'Cryptographic signature or proof failed verification',
  }),
  ISSUER_UNKNOWN_UNREGISTERED: Object.freeze({
    code: 'ISSUER_UNKNOWN_UNREGISTERED',
    category: 'issuer-trust-directory',
    headline: 'Unknown issuer trust (cryptographic signature is valid)',
    accessibleExplanation:
      'The underlying cryptographic proof and signature verified cleanly, confirming the artifact was not altered since signing. Separately, this issuer address is not registered in the trusted issuer directory, so institutional endorsement is unverified rather than forged.',
    underlyingProofStatus: 'valid',
    underlyingProofLabel: 'Underlying cryptographic proof verified',
  }),
  ISSUER_TRUSTED_REGISTERED: Object.freeze({
    code: 'ISSUER_TRUSTED_REGISTERED',
    category: 'issuer-trust-directory',
    headline: 'Registered active issuer and valid cryptographic proof',
    accessibleExplanation:
      'Both the underlying cryptographic proof and the issuer’s active registry standing were verified on Stellar.',
    underlyingProofStatus: 'valid',
    underlyingProofLabel: 'Underlying cryptographic proof verified',
  }),
  ISSUER_REVOKED_AFTER_ISSUANCE: Object.freeze({
    code: 'ISSUER_REVOKED_AFTER_ISSUANCE',
    category: 'issuer-trust-directory',
    headline: 'Issuer standing revoked (underlying proof remains inspectable)',
    accessibleExplanation:
      'The underlying cryptographic proof matched the recorded commitment, but the registry lists this issuer as revoked. Do not rely on institutional endorsement for this seal.',
    underlyingProofStatus: 'valid',
    underlyingProofLabel: 'Underlying cryptographic proof verified',
  }),
  ISSUER_ENDORSEMENT_EXPIRED: Object.freeze({
    code: 'ISSUER_ENDORSEMENT_EXPIRED',
    category: 'issuer-trust-directory',
    headline: 'Issuer endorsement window expired (underlying proof verified)',
    accessibleExplanation:
      'The underlying cryptographic proof verified, and the issuer remains listed, but this record’s endorsement window has passed.',
    underlyingProofStatus: 'valid',
    underlyingProofLabel: 'Underlying cryptographic proof verified',
  }),
  ISSUER_ADDRESS_INVALID: Object.freeze({
    code: 'ISSUER_ADDRESS_INVALID',
    category: 'issuer-trust-directory',
    headline: 'Malformed issuer identifier (underlying proof verified)',
    accessibleExplanation:
      'The underlying proof commitment matched, but the recorded issuer address is not a well-formed Stellar account or contract identifier, so directory trust cannot be established.',
    underlyingProofStatus: 'valid',
    underlyingProofLabel: 'Underlying cryptographic proof verified',
  }),
  ISSUER_DIRECTORY_UNAVAILABLE: Object.freeze({
    code: 'ISSUER_DIRECTORY_UNAVAILABLE',
    category: 'issuer-trust-directory',
    headline: 'Issuer directory lookup unavailable (underlying proof verified)',
    accessibleExplanation:
      'The underlying cryptographic proof verified, but the issuer directory could not be read. Issuer standing remains undetermined — neither trusted nor invalid.',
    underlyingProofStatus: 'valid',
    underlyingProofLabel: 'Underlying cryptographic proof verified',
  }),
  ANONYMOUS_TIER_NO_ISSUER: Object.freeze({
    code: 'ANONYMOUS_TIER_NO_ISSUER',
    category: 'anonymous-tier',
    headline: 'Anonymous Silent Witness proof (no public issuer by design)',
    accessibleExplanation:
      'The zero-knowledge membership proof verified cleanly. Silent Witness (Tier 0) deliberately omits a public issuer address to protect source anonymity.',
    underlyingProofStatus: 'valid',
    underlyingProofLabel: 'Underlying zero-knowledge proof verified',
  }),
  PROOF_RECORD_REVOKED_OR_EXPIRED: Object.freeze({
    code: 'PROOF_RECORD_REVOKED_OR_EXPIRED',
    category: 'proof-lifecycle',
    headline: 'On-chain proof record revoked or expired',
    accessibleExplanation:
      'The proof record on Soroban has been explicitly revoked or expired and is no longer active.',
    underlyingProofStatus: 'revoked-or-expired',
    underlyingProofLabel: 'Proof record revoked or expired on-chain',
  }),
})

const SIGNATURE_FAILURE_ERROR_CODES = new Set([
  'INVALID_SIGNATURE',
  'INVALID_EVIDENCE',
  'METADATA_ENVELOPE_MISMATCH',
  'PROOF_VERIFICATION_FAILED',
  'TAMPERED_METADATA',
  'INVALID_RECEIPT_SIGNATURE',
])

export interface ExplainTrustVsSignatureInput {
  readonly status: string
  readonly verifyResult: string
  readonly errorCode?: string | null
  readonly offline: boolean
  readonly chainProof: ChainProofRecord | null
  readonly issuerTrust?: IssuerTrust | null
  readonly issuerLookupOutcome?: IssuerLookupOutcome
  readonly signatureValid?: boolean | null
}

export interface TrustVsSignatureStandingExplanation extends TrustReasonCopyEntry {
  readonly visibleProofResultSummary: string
  readonly issuerAddress: string | null
}

/**
 * Maps verification outcomes and issuer directory standing into stable trust
 * reason codes with accessible copy, keeping unknown issuer trust clearly
 * separate from cryptographic signature failure while preserving the visible
 * underlying proof result.
 */
export function explainTrustVsSignatureStanding(
  input: ExplainTrustVsSignatureInput,
): TrustVsSignatureStandingExplanation | null {
  const normalizedError = (input.errorCode ?? '').trim().toUpperCase()
  const visibleProofResultSummary =
    input.verifyResult.trim() ||
    (input.status === 'success'
      ? 'Verification complete.'
      : 'Verification did not confirm this artifact.')

  if (
    input.signatureValid === false ||
    (input.status === 'error' && SIGNATURE_FAILURE_ERROR_CODES.has(normalizedError))
  ) {
    return Object.freeze({
      ...TRUST_REASON_ACCESSIBLE_COPY.SIGNATURE_OR_PROOF_INVALID,
      visibleProofResultSummary,
      issuerAddress: input.chainProof?.issuer ?? null,
    })
  }

  if (
    normalizedError === 'REVOKED_EVIDENCE' ||
    normalizedError === 'EXPIRED_EVIDENCE' ||
    input.chainProof?.status === 2 ||
    input.chainProof?.status === 3
  ) {
    return Object.freeze({
      ...TRUST_REASON_ACCESSIBLE_COPY.PROOF_RECORD_REVOKED_OR_EXPIRED,
      visibleProofResultSummary,
      issuerAddress: input.chainProof?.issuer ?? null,
    })
  }

  if (input.status !== 'success') {
    return null
  }

  const resolvedTrust: IssuerTrust | null =
    input.issuerTrust ??
    (input.chainProof
      ? resolveIssuerTrust({
          issuer: input.chainProof.issuer,
          lookup:
            input.issuerLookupOutcome ??
            (input.offline
              ? { kind: 'failed' }
              : input.chainProof.issuer
                ? { kind: 'missing' }
                : { kind: 'pending' }),
          expiresAt: input.chainProof.expiresAt,
        })
      : null)

  if (!resolvedTrust || resolvedTrust.state === 'checking') {
    return null
  }

  let reasonCode: VerificationTrustReasonCode
  switch (resolvedTrust.state) {
    case 'unknown':
      reasonCode = 'ISSUER_UNKNOWN_UNREGISTERED'
      break
    case 'trusted':
      reasonCode = 'ISSUER_TRUSTED_REGISTERED'
      break
    case 'revoked':
      reasonCode = 'ISSUER_REVOKED_AFTER_ISSUANCE'
      break
    case 'expired':
      reasonCode = 'ISSUER_ENDORSEMENT_EXPIRED'
      break
    case 'malformed':
    case 'oversized':
      reasonCode = 'ISSUER_ADDRESS_INVALID'
      break
    case 'unavailable':
      reasonCode = 'ISSUER_DIRECTORY_UNAVAILABLE'
      break
    case 'unsupported':
      reasonCode = 'ANONYMOUS_TIER_NO_ISSUER'
      break
  }

  return Object.freeze({
    ...TRUST_REASON_ACCESSIBLE_COPY[reasonCode],
    visibleProofResultSummary,
    issuerAddress: resolvedTrust.issuer,
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
