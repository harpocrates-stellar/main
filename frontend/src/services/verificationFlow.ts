/**
 * verificationFlow — orchestrates the verification portal flow and evaluates
 * independent trust dimensions without letting passing checks mask failures.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single structured result. No React state.
 */

import {
  resolveIssuerTrust,
  type IssuerLookupOutcome,
  type IssuerTrust,
} from '../provenance/issuerTrust'
import type { ProvenanceRecord } from '../provenance/provenanceModel'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import {
  extractMetadata,
  fetchProofEventsByVideo,
  getOnChainProof,
} from './verificationService'
import { assertValidVideoHash } from './videoHash'

export const TRUST_DIMENSION_IDS = [
  'contentIntegrity',
  'chainRegistration',
  'issuerTrust',
  'freshness',
] as const

export type TrustDimensionId = (typeof TRUST_DIMENSION_IDS)[number]

export type TrustDimensionStatus =
  | 'verified'
  | 'failed'
  | 'unverified'
  | 'not-applicable'

export type TrustDimensionEvaluation = {
  readonly id: TrustDimensionId
  readonly label: string
  readonly status: TrustDimensionStatus
  readonly reasonCode: string
  readonly summary: string
}

export type StructuredVerificationVerdict =
  | 'verified'
  | 'rejected'
  | 'unconfirmed'
  | 'pending'

export type StructuredVerificationDimensions = {
  readonly contentIntegrity: TrustDimensionEvaluation
  readonly chainRegistration: TrustDimensionEvaluation
  readonly issuerTrust: TrustDimensionEvaluation
  readonly freshness: TrustDimensionEvaluation
}

export type StructuredVerificationResultModel = {
  readonly overallVerdict: StructuredVerificationVerdict
  readonly overallSummary: string
  readonly failedDimensions: readonly TrustDimensionId[]
  readonly unverifiedDimensions: readonly TrustDimensionId[]
  readonly verifiedDimensions: readonly TrustDimensionId[]
  readonly dimensions: StructuredVerificationDimensions
  readonly dimensionList: readonly TrustDimensionEvaluation[]
}

export type VerificationPortalLifecycleStatus =
  | 'idle'
  | 'validating'
  | 'hashing'
  | 'verifying'
  | 'success'
  | 'error'
  | 'cancelled'

export type EvaluateStructuredVerificationInput = {
  status?: VerificationPortalLifecycleStatus
  errorCode?: string | null
  manifestError?: string | null
  verifyHash?: string | null
  hasEmbeddedMetadata?: boolean | null
  offline?: boolean
  events?: readonly ProofEvent[]
  chainProof?: ChainProofRecord | null
  provenanceRecord?: ProvenanceRecord | null
  issuerTrust?: IssuerTrust | null
  issuerLookup?: IssuerLookupOutcome
  networkMismatch?: string | null
  nowUnixSeconds?: number
}

export type VerificationFlowOptions = {
  signal?: AbortSignal
  sourceAddress?: string
  issuerLookup?: IssuerLookupOutcome
  nowUnixSeconds?: number
}

export type VerificationResult = {
  videoHash: string
  hasHarpocratesMetadata: boolean
  events: ProofEvent[]
  onChain: ChainProofRecord | null
  structuredResult: StructuredVerificationResultModel
}

const CONTENT_FAILURE_CODES = new Set([
  'EMPTY_INPUT',
  'OVERSIZED_ARTIFACT',
  'UNSUPPORTED_ARTIFACT',
  'METADATA_ENVELOPE_MISMATCH',
  'INVALID_EVIDENCE',
])

const DIMENSION_LABELS: Record<TrustDimensionId, string> = {
  contentIntegrity: 'Content integrity',
  chainRegistration: 'Chain registration',
  issuerTrust: 'Issuer trust',
  freshness: 'Freshness',
}

function normalizeComparableHex(value: string | null | undefined): string {
  if (!value) return ''
  return value.trim().replace(/^0x/i, '').toLowerCase()
}

function evaluateContentIntegrity(
  input: EvaluateStructuredVerificationInput,
): TrustDimensionEvaluation {
  const id: TrustDimensionId = 'contentIntegrity'
  const label = DIMENSION_LABELS[id]

  if (input.manifestError) {
    return {
      id,
      label,
      status: 'failed',
      reasonCode: 'MANIFEST_PARSE_FAILED',
      summary: 'Portable proof manifest failed schema or size validation.',
    }
  }

  if (input.errorCode && CONTENT_FAILURE_CODES.has(input.errorCode)) {
    const summaryByCode: Record<string, string> = {
      METADATA_ENVELOPE_MISMATCH:
        'Embedded metadata envelope digest does not match the received artifact bytes.',
      INVALID_EVIDENCE:
        'Artifact or cryptographic proof payload failed local integrity verification.',
      EMPTY_INPUT: 'Received artifact input was empty and could not be hashed.',
      OVERSIZED_ARTIFACT: 'Received artifact exceeded maximum verification size bounds.',
      UNSUPPORTED_ARTIFACT: 'Received artifact format is unsupported for verification.',
    }
    return {
      id,
      label,
      status: 'failed',
      reasonCode: input.errorCode,
      summary:
        summaryByCode[input.errorCode] ??
        'Artifact failed content integrity validation.',
    }
  }

  const hasContentDigestMismatch = Boolean(
    input.provenanceRecord?.mismatches.some(
      (mismatch) => mismatch.field === 'videoHash' || mismatch.field === 'metadataHash',
    ),
  )
  if (hasContentDigestMismatch) {
    return {
      id,
      label,
      status: 'failed',
      reasonCode: 'CHAIN_DIGEST_MISMATCH',
      summary:
        'Manifest or artifact content hashes diverge from the on-chain commitment.',
    }
  }

  const normalizedVerifyHash = normalizeComparableHex(input.verifyHash)
  const normalizedChainHash = normalizeComparableHex(input.chainProof?.videoHash)
  if (
    normalizedVerifyHash &&
    normalizedChainHash &&
    normalizedVerifyHash !== normalizedChainHash
  ) {
    return {
      id,
      label,
      status: 'failed',
      reasonCode: 'VIDEO_HASH_MISMATCH',
      summary:
        'Computed video hash does not match the video hash committed on chain.',
    }
  }

  if (input.hasEmbeddedMetadata === false) {
    return {
      id,
      label,
      status: 'failed',
      reasonCode: 'MISSING_METADATA_ENVELOPE',
      summary:
        'No valid embedded Harpocrates metadata envelope was extracted from the artifact.',
    }
  }

  const hasEvaluatedDigest = Boolean(normalizedVerifyHash || normalizedChainHash)
  const confirmedContent =
    hasEvaluatedDigest &&
    (input.hasEmbeddedMetadata === true ||
      input.status === 'success' ||
      Boolean(input.chainProof))

  if (confirmedContent) {
    return {
      id,
      label,
      status: 'verified',
      reasonCode: 'CONTENT_HASH_BOUND',
      summary:
        'Artifact content digest and metadata commitment are intact and consistent.',
    }
  }

  return {
    id,
    label,
    status: 'unverified',
    reasonCode: 'CONTENT_NOT_EVALUATED',
    summary: 'Artifact content integrity has not been confirmed yet.',
  }
}

function evaluateChainRegistration(
  input: EvaluateStructuredVerificationInput,
): TrustDimensionEvaluation {
  const id: TrustDimensionId = 'chainRegistration'
  const label = DIMENSION_LABELS[id]

  if (input.offline) {
    return {
      id,
      label,
      status: 'unverified',
      reasonCode: 'OFFLINE_CHAIN_UNCHECKED',
      summary: 'Soroban registry was not queried in offline local check mode.',
    }
  }

  if (input.errorCode === 'REVOKED_EVIDENCE' || input.chainProof?.status === 2) {
    return {
      id,
      label,
      status: 'failed',
      reasonCode: 'CHAIN_RECORD_REVOKED',
      summary: 'The Soroban registry lists this proof commitment as revoked.',
    }
  }

  const hasTierMismatch = Boolean(
    input.provenanceRecord?.mismatches.some((mismatch) => mismatch.field === 'tier'),
  )
  if (hasTierMismatch) {
    return {
      id,
      label,
      status: 'failed',
      reasonCode: 'IDENTITY_TIER_MISMATCH',
      summary:
        'Claimed identity tier does not match the tier registered on chain.',
    }
  }

  if (input.chainProof && (input.chainProof.status === 1 || input.chainProof.status === 3)) {
    return {
      id,
      label,
      status: 'verified',
      reasonCode:
        input.chainProof.status === 1
          ? 'CHAIN_RECORD_ACTIVE'
          : 'CHAIN_RECORD_REGISTERED',
      summary:
        'Unrevoked proof commitment confirmed in the Soroban registry.',
    }
  }

  if (input.errorCode === 'TIMEOUT' || input.errorCode === 'UPSTREAM_ERROR') {
    return {
      id,
      label,
      status: 'unverified',
      reasonCode: 'CHAIN_LOOKUP_UNAVAILABLE',
      summary:
        'Soroban registry read did not complete; registration was not confirmed.',
    }
  }

  return {
    id,
    label,
    status: 'unverified',
    reasonCode: 'CHAIN_RECORD_MISSING',
    summary:
      'No Soroban registry proof record has been confirmed for this artifact.',
  }
}

function evaluateIssuerTrustDimension(
  input: EvaluateStructuredVerificationInput,
  nowUnixSeconds: number,
): TrustDimensionEvaluation {
  const id: TrustDimensionId = 'issuerTrust'
  const label = DIMENSION_LABELS[id]

  if (input.offline) {
    return {
      id,
      label,
      status: 'unverified',
      reasonCode: 'OFFLINE_ISSUER_UNCHECKED',
      summary:
        'Issuer standing cannot be checked against the Soroban registry in offline mode.',
    }
  }

  const chainProof = input.chainProof ?? null
  const resolvedTrust: IssuerTrust | null =
    input.issuerTrust ??
    (chainProof
      ? chainProof.issuer
        ? resolveIssuerTrust({
            issuer: chainProof.issuer,
            lookup: input.issuerLookup ?? { kind: 'pending' },
            expiresAt: chainProof.expiresAt,
            now: nowUnixSeconds,
          })
        : null
      : null)

  if (!resolvedTrust) {
    if (chainProof?.tier === 2) {
      return {
        id,
        label,
        status: 'failed',
        reasonCode: 'SEAL_ISSUER_MISSING',
        summary:
          'Institutional Seal tier requires a registered issuer address, but none was present.',
      }
    }

    if (chainProof && (chainProof.tier === 0 || chainProof.tier === 1)) {
      return {
        id,
        label,
        status: 'not-applicable',
        reasonCode: 'TIER_WITHOUT_ISSUER',
        summary:
          'Anonymous or source-witness identity tier does not rely on an institutional issuer.',
      }
    }

    return {
      id,
      label,
      status: 'unverified',
      reasonCode: 'ISSUER_NOT_EVALUATED',
      summary:
        'Issuer standing has not been evaluated because no chain record is loaded.',
    }
  }

  switch (resolvedTrust.state) {
    case 'trusted':
      return {
        id,
        label,
        status: 'verified',
        reasonCode: 'ISSUER_TRUSTED',
        summary: resolvedTrust.description,
      }
    case 'revoked':
      return {
        id,
        label,
        status: 'failed',
        reasonCode: 'ISSUER_REVOKED',
        summary: resolvedTrust.description,
      }
    case 'malformed':
      return {
        id,
        label,
        status: 'failed',
        reasonCode: 'ISSUER_MALFORMED',
        summary: resolvedTrust.description,
      }
    case 'oversized':
      return {
        id,
        label,
        status: 'failed',
        reasonCode: 'ISSUER_OVERSIZED',
        summary: resolvedTrust.description,
      }
    case 'expired':
      return {
        id,
        label,
        status: 'failed',
        reasonCode: 'ISSUER_ENDORSEMENT_EXPIRED',
        summary: resolvedTrust.description,
      }
    case 'unsupported':
      if (chainProof?.tier === 2) {
        return {
          id,
          label,
          status: 'failed',
          reasonCode: 'SEAL_ISSUER_MISSING',
          summary:
            'Institutional Seal tier requires a registered issuer address, but none was present.',
        }
      }
      return {
        id,
        label,
        status: 'not-applicable',
        reasonCode: 'TIER_WITHOUT_ISSUER',
        summary: resolvedTrust.description,
      }
    case 'unknown':
      return {
        id,
        label,
        status: 'unverified',
        reasonCode: 'ISSUER_UNKNOWN',
        summary: resolvedTrust.description,
      }
    case 'unavailable':
    case 'checking':
      return {
        id,
        label,
        status: 'unverified',
        reasonCode: 'ISSUER_LOOKUP_INCOMPLETE',
        summary: resolvedTrust.description,
      }
  }
}

function isChainRecordExpired(
  expiresAt: number | null | undefined,
  nowUnixSeconds: number,
): boolean {
  if (expiresAt === null || expiresAt === undefined || expiresAt === 0) return false
  if (!Number.isFinite(expiresAt)) return false
  return nowUnixSeconds > expiresAt
}

function evaluateFreshness(
  input: EvaluateStructuredVerificationInput,
  nowUnixSeconds: number,
): TrustDimensionEvaluation {
  const id: TrustDimensionId = 'freshness'
  const label = DIMENSION_LABELS[id]

  if (input.networkMismatch) {
    return {
      id,
      label,
      status: 'failed',
      reasonCode: 'NETWORK_CONTEXT_MISMATCH',
      summary:
        'Connected wallet or RPC network does not match the verification target network.',
    }
  }

  if (
    input.errorCode === 'EXPIRED_EVIDENCE' ||
    input.chainProof?.status === 3 ||
    isChainRecordExpired(input.chainProof?.expiresAt, nowUnixSeconds)
  ) {
    return {
      id,
      label,
      status: 'failed',
      reasonCode: 'PROOF_EXPIRED',
      summary:
        'The proof record has passed its on-chain validity window.',
    }
  }

  if (
    input.provenanceRecord?.staleness.stale === true &&
    input.provenanceRecord.staleness.reason === 'fetched-long-ago'
  ) {
    return {
      id,
      label,
      status: 'failed',
      reasonCode: 'OBSERVATION_STALE',
      summary:
        'Verification observation exceeded the freshness window without on-chain confirmation.',
    }
  }

  if (input.offline) {
    return {
      id,
      label,
      status: 'unverified',
      reasonCode: 'OFFLINE_FRESHNESS_UNCHECKED',
      summary:
        'Ledger freshness and expiry windows cannot be verified in offline mode.',
    }
  }

  if (input.provenanceRecord?.staleness.stale === true) {
    return {
      id,
      label,
      status: 'unverified',
      reasonCode: 'FRESHNESS_SOURCE_INCOMPLETE',
      summary:
        'Freshness could not be confirmed because the live chain observation is incomplete.',
    }
  }

  if (!input.chainProof) {
    return {
      id,
      label,
      status: 'unverified',
      reasonCode: 'FRESHNESS_UNCHECKED',
      summary:
        'No live on-chain record timestamp or expiry window has been verified yet.',
    }
  }

  return {
    id,
    label,
    status: 'verified',
    reasonCode: 'OBSERVATION_FRESH',
    summary:
      'Chain observation is current and within the proof validity window.',
  }
}

/**
 * Evaluate all four trust dimensions independently and compose an overall
 * verdict where a passing dimension never masks a failed or unverified one.
 */
export function evaluateStructuredVerificationResult(
  input: EvaluateStructuredVerificationInput,
): StructuredVerificationResultModel {
  const nowUnixSeconds = input.nowUnixSeconds ?? Math.floor(Date.now() / 1000)

  const contentIntegrity = evaluateContentIntegrity(input)
  const chainRegistration = evaluateChainRegistration(input)
  const issuerTrust = evaluateIssuerTrustDimension(input, nowUnixSeconds)
  const freshness = evaluateFreshness(input, nowUnixSeconds)

  const dimensions: StructuredVerificationDimensions = {
    contentIntegrity,
    chainRegistration,
    issuerTrust,
    freshness,
  }

  const dimensionList: readonly TrustDimensionEvaluation[] = [
    contentIntegrity,
    chainRegistration,
    issuerTrust,
    freshness,
  ]

  const failedDimensions = dimensionList
    .filter((dimension) => dimension.status === 'failed')
    .map((dimension) => dimension.id)

  const unverifiedDimensions = dimensionList
    .filter((dimension) => dimension.status === 'unverified')
    .map((dimension) => dimension.id)

  const verifiedDimensions = dimensionList
    .filter((dimension) => dimension.status === 'verified')
    .map((dimension) => dimension.id)

  if (failedDimensions.length > 0) {
    const failedLabels = failedDimensions
      .map((id) => DIMENSION_LABELS[id])
      .join(', ')
    const passedLabels = verifiedDimensions
      .map((id) => DIMENSION_LABELS[id])
      .join(', ')

    const overallSummary =
      verifiedDimensions.length > 0
        ? `Rejected: ${failedLabels} failed (${passedLabels} passed independently; passing dimensions never mask a failed trust dimension).`
        : `Rejected: ${failedLabels} failed verification.`

    return {
      overallVerdict: 'rejected',
      overallSummary,
      failedDimensions,
      unverifiedDimensions,
      verifiedDimensions,
      dimensions,
      dimensionList,
    }
  }

  const status = input.status ?? 'idle'
  const isAwaitingInput =
    (status === 'idle' ||
      status === 'validating' ||
      status === 'hashing' ||
      status === 'verifying') &&
    !input.verifyHash &&
    !input.chainProof &&
    (!input.events || input.events.length === 0) &&
    !input.errorCode &&
    !input.manifestError

  if (isAwaitingInput) {
    return {
      overallVerdict: 'pending',
      overallSummary:
        'Pending: awaiting artifact or manifest input to evaluate independent trust dimensions.',
      failedDimensions,
      unverifiedDimensions,
      verifiedDimensions,
      dimensions,
      dimensionList,
    }
  }

  if (unverifiedDimensions.length > 0) {
    const unverifiedLabels = unverifiedDimensions
      .map((id) => DIMENSION_LABELS[id])
      .join(', ')
    const passedLabels = verifiedDimensions
      .map((id) => DIMENSION_LABELS[id])
      .join(', ')

    const overallSummary =
      verifiedDimensions.length > 0
        ? `Unconfirmed: ${passedLabels} passed, while ${unverifiedLabels} could not be verified.`
        : `Unconfirmed: ${unverifiedLabels} remain unverified.`

    return {
      overallVerdict: 'unconfirmed',
      overallSummary,
      failedDimensions,
      unverifiedDimensions,
      verifiedDimensions,
      dimensions,
      dimensionList,
    }
  }

  return {
    overallVerdict: 'verified',
    overallSummary:
      'Verified: all applicable trust dimensions (content integrity, chain registration, issuer trust, and freshness) passed independently.',
    failedDimensions,
    unverifiedDimensions,
    verifiedDimensions,
    dimensions,
    dimensionList,
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
  const safeHash = assertValidVideoHash(videoHash)

  const events = await fetchProofEventsByVideo(safeHash, options.signal)
  const onChain = await getOnChainProof(safeHash, options.sourceAddress)
  const hasHarpocratesMetadata = events.length > 0

  const structuredResult = evaluateStructuredVerificationResult({
    status: 'success',
    verifyHash: safeHash,
    hasEmbeddedMetadata: hasHarpocratesMetadata,
    events,
    chainProof: onChain,
    issuerLookup: options.issuerLookup,
    nowUnixSeconds: options.nowUnixSeconds,
  })

  return {
    videoHash: safeHash,
    hasHarpocratesMetadata,
    events,
    onChain,
    structuredResult,
  }
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
  // Validate before hitting the network at all.
  const safeHash = assertValidVideoHash(videoHash)
  const extract = await extractMetadata(file, options.signal)
  const events = await fetchProofEventsByVideo(safeHash, options.signal)
  const onChain = await getOnChainProof(safeHash, options.sourceAddress)

  const structuredResult = evaluateStructuredVerificationResult({
    status: 'success',
    verifyHash: safeHash,
    hasEmbeddedMetadata: extract.hasHarpocratesMetadata,
    events,
    chainProof: onChain,
    issuerLookup: options.issuerLookup,
    nowUnixSeconds: options.nowUnixSeconds,
  })

  return {
    videoHash: safeHash,
    hasHarpocratesMetadata: extract.hasHarpocratesMetadata,
    events,
    onChain,
    structuredResult,
  }
}
