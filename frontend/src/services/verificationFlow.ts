/**
 * verificationFlow — orchestrates the verification portal flow.
 *
 * Responsibility: combine the Flask extraction, NeonDB lookup, and the
 * Soroban on-chain registry into a single structured result with independent
 * trust dimensions. No React state.
 */

import type { ChainProofRecord, IssuerRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import { assertValidVideoHash } from './videoHash'
import {
  extractMetadata,
  fetchProofEventsByVideo,
  getOnChainProof,
} from './verificationService'

export type TrustDimensionKey =
  | 'contentIntegrity'
  | 'chainRegistration'
  | 'issuerTrust'
  | 'freshness'

export type TrustDimensionState =
  | 'verified'
  | 'failed'
  | 'unverified'
  | 'not_applicable'

export type TrustDimensionResult = {
  key: TrustDimensionKey
  label: string
  state: TrustDimensionState
  code: string
  summary: string
}

export type TrustDimensions = {
  contentIntegrity: TrustDimensionResult
  chainRegistration: TrustDimensionResult
  issuerTrust: TrustDimensionResult
  freshness: TrustDimensionResult
}

export type OverallTrustVerdict = 'verified' | 'failed' | 'incomplete'

export type StructuredVerificationModel = {
  overall: OverallTrustVerdict
  hasFailure: boolean
  failedDimensions: TrustDimensionKey[]
  dimensions: TrustDimensions
}

export type VerificationDimensionsInput = {
  hasHarpocratesMetadata?: boolean | null
  metadataEnvelopeMismatch?: boolean
  onChain: ChainProofRecord | null
  events?: ProofEvent[]
  issuerRecord?: IssuerRecord | null
  offline?: boolean
  errorCode?: string | null
  nowUnixSeconds?: number
}

export type VerificationResult = {
  videoHash: string
  hasHarpocratesMetadata: boolean
  events: ProofEvent[]
  onChain: ChainProofRecord | null
  trust: StructuredVerificationModel
}

const CONTENT_FAILURE_CODES = new Set([
  'EMPTY_INPUT',
  'UNSUPPORTED_ARTIFACT',
  'OVERSIZED_ARTIFACT',
  'INVALID_EVIDENCE',
])

const CHAIN_FAILURE_CODES = new Set([
  'DEPENDENCY_UNAVAILABLE',
  'TIMEOUT',
  'VERIFICATION_FAILED',
  'WALLET_UNAVAILABLE',
])

/**
 * Evaluate each verification trust dimension independently so a successful
 * dimension can never mask another dimension's failure.
 */
export function buildVerificationDimensions(
  input: VerificationDimensionsInput,
): StructuredVerificationModel {
  const {
    hasHarpocratesMetadata = null,
    metadataEnvelopeMismatch = false,
    onChain,
    issuerRecord,
    offline = false,
    errorCode = null,
    nowUnixSeconds = Math.floor(Date.now() / 1000),
  } = input

  // 1. Content integrity
  let contentIntegrity: TrustDimensionResult
  if (metadataEnvelopeMismatch || errorCode === 'METADATA_ENVELOPE_MISMATCH') {
    contentIntegrity = {
      key: 'contentIntegrity',
      label: 'Content Integrity',
      state: 'failed',
      code: 'METADATA_ENVELOPE_MISMATCH',
      summary: 'Embedded metadata hash does not match the on-chain envelope.',
    }
  } else if (errorCode && CONTENT_FAILURE_CODES.has(errorCode)) {
    contentIntegrity = {
      key: 'contentIntegrity',
      label: 'Content Integrity',
      state: 'failed',
      code: errorCode,
      summary: 'Artifact failed content validation or metadata extraction.',
    }
  } else if (hasHarpocratesMetadata === true) {
    contentIntegrity = {
      key: 'contentIntegrity',
      label: 'Content Integrity',
      state: 'verified',
      code: 'METADATA_CONFIRMED',
      summary: 'Embedded Harpocrates metadata was extracted and validated.',
    }
  } else {
    contentIntegrity = {
      key: 'contentIntegrity',
      label: 'Content Integrity',
      state: 'unverified',
      code: 'METADATA_ABSENT',
      summary: 'No valid embedded Harpocrates metadata was confirmed for this artifact.',
    }
  }

  // 2. Chain registration
  let chainRegistration: TrustDimensionResult
  if (offline) {
    chainRegistration = {
      key: 'chainRegistration',
      label: 'Chain Registration',
      state: 'unverified',
      code: 'OFFLINE_NOT_CHECKED',
      summary: 'On-chain registry was not queried in offline mode.',
    }
  } else if (onChain) {
    if (onChain.status === 2 || errorCode === 'REVOKED_EVIDENCE') {
      chainRegistration = {
        key: 'chainRegistration',
        label: 'Chain Registration',
        state: 'failed',
        code: 'CHAIN_REVOKED',
        summary: 'On-chain registry record has been revoked.',
      }
    } else {
      chainRegistration = {
        key: 'chainRegistration',
        label: 'Chain Registration',
        state: 'verified',
        code: 'CHAIN_REGISTERED',
        summary: 'Proof record is registered on the Stellar Soroban registry.',
      }
    }
  } else if (errorCode === 'REVOKED_EVIDENCE') {
    chainRegistration = {
      key: 'chainRegistration',
      label: 'Chain Registration',
      state: 'failed',
      code: 'CHAIN_REVOKED',
      summary: 'On-chain registry record has been revoked.',
    }
  } else if (errorCode && CHAIN_FAILURE_CODES.has(errorCode)) {
    chainRegistration = {
      key: 'chainRegistration',
      label: 'Chain Registration',
      state: 'failed',
      code: errorCode,
      summary: 'Unable to confirm on-chain registration due to a verification error.',
    }
  } else {
    chainRegistration = {
      key: 'chainRegistration',
      label: 'Chain Registration',
      state: 'unverified',
      code: 'CHAIN_NOT_FOUND',
      summary: 'No matching proof record was found on the Stellar registry.',
    }
  }

  // 3. Issuer trust (preserves Silent / Source / Seal tier separation)
  let issuerTrust: TrustDimensionResult
  if (offline) {
    issuerTrust = {
      key: 'issuerTrust',
      label: 'Issuer Trust',
      state: 'unverified',
      code: 'OFFLINE_NOT_CHECKED',
      summary: 'Issuer standing was not checked in offline mode.',
    }
  } else if (issuerRecord !== undefined && issuerRecord !== null) {
    issuerTrust = issuerRecord.active
      ? {
          key: 'issuerTrust',
          label: 'Issuer Trust',
          state: 'verified',
          code: 'ISSUER_ACTIVE',
          summary: 'Institutional issuer is active in the on-chain registry.',
        }
      : {
          key: 'issuerTrust',
          label: 'Issuer Trust',
          state: 'failed',
          code: 'ISSUER_REVOKED',
          summary: 'Institutional issuer has been revoked in the on-chain registry.',
        }
  } else if (onChain) {
    if (onChain.tier === 0) {
      issuerTrust = {
        key: 'issuerTrust',
        label: 'Issuer Trust',
        state: 'not_applicable',
        code: 'SILENT_TIER_NO_ISSUER',
        summary: 'Silent tier preserves anonymous witness privacy without an issuer.',
      }
    } else if (onChain.tier === 1) {
      issuerTrust = onChain.source
        ? {
            key: 'issuerTrust',
            label: 'Issuer Trust',
            state: 'verified',
            code: 'SOURCE_ATTRIBUTED',
            summary: 'Source tier proof is attributed to a Stellar source address.',
          }
        : {
            key: 'issuerTrust',
            label: 'Issuer Trust',
            state: 'failed',
            code: 'SOURCE_MISSING',
            summary: 'Source tier proof is missing its attributed source address.',
          }
    } else if (onChain.tier === 2) {
      if (!onChain.issuer) {
        issuerTrust = {
          key: 'issuerTrust',
          label: 'Issuer Trust',
          state: 'failed',
          code: 'ISSUER_MISSING',
          summary: 'Seal tier proof is missing an institutional issuer address.',
        }
      } else if (issuerRecord === null) {
        issuerTrust = {
          key: 'issuerTrust',
          label: 'Issuer Trust',
          state: 'failed',
          code: 'ISSUER_NOT_FOUND',
          summary: 'Institutional issuer was not found in the on-chain registry.',
        }
      } else {
        issuerTrust = {
          key: 'issuerTrust',
          label: 'Issuer Trust',
          state: 'unverified',
          code: 'ISSUER_STANDING_UNCHECKED',
          summary: 'Seal tier issuer address is present, but registry standing was not verified.',
        }
      }
    } else {
      issuerTrust = {
        key: 'issuerTrust',
        label: 'Issuer Trust',
        state: 'unverified',
        code: 'ISSUER_UNVERIFIED',
        summary: 'Issuer trust could not be determined for this identity tier.',
      }
    }
  } else {
    issuerTrust = {
      key: 'issuerTrust',
      label: 'Issuer Trust',
      state: 'unverified',
      code: 'ISSUER_UNVERIFIED',
      summary: 'No on-chain record is available to evaluate issuer trust.',
    }
  }

  // 4. Freshness
  let freshness: TrustDimensionResult
  if (offline) {
    freshness = {
      key: 'freshness',
      label: 'Freshness',
      state: 'unverified',
      code: 'OFFLINE_NOT_CHECKED',
      summary: 'Record expiry and freshness were not checked in offline mode.',
    }
  } else if (errorCode === 'EXPIRED_EVIDENCE' || onChain?.status === 3) {
    freshness = {
      key: 'freshness',
      label: 'Freshness',
      state: 'failed',
      code: 'RECORD_EXPIRED',
      summary: 'On-chain proof record has expired.',
    }
  } else if (onChain) {
    if (onChain.expiresAt === null || onChain.expiresAt === 0) {
      freshness = {
        key: 'freshness',
        label: 'Freshness',
        state: 'verified',
        code: 'NO_EXPIRY',
        summary: 'On-chain proof record does not expire.',
      }
    } else if (onChain.expiresAt <= nowUnixSeconds) {
      freshness = {
        key: 'freshness',
        label: 'Freshness',
        state: 'failed',
        code: 'RECORD_EXPIRED',
        summary: 'On-chain proof record has passed its expiration timestamp.',
      }
    } else {
      freshness = {
        key: 'freshness',
        label: 'Freshness',
        state: 'verified',
        code: 'WITHIN_VALIDITY_WINDOW',
        summary: 'On-chain proof record is within its active validity window.',
      }
    }
  } else {
    freshness = {
      key: 'freshness',
      label: 'Freshness',
      state: 'unverified',
      code: 'FRESHNESS_UNVERIFIED',
      summary: 'No on-chain record is available to evaluate freshness.',
    }
  }

  const dimensions: TrustDimensions = {
    contentIntegrity,
    chainRegistration,
    issuerTrust,
    freshness,
  }

  const dimensionList: TrustDimensionResult[] = [
    contentIntegrity,
    chainRegistration,
    issuerTrust,
    freshness,
  ]

  const failedDimensions = dimensionList
    .filter((d) => d.state === 'failed')
    .map((d) => d.key)

  const hasFailure = failedDimensions.length > 0

  let overall: OverallTrustVerdict
  if (hasFailure) {
    overall = 'failed'
  } else if (
    dimensionList.every((d) => d.state === 'verified' || d.state === 'not_applicable') &&
    dimensionList.some((d) => d.state === 'verified')
  ) {
    overall = 'verified'
  } else {
    overall = 'incomplete'
  }

  return {
    overall,
    hasFailure,
    failedDimensions,
    dimensions,
  }
}

export type VerificationFlowOptions = {
  signal?: AbortSignal
  sourceAddress?: string
  issuerRecord?: IssuerRecord | null
  nowUnixSeconds?: number
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

  return {
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
