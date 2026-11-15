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

const MAX_COMPARABLE_RECEIPT_BYTES = 64 * 1024
const MAX_COMPARISON_SHARE_URL_BYTES = 2048

const PRIVATE_METADATA_KEYS = new Set([
  'filename',
  'file_name',
  'originalfilename',
  'sourcepath',
  'source_path',
  'filepath',
  'notes',
  'issuernotes',
  'issuer_notes',
  'privatenotes',
  'witness',
  'privateinputs',
  'private_inputs',
  'credentialseed',
  'nullifierseed',
  'secret',
  'deviceid',
  'gps',
  'location',
])

export type ReceiptObservationCategory = 'trust' | 'chain' | 'statement'

export interface NormalizedComparableReceipt {
  readonly verifiedAt: string
  readonly videoHash: string
  readonly proofId: string
  readonly metadataHash: string
  readonly result: string
  readonly tier: string
  readonly networkPassphrase: string
  readonly contractId: string
  readonly ledgerSequence: number | null
  readonly transactionHash: string | null
  readonly signerKeyId: string | null
  readonly circuitVersion: string
  readonly verifierVersion: string
  readonly strippedPrivateKeys: readonly string[]
}

export interface ReceiptFieldDiff {
  readonly key: string
  readonly label: string
  readonly category: ReceiptObservationCategory
  readonly baselineValue: string
  readonly candidateValue: string
  readonly changed: boolean
}

export interface ReceiptComparisonReport {
  readonly sameStatement: boolean
  readonly baselineVerifiedAt: string
  readonly candidateVerifiedAt: string
  readonly baseline: NormalizedComparableReceipt
  readonly candidate: NormalizedComparableReceipt
  readonly observations: readonly ReceiptFieldDiff[]
  readonly changedTrustObservations: readonly ReceiptFieldDiff[]
  readonly changedChainObservations: readonly ReceiptFieldDiff[]
  readonly changedStatementFields: readonly ReceiptFieldDiff[]
  readonly strippedPrivateFieldNames: readonly string[]
}

function collectStrippedPrivateKeys(record: Record<string, unknown>): string[] {
  const found: string[] = []
  const visit = (obj: Record<string, unknown>) => {
    for (const [key, val] of Object.entries(obj)) {
      const normalized = key.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase()
      if (PRIVATE_METADATA_KEYS.has(normalized)) {
        found.push(key)
      } else if (val && typeof val === 'object' && !Array.isArray(val)) {
        visit(val as Record<string, unknown>)
      }
    }
  }
  visit(record)
  return Array.from(new Set(found)).sort()
}

function requireNonEmptyString(
  record: Record<string, unknown>,
  keys: readonly string[],
  fieldLabel: string,
): string {
  for (const key of keys) {
    const candidate = record[key]
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim()
    }
  }
  throw new Error(`Receipt is missing required public field "${fieldLabel}".`)
}

function optionalString(
  record: Record<string, unknown>,
  keys: readonly string[],
): string | null {
  for (const key of keys) {
    const candidate = record[key]
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim()
    }
  }
  return null
}

function encodeBase64UrlUtf8(text: string): string {
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

/**
 * Parses and normalizes a verification receipt JSON payload while stripping any
 * private evidence metadata so filenames, notes, or local paths never propagate.
 */
export function parseComparableVerificationReceipt(
  rawInput: string | Record<string, unknown>,
): NormalizedComparableReceipt {
  let parsed: unknown
  if (typeof rawInput === 'string') {
    const byteLength = new TextEncoder().encode(rawInput).byteLength
    if (byteLength > MAX_COMPARABLE_RECEIPT_BYTES) {
      throw new Error('Receipt exceeds the 64 KB comparison size limit.')
    }
    try {
      parsed = JSON.parse(rawInput)
    } catch {
      throw new Error('Invalid or malformed verification receipt JSON.')
    }
  } else {
    parsed = rawInput
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Verification receipt must be a JSON object.')
  }

  const record = parsed as Record<string, unknown>
  const strippedPrivateKeys = collectStrippedPrivateKeys(record)

  const verifiedAt = requireNonEmptyString(
    record,
    ['verifiedAt', 'timestamp'],
    'verifiedAt',
  )
  if (Number.isNaN(Date.parse(verifiedAt))) {
    throw new Error(`Receipt timestamp "${verifiedAt}" is not a valid ISO-8601 timestamp.`)
  }

  const videoHash = assertValidVideoHash(
    requireNonEmptyString(record, ['videoHash'], 'videoHash'),
  )
  const proofId = requireNonEmptyString(record, ['proofId'], 'proofId').toLowerCase()
  const metadataHash = requireNonEmptyString(
    record,
    ['metadataHash'],
    'metadataHash',
  )
    .replace(/^0x/i, '')
    .toLowerCase()
  const networkPassphrase = requireNonEmptyString(
    record,
    ['networkPassphrase', 'network'],
    'networkPassphrase',
  )
  const contractId = requireNonEmptyString(record, ['contractId'], 'contractId')
  const result = optionalString(record, ['result', 'status']) ?? 'verified'
  const tier = optionalString(record, ['tier']) ?? 'silent'

  const ledgerRaw = record.ledgerSequence
  const ledgerSequence =
    typeof ledgerRaw === 'number' && Number.isInteger(ledgerRaw) && ledgerRaw >= 0
      ? ledgerRaw
      : null

  const transactionHash = optionalString(record, [
    'transactionHash',
    'transactionRef',
  ])

  const signerObj =
    record.signer && typeof record.signer === 'object' && !Array.isArray(record.signer)
      ? (record.signer as Record<string, unknown>)
      : null
  const signerKeyId = signerObj ? optionalString(signerObj, ['keyId']) : null

  const circuitVersion = optionalString(record, ['circuitVersion']) ?? '1'
  const verifierVersion = optionalString(record, ['verifierVersion']) ?? '1'

  return Object.freeze({
    verifiedAt,
    videoHash,
    proofId,
    metadataHash,
    result,
    tier,
    networkPassphrase,
    contractId,
    ledgerSequence,
    transactionHash,
    signerKeyId,
    circuitVersion,
    verifierVersion,
    strippedPrivateKeys: Object.freeze(strippedPrivateKeys),
  })
}

/**
 * Compares two verification receipts, preserving exact timestamps and
 * separating trust-standing changes from on-chain observation changes.
 */
export function compareVerificationReceipts(
  baselineInput: string | Record<string, unknown>,
  candidateInput: string | Record<string, unknown>,
): ReceiptComparisonReport {
  const baseline = parseComparableVerificationReceipt(baselineInput)
  const candidate = parseComparableVerificationReceipt(candidateInput)

  const sameStatement =
    baseline.videoHash === candidate.videoHash &&
    baseline.proofId === candidate.proofId &&
    baseline.metadataHash === candidate.metadataHash

  const specs: readonly {
    key: string
    label: string
    category: ReceiptObservationCategory
    base: string
    cand: string
  }[] = [
    {
      key: 'result',
      label: 'Verification result',
      category: 'trust',
      base: baseline.result,
      cand: candidate.result,
    },
    {
      key: 'tier',
      label: 'Identity tier',
      category: 'trust',
      base: baseline.tier,
      cand: candidate.tier,
    },
    {
      key: 'signerKeyId',
      label: 'Receipt signer key ID',
      category: 'trust',
      base: baseline.signerKeyId ?? 'Unsigned',
      cand: candidate.signerKeyId ?? 'Unsigned',
    },
    {
      key: 'verifierVersion',
      label: 'Verifier version',
      category: 'trust',
      base: baseline.verifierVersion,
      cand: candidate.verifierVersion,
    },
    {
      key: 'circuitVersion',
      label: 'Circuit version',
      category: 'trust',
      base: baseline.circuitVersion,
      cand: candidate.circuitVersion,
    },
    {
      key: 'networkPassphrase',
      label: 'Stellar network',
      category: 'chain',
      base: baseline.networkPassphrase,
      cand: candidate.networkPassphrase,
    },
    {
      key: 'contractId',
      label: 'Registry contract ID',
      category: 'chain',
      base: baseline.contractId,
      cand: candidate.contractId,
    },
    {
      key: 'ledgerSequence',
      label: 'Ledger sequence',
      category: 'chain',
      base: baseline.ledgerSequence !== null ? `#${baseline.ledgerSequence}` : 'Unrecorded',
      cand: candidate.ledgerSequence !== null ? `#${candidate.ledgerSequence}` : 'Unrecorded',
    },
    {
      key: 'transactionHash',
      label: 'Transaction hash',
      category: 'chain',
      base: baseline.transactionHash ?? 'Unrecorded',
      cand: candidate.transactionHash ?? 'Unrecorded',
    },
    {
      key: 'videoHash',
      label: 'Statement video hash',
      category: 'statement',
      base: baseline.videoHash,
      cand: candidate.videoHash,
    },
    {
      key: 'proofId',
      label: 'Proof ID',
      category: 'statement',
      base: baseline.proofId,
      cand: candidate.proofId,
    },
    {
      key: 'metadataHash',
      label: 'Metadata commitment',
      category: 'statement',
      base: baseline.metadataHash,
      cand: candidate.metadataHash,
    },
  ]

  const observations: readonly ReceiptFieldDiff[] = Object.freeze(
    specs.map((spec) =>
      Object.freeze({
        key: spec.key,
        label: spec.label,
        category: spec.category,
        baselineValue: spec.base,
        candidateValue: spec.cand,
        changed: spec.base !== spec.cand,
      }),
    ),
  )

  const changedTrustObservations = Object.freeze(
    observations.filter((obs) => obs.category === 'trust' && obs.changed),
  )
  const changedChainObservations = Object.freeze(
    observations.filter((obs) => obs.category === 'chain' && obs.changed),
  )
  const changedStatementFields = Object.freeze(
    observations.filter((obs) => obs.category === 'statement' && obs.changed),
  )

  const strippedPrivateFieldNames = Object.freeze(
    Array.from(
      new Set([
        ...baseline.strippedPrivateKeys,
        ...candidate.strippedPrivateKeys,
      ]),
    ).sort(),
  )

  return Object.freeze({
    sameStatement,
    baselineVerifiedAt: baseline.verifiedAt,
    candidateVerifiedAt: candidate.verifiedAt,
    baseline,
    candidate,
    observations,
    changedTrustObservations,
    changedChainObservations,
    changedStatementFields,
    strippedPrivateFieldNames,
  })
}

/**
 * Builds a privacy-preserving shareable URL fragment containing ONLY public
 * digests, exact timestamps, and public trust/chain diff keys — never private
 * evidence filenames, notes, paths, or witness material.
 */
export function createReceiptComparisonShareUrl(
  report: ReceiptComparisonReport,
  baseUrl = 'https://harpocrates.local/',
): string {
  const publicSharePayload = {
    protocol: 'harpocrates-receipt-comparison',
    version: 1,
    sameStatement: report.sameStatement,
    videoHash: report.candidate.videoHash,
    proofId: report.candidate.proofId,
    baselineVerifiedAt: report.baselineVerifiedAt,
    candidateVerifiedAt: report.candidateVerifiedAt,
    baselineResult: report.baseline.result,
    candidateResult: report.candidate.result,
    baselineLedger: report.baseline.ledgerSequence,
    candidateLedger: report.candidate.ledgerSequence,
    changedTrustKeys: report.changedTrustObservations.map((d) => d.key),
    changedChainKeys: report.changedChainObservations.map((d) => d.key),
  }
  const encoded = encodeBase64UrlUtf8(JSON.stringify(publicSharePayload))
  const cleanBase = baseUrl.split('#')[0]
  const fullUrl = `${cleanBase}#verify?compare=${encoded}`
  if (fullUrl.length > MAX_COMPARISON_SHARE_URL_BYTES) {
    throw new Error('Comparison share URL exceeds the maximum safe URL length.')
  }
  return fullUrl
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
