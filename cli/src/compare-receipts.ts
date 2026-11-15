import { parseC2paReceiptInput, assertC2paInputWithinLimit } from './c2pa.js'
import { canonicalHash } from './hashing.js'
import { ALLOWED_TIERS, type IdentityTier } from './metadata.js'
import type { VerificationReceipt } from './receipt.js'
import {
  decodeReceiptFromQr,
  verifyVerificationReceipt,
  type SignedVerificationReceipt,
} from './signed-receipt.js'

export const RECEIPT_COMPARISON_PROTOCOL = 'harpocrates-receipt-comparison' as const
export const RECEIPT_COMPARISON_VERSION = 1 as const

export type ReceiptFormatKind = 'verification-receipt' | 'signed-receipt'

export type ReceiptFieldDifference = {
  field: string
  left: unknown
  right: unknown
}

export type CanonicalStatementSummary = {
  proofId: string
  videoHash: string
  metadataHash: string
  sourceHash: string | null
  tier: IdentityTier
  manifestVersion: number | null
  timestamp: string | null
  verifierScope: string | null
  epoch: number | null
  scopeName: string | null
  circuitVersion: string | null
  selectiveDisclosure: {
    circuitVersion: number
    predicateCommitment: string
    publicInputs: string
    schemaHash: string
  } | null
}

export type CanonicalTrustSummary = {
  receiptKind: ReceiptFormatKind
  outcomeCategory: 'trusted' | 'untrusted' | 'incomplete'
  rawResult: string
  network: string
  contractId: string
  transactionHash: string | null
  transactionStatus: string | null
  ledgerSequence: number | null
  chainStatus: number | null
  chainExpiresAt: string | null
  verifierVersion: string | null
  signerKeyId: string | null
  signerAlgorithm: string | null
  signatureStatus: 'valid' | 'invalid' | 'unchecked' | 'unsigned'
  signatureReason: string | null
}

export type ReceiptComparisonReport = {
  protocol: typeof RECEIPT_COMPARISON_PROTOCOL
  version: typeof RECEIPT_COMPARISON_VERSION
  equivalent: boolean
  statementEqual: boolean
  trustEqual: boolean
  leftKind: ReceiptFormatKind
  rightKind: ReceiptFormatKind
  statementDigestLeft: string
  statementDigestRight: string
  trustDigestLeft: string
  trustDigestRight: string
  statementDifferences: ReceiptFieldDifference[]
  trustDifferences: ReceiptFieldDifference[]
  observationMetadata: {
    leftVerifiedAt: string
    rightVerifiedAt: string
    verifiedAtChanged: boolean
  }
}

export type CompareReceiptsOptions = {
  keys?: Record<string, JsonWebKey>
  now?: Date
}

type NormalizedReceiptView = {
  kind: ReceiptFormatKind
  verifiedAt: string
  statement: CanonicalStatementSummary
  trust: CanonicalTrustSummary
}

const HEX32_RE = /^[0-9a-fA-F]{64}$/
const FORBIDDEN_PRIVATE_KEYS = new Set([
  'secret',
  'signerSecret',
  'privateKey',
  'seed',
  'witness',
  'witnessData',
  'proofBytes',
])

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasForbiddenPrivateKeys(value: unknown, depth = 0): boolean {
  if (depth > 8) return false
  if (Array.isArray(value)) {
    return value.some((entry) => hasForbiddenPrivateKeys(entry, depth + 1))
  }
  if (!isPlainObject(value)) return false
  for (const [k, v] of Object.entries(value)) {
    if (FORBIDDEN_PRIVATE_KEYS.has(k)) return true
    if (hasForbiddenPrivateKeys(v, depth + 1)) return true
  }
  return false
}

function canonicalizeValue(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalizeValue).join(',')}]`
  const rec = value as Record<string, unknown>
  const entries = Object.keys(rec)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalizeValue(rec[key])}`)
  return `{${entries.join(',')}}`
}

function validateSignedReceiptShape(raw: unknown): SignedVerificationReceipt {
  if (!isPlainObject(raw)) {
    throw new Error('signed receipt must be a JSON object')
  }
  if (raw.protocol !== 'harpocrates-verification-receipt' || raw.version !== 1) {
    throw new Error('unsupported signed receipt version')
  }
  if (raw.result !== 'verified' && raw.result !== 'unverified') {
    throw new Error('signed receipt result is invalid')
  }
  if (
    typeof raw.proofId !== 'string' ||
    !HEX32_RE.test(raw.proofId) ||
    typeof raw.videoHash !== 'string' ||
    !HEX32_RE.test(raw.videoHash) ||
    typeof raw.metadataHash !== 'string' ||
    !HEX32_RE.test(raw.metadataHash)
  ) {
    throw new Error('signed receipt digests must be 32-byte hex strings')
  }
  if (typeof raw.tier !== 'string' || !ALLOWED_TIERS.has(raw.tier)) {
    throw new Error('signed receipt tier is invalid')
  }
  if (
    typeof raw.networkPassphrase !== 'string' ||
    raw.networkPassphrase.trim() === '' ||
    typeof raw.contractId !== 'string' ||
    raw.contractId.trim() === '' ||
    typeof raw.circuitVersion !== 'string' ||
    raw.circuitVersion.trim() === '' ||
    typeof raw.verifierVersion !== 'string' ||
    raw.verifierVersion.trim() === ''
  ) {
    throw new Error('signed receipt metadata is incomplete')
  }
  if (
    !isPlainObject(raw.signer) ||
    typeof raw.signer.keyId !== 'string' ||
    raw.signer.keyId.trim() === '' ||
    raw.signer.algorithm !== 'ECDSA_P256_SHA256'
  ) {
    throw new Error('signed receipt signer is invalid')
  }
  if (raw.ledgerSequence !== null && (!Number.isSafeInteger(raw.ledgerSequence) || (raw.ledgerSequence as number) < 0)) {
    throw new Error('signed receipt ledgerSequence is invalid')
  }
  if (raw.transactionHash !== null && (typeof raw.transactionHash !== 'string' || !HEX32_RE.test(raw.transactionHash))) {
    throw new Error('signed receipt transactionHash is invalid')
  }
  if (typeof raw.verifiedAt !== 'string' || Number.isNaN(Date.parse(raw.verifiedAt))) {
    throw new Error('signed receipt verifiedAt is invalid')
  }
  if (typeof raw.signature !== 'string' || raw.signature.trim() === '') {
    throw new Error('signed receipt signature is missing')
  }
  return raw as unknown as SignedVerificationReceipt
}

async function parseAndNormalizeReceipt(
  rawInput: string,
  options: CompareReceiptsOptions,
): Promise<NormalizedReceiptView> {
  assertC2paInputWithinLimit(rawInput, 'receipt')
  const trimmed = rawInput.trim()
  if (trimmed === '') {
    throw new Error('receipt input is empty')
  }

  let parsedObj: unknown
  if (trimmed.startsWith('{')) {
    try {
      parsedObj = JSON.parse(trimmed)
    } catch {
      throw new Error('receipt is not valid JSON')
    }
  } else {
    parsedObj = decodeReceiptFromQr(trimmed)
  }

  if (!isPlainObject(parsedObj)) {
    throw new Error('receipt must be a JSON object')
  }
  if (hasForbiddenPrivateKeys(parsedObj)) {
    throw new Error('receipt contains forbidden private or secret fields')
  }

  if (parsedObj.protocol === 'harpocrates-verification-receipt') {
    const sr = validateSignedReceiptShape(parsedObj)
    let signatureStatus: CanonicalTrustSummary['signatureStatus'] = 'unchecked'
    let signatureReason: string | null = null
    if (options.keys !== undefined) {
      const verification = await verifyVerificationReceipt(sr, {
        keys: options.keys,
        now: options.now,
      })
      if (verification.valid) {
        signatureStatus = 'valid'
      } else {
        signatureStatus = 'invalid'
        signatureReason = verification.reason
      }
    }

    const outcomeCategory: CanonicalTrustSummary['outcomeCategory'] =
      sr.result === 'verified' && signatureStatus !== 'invalid' ? 'trusted' : 'untrusted'

    return {
      kind: 'signed-receipt',
      verifiedAt: sr.verifiedAt,
      statement: {
        proofId: sr.proofId.toLowerCase(),
        videoHash: sr.videoHash.toLowerCase(),
        metadataHash: sr.metadataHash.toLowerCase(),
        sourceHash: null,
        tier: sr.tier,
        manifestVersion: null,
        timestamp: null,
        verifierScope: null,
        epoch: null,
        scopeName: null,
        circuitVersion: sr.circuitVersion,
        selectiveDisclosure: null,
      },
      trust: {
        receiptKind: 'signed-receipt',
        outcomeCategory,
        rawResult: sr.result,
        network: sr.networkPassphrase,
        contractId: sr.contractId,
        transactionHash: sr.transactionHash ? sr.transactionHash.toLowerCase() : null,
        transactionStatus: null,
        ledgerSequence: sr.ledgerSequence,
        chainStatus: null,
        chainExpiresAt: null,
        verifierVersion: sr.verifierVersion,
        signerKeyId: sr.signer.keyId,
        signerAlgorithm: sr.signer.algorithm,
        signatureStatus,
        signatureReason,
      },
    }
  }

  const vr: VerificationReceipt = parseC2paReceiptInput(parsedObj)
  const sd = vr.manifest.selectiveDisclosure
    ? {
        circuitVersion: vr.manifest.selectiveDisclosure.circuitVersion,
        predicateCommitment: vr.manifest.selectiveDisclosure.predicateCommitment.toLowerCase(),
        publicInputs: vr.manifest.selectiveDisclosure.publicInputs.toLowerCase(),
        schemaHash: vr.manifest.selectiveDisclosure.schemaHash.toLowerCase(),
      }
    : null

  const outcomeCategory: CanonicalTrustSummary['outcomeCategory'] =
    vr.result === 'valid'
      ? 'trusted'
      : vr.result === 'pending'
        ? 'incomplete'
        : 'untrusted'

  return {
    kind: 'verification-receipt',
    verifiedAt: vr.verifiedAt,
    statement: {
      proofId: vr.manifest.proofId.toLowerCase(),
      videoHash: vr.manifest.videoHash.toLowerCase(),
      metadataHash: vr.manifest.metadataHash.toLowerCase(),
      sourceHash: vr.manifest.sourceHash.toLowerCase(),
      tier: vr.manifest.tier,
      manifestVersion: vr.manifest.version,
      timestamp: vr.manifest.timestamp,
      verifierScope: vr.manifest.verifierScope ?? null,
      epoch: vr.manifest.epoch ?? null,
      scopeName: vr.manifest.scopeName ?? null,
      circuitVersion: sd ? String(sd.circuitVersion) : null,
      selectiveDisclosure: sd,
    },
    trust: {
      receiptKind: 'verification-receipt',
      outcomeCategory,
      rawResult: vr.result,
      network: vr.manifest.network,
      contractId: vr.manifest.contractId,
      transactionHash: vr.transaction.txHash.toLowerCase(),
      transactionStatus: vr.transaction.status,
      ledgerSequence: vr.transaction.ledger ?? null,
      chainStatus: vr.chainRecord ? vr.chainRecord.status : null,
      chainExpiresAt: vr.chainRecord?.expiresAt ?? null,
      verifierVersion: null,
      signerKeyId: null,
      signerAlgorithm: null,
      signatureStatus: 'unsigned',
      signatureReason: null,
    },
  }
}

function diffRecords(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
  fields: readonly string[],
): ReceiptFieldDifference[] {
  const diffs: ReceiptFieldDifference[] = []
  for (const field of [...fields].sort()) {
    const lVal = left[field] ?? null
    const rVal = right[field] ?? null
    if (canonicalizeValue(lVal) !== canonicalizeValue(rVal)) {
      diffs.push({ field, left: lVal, right: rVal })
    }
  }
  return diffs
}

const ALL_STATEMENT_FIELDS: ReadonlyArray<keyof CanonicalStatementSummary> = [
  'circuitVersion',
  'epoch',
  'manifestVersion',
  'metadataHash',
  'proofId',
  'scopeName',
  'selectiveDisclosure',
  'sourceHash',
  'tier',
  'timestamp',
  'verifierScope',
  'videoHash',
]

const SHARED_CROSS_KIND_STATEMENT_FIELDS: ReadonlyArray<keyof CanonicalStatementSummary> = [
  'circuitVersion',
  'metadataHash',
  'proofId',
  'tier',
  'videoHash',
]

const ALL_TRUST_FIELDS: ReadonlyArray<keyof CanonicalTrustSummary> = [
  'chainExpiresAt',
  'chainStatus',
  'contractId',
  'ledgerSequence',
  'network',
  'outcomeCategory',
  'rawResult',
  'receiptKind',
  'signatureReason',
  'signatureStatus',
  'signerAlgorithm',
  'signerKeyId',
  'transactionHash',
  'transactionStatus',
  'verifierVersion',
]

/**
 * Offline, deterministic comparison of two Harpocrates verification receipts
 * (`VerificationReceipt` or `SignedVerificationReceipt`, JSON or QR payload).
 *
 * Separates canonical statement identity differences from trust-context
 * differences without performing any live network calls.
 */
export async function compareReceipts(
  rawLeft: string,
  rawRight: string,
  options: CompareReceiptsOptions = {},
): Promise<ReceiptComparisonReport> {
  const left = await parseAndNormalizeReceipt(rawLeft, options)
  const right = await parseAndNormalizeReceipt(rawRight, options)

  const sameKind = left.kind === right.kind
  const statementFields = sameKind
    ? ALL_STATEMENT_FIELDS
    : SHARED_CROSS_KIND_STATEMENT_FIELDS

  const statementDifferences = diffRecords(
    left.statement as unknown as Record<string, unknown>,
    right.statement as unknown as Record<string, unknown>,
    statementFields,
  )

  const trustDifferences = diffRecords(
    left.trust as unknown as Record<string, unknown>,
    right.trust as unknown as Record<string, unknown>,
    ALL_TRUST_FIELDS,
  )

  // Fail closed when --keys detected an invalid signature on either receipt, even if both failed identically.
  const hasInvalidSignature =
    left.trust.signatureStatus === 'invalid' || right.trust.signatureStatus === 'invalid'

  const statementDigestLeft = canonicalHash(
    Object.fromEntries(statementFields.map((f) => [f, left.statement[f]])),
  )
  const statementDigestRight = canonicalHash(
    Object.fromEntries(statementFields.map((f) => [f, right.statement[f]])),
  )
  const trustDigestLeft = canonicalHash(left.trust as unknown as Record<string, unknown>)
  const trustDigestRight = canonicalHash(right.trust as unknown as Record<string, unknown>)

  const statementEqual = statementDifferences.length === 0
  const trustEqual = trustDifferences.length === 0 && !hasInvalidSignature

  return {
    protocol: RECEIPT_COMPARISON_PROTOCOL,
    version: RECEIPT_COMPARISON_VERSION,
    equivalent: statementEqual && trustEqual,
    statementEqual,
    trustEqual,
    leftKind: left.kind,
    rightKind: right.kind,
    statementDigestLeft,
    statementDigestRight,
    trustDigestLeft,
    trustDigestRight,
    statementDifferences,
    trustDifferences,
    observationMetadata: {
      leftVerifiedAt: left.verifiedAt,
      rightVerifiedAt: right.verifiedAt,
      verifiedAtChanged: left.verifiedAt !== right.verifiedAt,
    },
  }
}

/**
 * Deterministic canonical JSON serialization (sorted object keys recursively)
 * for machine-readable output.
 */
export function serializeReceiptComparison(report: ReceiptComparisonReport): string {
  const sortDeep = (val: unknown): unknown => {
    if (Array.isArray(val)) return val.map(sortDeep)
    if (isPlainObject(val)) {
      const sorted: Record<string, unknown> = {}
      for (const k of Object.keys(val).sort()) {
        sorted[k] = sortDeep(val[k])
      }
      return sorted
    }
    return val
  }
  return JSON.stringify(sortDeep(report), null, 2)
}

/**
 * Format a human-readable summary separating canonical statement differences
 * from trust-context differences.
 */
export function formatReceiptComparison(report: ReceiptComparisonReport): string {
  const lines = [
    `Receipt Comparison: ${report.equivalent ? 'EQUIVALENT' : 'DIFFERENT'}`,
    `Left kind:          ${report.leftKind} (verifiedAt=${report.observationMetadata.leftVerifiedAt})`,
    `Right kind:         ${report.rightKind} (verifiedAt=${report.observationMetadata.rightVerifiedAt})`,
    `Statement equal:    ${report.statementEqual ? 'yes' : 'no'} (${report.statementDifferences.length} difference(s))`,
  ]
  for (const diff of report.statementDifferences) {
    lines.push(`  [statement] ${diff.field}: ${JSON.stringify(diff.left)} -> ${JSON.stringify(diff.right)}`)
  }
  lines.push(
    `Trust equal:        ${report.trustEqual ? 'yes' : 'no'} (${report.trustDifferences.length} difference(s))`,
  )
  for (const diff of report.trustDifferences) {
    lines.push(`  [trust] ${diff.field}: ${JSON.stringify(diff.left)} -> ${JSON.stringify(diff.right)}`)
  }
  return lines.join('\n')
}
