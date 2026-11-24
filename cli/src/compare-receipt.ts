import { resolveNetwork } from './network.js'
import { decodeReceiptFromQr, type SignedVerificationReceipt } from './signed-receipt.js'
import type { VerificationReceipt } from './receipt.js'

export type ReceiptCategory = 'statement' | 'trust'

export interface ReceiptDifference {
  category: ReceiptCategory
  field: string
  base: unknown
  target: unknown
}

export interface ReceiptComparisonResult {
  match: boolean
  statementMatch: boolean
  trustMatch: boolean
  differences: ReceiptDifference[]
  statementDifferences: ReceiptDifference[]
  trustDifferences: ReceiptDifference[]
  summary: {
    totalDifferences: number
    statementDifferencesCount: number
    trustDifferencesCount: number
  }
}

export interface NormalizedCanonicalStatement {
  proofId: string | null
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  tier: string | null
  circuitVersion: string | null
  verifierScope: string | null
  epoch: number | null
  scopeName: string | null
  selectiveDisclosure: string[] | null
}

export interface NormalizedTrustProperties {
  network: string | null
  contractId: string | null
  result: string | null
  transactionHash: string | null
  transactionStatus: string | null
  ledgerSequence: number | null
  signerKeyId: string | null
  signerAlgorithm: string | null
  chainRecordStatus: string | null
  chainRecordIssuer: string | null
  chainRecordExpiresAt: string | null
  verifierVersion: string | null
}

export interface NormalizedReceipt {
  statement: NormalizedCanonicalStatement
  trust: NormalizedTrustProperties
  raw: unknown
}

function normalizeHash(value: unknown): string | null {
  if (value === null || value === undefined) return null
  if (typeof value === 'string') {
    const trimmed = value.trim().toLowerCase()
    return trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed
  }
  return String(value).trim().toLowerCase()
}

function normalizeString(value: unknown): string | null {
  if (value === null || value === undefined) return null
  const str = String(value).trim()
  return str.length > 0 ? str : null
}

function normalizeNumber(value: unknown): number | null {
  if (value === null || value === undefined) return null
  const num = Number(value)
  return Number.isFinite(num) ? num : null
}

function normalizeArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null
  return value.map((v) => String(v).trim()).sort()
}

function normalizeNetworkValue(value: unknown): string | null {
  if (value === null || value === undefined) return null
  const str = String(value).trim()
  if (str.length === 0) return null
  return resolveNetwork(str)
}

function isRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val)
}

/**
 * Parses raw text input into a receipt object.
 * Supports standard JSON (VerificationReceipt or SignedVerificationReceipt)
 * as well as base64url-encoded QR payloads.
 */
export function parseReceiptInput(rawText: string): unknown {
  const trimmed = rawText.trim()
  if (trimmed.length === 0) {
    throw new Error('empty receipt content')
  }

  if (trimmed.startsWith('{')) {
    try {
      return JSON.parse(trimmed)
    } catch (err) {
      throw new Error(`invalid receipt JSON: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  try {
    return decodeReceiptFromQr(trimmed)
  } catch (err) {
    throw new Error(`invalid receipt format: ${err instanceof Error ? err.message : String(err)}`)
  }
}

/**
 * Normalizes either a VerificationReceipt, SignedVerificationReceipt,
 * or raw receipt dictionary into unified statement and trust models.
 */
export function normalizeReceipt(input: unknown): NormalizedReceipt {
  if (!isRecord(input)) {
    throw new Error('receipt must be a valid JSON object')
  }

  // Check if input is a VerificationReceipt (has .manifest property)
  const manifest = isRecord(input.manifest) ? input.manifest : null
  const transaction = isRecord(input.transaction) ? input.transaction : null
  const chainRecord = isRecord(input.chainRecord) ? input.chainRecord : null
  const signer = isRecord(input.signer) ? input.signer : null

  const statement: NormalizedCanonicalStatement = {
    proofId: normalizeHash(manifest?.proofId ?? input.proofId),
    videoHash: normalizeHash(manifest?.videoHash ?? chainRecord?.videoHash ?? input.videoHash),
    metadataHash: normalizeHash(manifest?.metadataHash ?? chainRecord?.metadataHash ?? input.metadataHash),
    sourceHash: normalizeHash(manifest?.sourceHash ?? chainRecord?.source ?? input.sourceHash),
    tier: normalizeString(manifest?.tier ?? chainRecord?.tier ?? input.tier),
    circuitVersion: normalizeString(manifest?.circuitVersion ?? input.circuitVersion),
    verifierScope: normalizeString(manifest?.verifierScope ?? input.verifierScope),
    epoch: normalizeNumber(manifest?.epoch ?? input.epoch),
    scopeName: normalizeString(manifest?.scopeName ?? input.scopeName),
    selectiveDisclosure: normalizeArray(manifest?.selectiveDisclosure ?? input.selectiveDisclosure),
  }

  const rawNetwork = input.networkPassphrase ?? manifest?.network ?? input.network
  const network = normalizeNetworkValue(rawNetwork)

  const contractId = normalizeString(manifest?.contractId ?? input.contractId)

  // Normalize result: 'valid', 'verified', 'revoked', 'expired', etc.
  const rawResult = input.result
  const result = normalizeString(rawResult)

  const transactionHash = normalizeHash(transaction?.txHash ?? input.transactionHash ?? manifest?.transactionRef)
  const transactionStatus = normalizeString(transaction?.status ?? input.transactionStatus)
  const ledgerSequence = normalizeNumber(transaction?.ledger ?? input.ledgerSequence ?? input.ledger)

  const signerKeyId = normalizeString(signer?.keyId ?? input.signerKeyId)
  const signerAlgorithm = normalizeString(signer?.algorithm ?? input.signerAlgorithm)

  const chainRecordStatus = normalizeString(chainRecord?.status ?? input.chainRecordStatus)
  const chainRecordIssuer = normalizeString(chainRecord?.issuer ?? input.chainRecordIssuer)
  const chainRecordExpiresAt = normalizeString(chainRecord?.expiresAt ?? input.chainRecordExpiresAt)

  const verifierVersion = normalizeString(input.verifierVersion)

  const trust: NormalizedTrustProperties = {
    network,
    contractId,
    result,
    transactionHash,
    transactionStatus,
    ledgerSequence,
    signerKeyId,
    signerAlgorithm,
    chainRecordStatus,
    chainRecordIssuer,
    chainRecordExpiresAt,
    verifierVersion,
  }

  return { statement, trust, raw: input }
}

function valuesEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (a === null || a === undefined) return b === null || b === undefined
  if (b === null || b === undefined) return false

  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false
    }
    return true
  }

  return JSON.stringify(a) === JSON.stringify(b)
}

/**
 * Compare two receipts and extract canonical statement and trust differences.
 */
export function compareReceipts(baseInput: unknown, targetInput: unknown): ReceiptComparisonResult {
  const base = normalizeReceipt(baseInput)
  const target = normalizeReceipt(targetInput)

  const statementDifferences: ReceiptDifference[] = []
  const trustDifferences: ReceiptDifference[] = []

  // Compare canonical statement fields in stable order
  const statementFields: Array<keyof NormalizedCanonicalStatement> = [
    'proofId',
    'videoHash',
    'metadataHash',
    'sourceHash',
    'tier',
    'circuitVersion',
    'verifierScope',
    'epoch',
    'scopeName',
    'selectiveDisclosure',
  ]

  for (const field of statementFields) {
    const baseVal = base.statement[field]
    const targetVal = target.statement[field]
    if (!valuesEqual(baseVal, targetVal)) {
      statementDifferences.push({
        category: 'statement',
        field,
        base: baseVal,
        target: targetVal,
      })
    }
  }

  // Compare trust properties in stable order
  const trustFields: Array<keyof NormalizedTrustProperties> = [
    'network',
    'contractId',
    'result',
    'transactionHash',
    'transactionStatus',
    'ledgerSequence',
    'signerKeyId',
    'signerAlgorithm',
    'chainRecordStatus',
    'chainRecordIssuer',
    'chainRecordExpiresAt',
    'verifierVersion',
  ]

  for (const field of trustFields) {
    const baseVal = base.trust[field]
    const targetVal = target.trust[field]
    if (!valuesEqual(baseVal, targetVal)) {
      trustDifferences.push({
        category: 'trust',
        field,
        base: baseVal,
        target: targetVal,
      })
    }
  }

  const differences = [...statementDifferences, ...trustDifferences]
  const statementMatch = statementDifferences.length === 0
  const trustMatch = trustDifferences.length === 0
  const match = statementMatch && trustMatch

  return {
    match,
    statementMatch,
    trustMatch,
    differences,
    statementDifferences,
    trustDifferences,
    summary: {
      totalDifferences: differences.length,
      statementDifferencesCount: statementDifferences.length,
      trustDifferencesCount: trustDifferences.length,
    },
  }
}

function formatValue(val: unknown): string {
  if (val === null || val === undefined) return '<none>'
  if (Array.isArray(val)) return JSON.stringify(val)
  return String(val)
}

/**
 * Format comparison results into human-readable text output.
 */
export function formatComparisonResult(result: ReceiptComparisonResult): string {
  const lines: string[] = [
    '═══════════════════════════════════════════',
    '  Harpocrates Receipt Comparison',
    '═══════════════════════════════════════════',
    '',
    `Status: ${result.match ? '✅ IDENTICAL' : '❌ DIFFERENCES DETECTED'}`,
    '',
  ]

  // Statement Section
  if (result.statementMatch) {
    lines.push('Canonical Statement: ✅ MATCH (all proof statement attributes identical)')
  } else {
    lines.push(`Canonical Statement: ❌ MISMATCH (${result.statementDifferences.length} difference${result.statementDifferences.length === 1 ? '' : 's'})`)
    for (const diff of result.statementDifferences) {
      lines.push(`  - ${diff.field}:`)
      lines.push(`      Base:   ${formatValue(diff.base)}`)
      lines.push(`      Target: ${formatValue(diff.target)}`)
    }
  }
  lines.push('')

  // Trust Section
  if (result.trustMatch) {
    lines.push('Trust & Environment: ✅ MATCH (all trust and deployment attributes identical)')
  } else {
    lines.push(`Trust & Environment: ❌ MISMATCH (${result.trustDifferences.length} difference${result.trustDifferences.length === 1 ? '' : 's'})`)
    for (const diff of result.trustDifferences) {
      lines.push(`  - ${diff.field}:`)
      lines.push(`      Base:   ${formatValue(diff.base)}`)
      lines.push(`      Target: ${formatValue(diff.target)}`)
    }
  }
  lines.push('')

  // Summary
  lines.push('Summary:')
  lines.push(`  Statement match: ${result.statementMatch ? 'YES' : 'NO'}${result.statementDifferences.length > 0 ? ` (${result.statementDifferences.length} difference${result.statementDifferences.length === 1 ? '' : 's'})` : ''}`)
  lines.push(`  Trust match:     ${result.trustMatch ? 'YES' : 'NO'}${result.trustDifferences.length > 0 ? ` (${result.trustDifferences.length} difference${result.trustDifferences.length === 1 ? '' : 's'})` : ''}`)
  lines.push(`  Overall match:   ${result.match ? 'YES' : 'NO'}`)
  lines.push('═══════════════════════════════════════════')

  return lines.join('\n')
}
