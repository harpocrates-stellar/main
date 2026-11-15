import type { BatchItemResult } from './batchVerifier'
import type { ProofManifest } from './proofManifest'

export type CleanBatchReportItem = {
  fileName: string
  fileSizeBytes: number
  status: string
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  tier: string | null
  chainStatus: string | null
  message: string
  duplicateOf: string | null
  failureReason: string | null
  durationMs: number | null
}

export type ReceiptCollection = {
  protocol: 'harpocrates-receipt-collection'
  version: 1
  exportedAt: string
  totalItems: number
  receipts: ProofManifest[]
}

export const SPREADSHEET_FORMULA_TRIGGERS = ['=', '+', '-', '@', '\t', '\r', '\n'] as const

export const BATCH_EXPORT_FORMAT_SEMANTICS = {
  csv: {
    audience: 'human-spreadsheet',
    neutralizesFormulaPrefixes: true,
    preservesExactDigestsAndAmounts: true,
  },
  json: {
    audience: 'machine-readable',
    neutralizesFormulaPrefixes: false,
    preservesExactDigestsAndAmounts: true,
  },
} as const

/**
 * Strips raw File handles and sensitive memory states, returning a clean,
 * privacy-safe serializable representation of batch verification results.
 */
export function sanitizeBatchResults(results: BatchItemResult[]): CleanBatchReportItem[] {
  return results.map((item) => ({
    fileName: item.fileName,
    fileSizeBytes: item.fileSizeBytes,
    status: item.status,
    videoHash: item.videoHash,
    metadataHash: item.metadataHash,
    sourceHash: item.sourceHash,
    tier: item.tier,
    chainStatus: item.chainStatus,
    message: item.message,
    duplicateOf: item.duplicateOf,
    failureReason: item.failureReason,
    durationMs: item.durationMs ? Math.round(item.durationMs) : null,
  }))
}

/**
 * Export machine-readable, privacy-safe JSON representation of batch results.
 * Unlike human-oriented CSV exports, JSON preserves exact unescaped string fields
 * without spreadsheet formula-prefix neutralization.
 */
export function exportBatchJSON(results: BatchItemResult[]): string {
  const clean = sanitizeBatchResults(results)
  const report = {
    protocol: 'harpocrates-batch-report',
    version: 1,
    exportedAt: new Date().toISOString(),
    totalCount: clean.length,
    results: clean,
  }
  return JSON.stringify(report, null, 2)
}

/**
 * Neutralizes spreadsheet formula injection prefixes (`=`, `+`, `-`, `@`,
 * leading tabs/newlines, or whitespace-padded formula prefixes) for
 * human-oriented CSV text cells by prepending a literal single quote (`'`).
 */
export function neutralizeSpreadsheetFormula(val: string): string {
  if (!val) return ''
  const firstChar = val[0]
  if (
    firstChar === '=' ||
    firstChar === '+' ||
    firstChar === '-' ||
    firstChar === '@' ||
    firstChar === '\t' ||
    firstChar === '\r' ||
    firstChar === '\n'
  ) {
    return `'${val}`
  }
  const trimmedLeading = val.replace(/^[ \t\r\n]+/, '')
  if (
    trimmedLeading.length > 0 &&
    (trimmedLeading[0] === '=' ||
      trimmedLeading[0] === '+' ||
      trimmedLeading[0] === '-' ||
      trimmedLeading[0] === '@')
  ) {
    return `'${val}`
  }
  return val
}

function formatExactDigestCell(digest: string | null): string {
  if (!digest) return '""'
  if (/^[0-9a-fA-F]+$/.test(digest)) {
    return digest
  }
  return escapeHumanCSVCell(digest)
}

function formatExactNumericAmountCell(amount: number | null): string {
  if (amount === null || !Number.isFinite(amount)) return ''
  return String(amount)
}

function escapeHumanCSVCell(val: string): string {
  if (!val) return '""'
  return escapeCSV(neutralizeSpreadsheetFormula(val))
}

/**
 * Export human-oriented, privacy-safe CSV representation of batch results.
 * Risky spreadsheet formula prefixes in text columns are neutralized with a
 * leading `'`, while canonical digest columns and numeric amount columns are
 * emitted verbatim. Use `exportBatchJSON` for exact machine-readable strings.
 */
export function exportBatchCSV(results: BatchItemResult[]): string {
  const clean = sanitizeBatchResults(results)
  const headers = [
    'File Name',
    'Size (Bytes)',
    'Status',
    'Video Hash',
    'Metadata Hash',
    'Source Hash',
    'Tier',
    'Chain Status',
    'Message',
    'Duplicate Of',
    'Failure Reason',
    'Duration (ms)',
  ]

  const rows = clean.map((item) => [
    escapeHumanCSVCell(item.fileName),
    formatExactNumericAmountCell(item.fileSizeBytes),
    escapeHumanCSVCell(item.status),
    formatExactDigestCell(item.videoHash),
    formatExactDigestCell(item.metadataHash),
    formatExactDigestCell(item.sourceHash),
    escapeHumanCSVCell(item.tier ?? ''),
    escapeHumanCSVCell(item.chainStatus ?? ''),
    escapeHumanCSVCell(item.message),
    escapeHumanCSVCell(item.duplicateOf ?? ''),
    escapeHumanCSVCell(item.failureReason ?? ''),
    formatExactNumericAmountCell(item.durationMs),
  ])

  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
}

/**
 * Export standalone collection of valid ProofManifest receipts from the batch.
 */
export function exportReceiptCollection(results: BatchItemResult[]): string {
  const manifests: ProofManifest[] = []

  for (const item of results) {
    if (item.manifest) {
      manifests.push(item.manifest)
    } else if (item.status === 'confirmed' && item.videoHash && item.metadataHash && item.tier) {
      manifests.push({
        protocol: 'harpocrates',
        version: 1,
        proofId: item.chainProof?.metadataHash ?? item.videoHash,
        tier: (item.tier as 'silent' | 'source' | 'seal') || 'source',
        network: 'testnet',
        contractId: item.chainProof?.issuer ?? '',
        transactionRef: item.events[0]?.tx_hash ?? '',
        videoHash: item.videoHash,
        metadataHash: item.metadataHash,
        sourceHash: item.sourceHash ?? item.videoHash,
        timestamp: new Date().toISOString(),
        verifierScope: '0',
        epoch: 0,
      })
    }
  }

  const collection: ReceiptCollection = {
    protocol: 'harpocrates-receipt-collection',
    version: 1,
    exportedAt: new Date().toISOString(),
    totalItems: manifests.length,
    receipts: manifests,
  }

  return JSON.stringify(collection, null, 2)
}

function escapeCSV(val: string): string {
  if (!val) return '""'
  const needsQuotes = val.includes(',') || val.includes('"') || val.includes('\n') || val.includes('\r')
  const escaped = val.replace(/"/g, '""')
  return needsQuotes ? `"${escaped}"` : escaped
}
