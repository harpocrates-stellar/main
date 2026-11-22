import type { BatchItemResult, BatchPreflightReport } from './batchVerifier'
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
 * Export privacy-safe JSON representation of batch results.
 */
export function exportBatchJSON(
  results: BatchItemResult[],
  preflight?: BatchPreflightReport | null,
): string {
  const clean = sanitizeBatchResults(results)
  const report: Record<string, unknown> = {
    protocol: 'harpocrates-batch-report',
    version: 1,
    exportedAt: new Date().toISOString(),
    totalCount: clean.length,
    results: clean,
  }
  if (preflight) {
    report.preflight = {
      totalFiles: preflight.totalFiles,
      totalBytes: preflight.totalBytes,
      validCount: preflight.validCount,
      duplicateCount: preflight.duplicateCount,
      unsupportedCount: preflight.unsupportedCount,
      oversizedCount: preflight.oversizedCount,
      canProceed: preflight.canProceed,
      hasIssues: preflight.hasIssues,
    }
  }
  return JSON.stringify(report, null, 2)
}

/**
 * Export preflight report as structured JSON.
 */
export function exportPreflightReportJSON(report: BatchPreflightReport): string {
  const exportData = {
    protocol: 'harpocrates-preflight-report',
    version: 1,
    exportedAt: report.completedAt || new Date().toISOString(),
    totalFiles: report.totalFiles,
    totalBytes: report.totalBytes,
    validCount: report.validCount,
    duplicateCount: report.duplicateCount,
    unsupportedCount: report.unsupportedCount,
    oversizedCount: report.oversizedCount,
    canProceed: report.canProceed,
    hasIssues: report.hasIssues,
    duplicates: report.duplicates,
    unsupported: report.unsupported,
    oversized: report.oversized,
  }
  return JSON.stringify(exportData, null, 2)
}

/**
 * Export preflight report issues and summary as CSV.
 */
export function exportPreflightReportCSV(report: BatchPreflightReport): string {
  const headers = ['Category', 'File Name', 'Size (Bytes)', 'Details', 'Reason']
  const rows: string[][] = []

  for (const item of report.duplicates) {
    rows.push([
      'Duplicate Input',
      escapeCSV(item.fileName),
      String(item.fileSizeBytes),
      escapeCSV(`Duplicate of ${item.duplicateOf}`),
      escapeCSV(item.reason),
    ])
  }

  for (const item of report.unsupported) {
    rows.push([
      'Unsupported Format',
      escapeCSV(item.fileName),
      String(item.fileSizeBytes),
      escapeCSV(`Type: ${item.mimeType || 'unknown'} | Ext: ${item.extension || 'none'}`),
      escapeCSV(item.reason),
    ])
  }

  for (const item of report.oversized) {
    rows.push([
      'Oversized',
      escapeCSV(item.fileName),
      String(item.fileSizeBytes),
      escapeCSV(`Limit: ${item.maxAllowedBytes} bytes`),
      escapeCSV(item.reason),
    ])
  }

  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
}

/**
 * Export privacy-safe CSV representation of batch results.
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
    escapeCSV(item.fileName),
    String(item.fileSizeBytes),
    escapeCSV(item.status),
    escapeCSV(item.videoHash ?? ''),
    escapeCSV(item.metadataHash ?? ''),
    escapeCSV(item.sourceHash ?? ''),
    escapeCSV(item.tier ?? ''),
    escapeCSV(item.chainStatus ?? ''),
    escapeCSV(item.message),
    escapeCSV(item.duplicateOf ?? ''),
    escapeCSV(item.failureReason ?? ''),
    item.durationMs !== null ? String(item.durationMs) : '',
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
  const needsQuotes = val.includes(',') || val.includes('"') || val.includes('\n')
  const escaped = val.replace(/"/g, '""')
  return needsQuotes ? `"${escaped}"` : escaped
}
