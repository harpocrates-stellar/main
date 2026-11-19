import type { BatchItemResult } from './batchVerifier'
import type { ProofManifest } from './proofManifest'

export type StatementConflict = {
  identifier: string
  identifierType: 'videoHash' | 'metadataHash' | 'proofId'
  firstFileName: string
  conflictingFileName: string
  reason: string
}

/**
 * Error thrown when a batch export is rejected due to duplicate conflicting
 * statement identifiers across result rows.
 */
export class BatchExportConflictError extends Error {
  readonly conflicts: StatementConflict[]

  constructor(conflicts: StatementConflict[]) {
    const summary = conflicts
      .map(
        (c) =>
          `${c.identifierType} "${c.identifier}" (${c.firstFileName} vs ${c.conflictingFileName}): ${c.reason}`,
      )
      .join('; ')
    super(`Batch export rejected due to conflicting statement identifiers: ${summary}`)
    this.name = 'BatchExportConflictError'
    this.conflicts = conflicts
  }
}

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
 * Detects contradictory result rows that share a statement identifier
 * (`videoHash`, `metadataHash`, or `manifest.proofId`) with conflicting
 * verification outcomes or claims.
 *
 * Rows marked with `status === 'duplicate'` are excluded from conflict checks
 * because they represent expected duplicate-file detections from batch hashing.
 */
export function detectConflictingStatements(results: BatchItemResult[]): StatementConflict[] {
  const conflicts: StatementConflict[] = []
  const byVideoHash = new Map<string, BatchItemResult>()
  const byMetadataHash = new Map<string, BatchItemResult>()
  const byProofId = new Map<string, BatchItemResult>()

  for (const item of results) {
    if (item.status === 'duplicate') {
      continue
    }

    if (item.videoHash) {
      const existing = byVideoHash.get(item.videoHash)
      if (existing) {
        const diff = describeRowConflict(existing, item)
        if (diff) {
          conflicts.push({
            identifier: item.videoHash,
            identifierType: 'videoHash',
            firstFileName: existing.fileName,
            conflictingFileName: item.fileName,
            reason: diff,
          })
        }
      } else {
        byVideoHash.set(item.videoHash, item)
      }
    }

    if (item.metadataHash) {
      const existing = byMetadataHash.get(item.metadataHash)
      if (existing) {
        const diff = describeRowConflict(existing, item)
        if (diff) {
          conflicts.push({
            identifier: item.metadataHash,
            identifierType: 'metadataHash',
            firstFileName: existing.fileName,
            conflictingFileName: item.fileName,
            reason: diff,
          })
        }
      } else {
        byMetadataHash.set(item.metadataHash, item)
      }
    }

    const proofId = item.manifest?.proofId
    if (proofId) {
      const existing = byProofId.get(proofId)
      if (existing) {
        const diff = describeManifestConflict(existing, item)
        if (diff) {
          conflicts.push({
            identifier: proofId,
            identifierType: 'proofId',
            firstFileName: existing.fileName,
            conflictingFileName: item.fileName,
            reason: diff,
          })
        }
      } else {
        byProofId.set(proofId, item)
      }
    }
  }

  return conflicts
}

function describeRowConflict(a: BatchItemResult, b: BatchItemResult): string | null {
  const diffs: string[] = []
  if (a.status !== b.status) diffs.push(`status (${a.status} vs ${b.status})`)
  if (a.videoHash !== b.videoHash) diffs.push(`videoHash (${a.videoHash} vs ${b.videoHash})`)
  if (a.metadataHash !== b.metadataHash) diffs.push(`metadataHash (${a.metadataHash} vs ${b.metadataHash})`)
  if (a.sourceHash !== b.sourceHash) diffs.push(`sourceHash (${a.sourceHash} vs ${b.sourceHash})`)
  if (a.tier !== b.tier) diffs.push(`tier (${a.tier} vs ${b.tier})`)
  if (a.chainStatus !== b.chainStatus) diffs.push(`chainStatus (${a.chainStatus} vs ${b.chainStatus})`)
  return diffs.length > 0 ? `conflicting ${diffs.join(', ')}` : null
}

function describeManifestConflict(a: BatchItemResult, b: BatchItemResult): string | null {
  const ma = a.manifest
  const mb = b.manifest
  if (!ma || !mb) return null
  const diffs: string[] = []
  if (ma.videoHash !== mb.videoHash) diffs.push(`videoHash (${ma.videoHash} vs ${mb.videoHash})`)
  if (ma.metadataHash !== mb.metadataHash) diffs.push(`metadataHash (${ma.metadataHash} vs ${mb.metadataHash})`)
  if (ma.tier !== mb.tier) diffs.push(`tier (${ma.tier} vs ${mb.tier})`)
  if (ma.contractId !== mb.contractId) diffs.push(`contractId (${ma.contractId} vs ${mb.contractId})`)
  return diffs.length > 0 ? `conflicting manifest ${diffs.join(', ')}` : null
}

/**
 * Validates batch results before serialization, throwing
 * {@link BatchExportConflictError} if any duplicate conflicting statement
 * identifiers are found. Preserves and returns valid unique results.
 */
export function validateBatchExportResults(results: BatchItemResult[]): BatchItemResult[] {
  const conflicts = detectConflictingStatements(results)
  if (conflicts.length > 0) {
    throw new BatchExportConflictError(conflicts)
  }
  return results
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
 * Throws {@link BatchExportConflictError} if duplicate conflicting statement
 * identifiers are detected.
 */
export function exportBatchJSON(results: BatchItemResult[]): string {
  const validated = validateBatchExportResults(results)
  const clean = sanitizeBatchResults(validated)
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
 * Export privacy-safe CSV representation of batch results.
 * Throws {@link BatchExportConflictError} if duplicate conflicting statement
 * identifiers are detected.
 */
export function exportBatchCSV(results: BatchItemResult[]): string {
  const validated = validateBatchExportResults(results)
  const clean = sanitizeBatchResults(validated)
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
 * Throws {@link BatchExportConflictError} if duplicate conflicting statement
 * identifiers are detected.
 */
export function exportReceiptCollection(results: BatchItemResult[]): string {
  const validated = validateBatchExportResults(results)
  const manifests: ProofManifest[] = []

  for (const item of validated) {
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
