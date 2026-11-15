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

export type BatchReportManifest = {
  protocol: 'harpocrates-batch-report'
  version: 1
  exportedAt?: string
  totalCount: number
  results: CleanBatchReportItem[]
}

export type BatchComparisonErrorCode =
  | 'malformed_manifest'
  | 'unsupported_protocol'
  | 'unsupported_version'
  | 'invalid_item'
  | 'conflicting_statement_identity'

export class BatchComparisonError extends Error {
  public readonly code: BatchComparisonErrorCode

  constructor(code: BatchComparisonErrorCode, message: string) {
    super(message)
    this.name = 'BatchComparisonError'
    this.code = code
  }
}

export type BatchTrustContextSnapshot = {
  status: string
  chainStatus: string | null
  tier: string | null
}

export type TrustContextTransition = {
  statementId: string
  baselineFileName: string
  candidateFileName: string
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  before: BatchTrustContextSnapshot
  after: BatchTrustContextSnapshot
  changedFields: Array<'status' | 'chainStatus' | 'tier'>
}

export type BatchComparisonItem = {
  statementId: string
  fileName: string
  fileSizeBytes: number
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  status: string
  chainStatus: string | null
  tier: string | null
}

export type BatchComparisonReport = {
  protocol: 'harpocrates-batch-comparison'
  version: 1
  baselineVersion: 1
  candidateVersion: 1
  summary: {
    baselineCount: number
    candidateCount: number
    trustContextChangedCount: number
    addedCount: number
    removedCount: number
    unchangedCount: number
  }
  trustContextChanges: TrustContextTransition[]
  added: BatchComparisonItem[]
  removed: BatchComparisonItem[]
  unchanged: BatchComparisonItem[]
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

/**
 * Computes canonical statement identity from cryptographic commitments so
 * renamed or reordered files still resolve to the same statement.
 */
export function deriveStatementIdentity(item: CleanBatchReportItem): string {
  const vh = typeof item.videoHash === 'string' && item.videoHash.trim() ? item.videoHash.trim().toLowerCase() : null
  const mh =
    typeof item.metadataHash === 'string' && item.metadataHash.trim() ? item.metadataHash.trim().toLowerCase() : 'none'
  const sh =
    typeof item.sourceHash === 'string' && item.sourceHash.trim() ? item.sourceHash.trim().toLowerCase() : 'none'

  if (vh) {
    return `stmt:${vh}:${mh}:${sh}`
  }
  return `unhashed:${item.fileName}:${item.fileSizeBytes}`
}

function normalizeReportItem(raw: unknown): CleanBatchReportItem {
  if (!raw || typeof raw !== 'object') {
    throw new BatchComparisonError('invalid_item', 'Batch report item must be an object.')
  }
  const rec = raw as Record<string, unknown>
  if (typeof rec.fileName !== 'string' || typeof rec.status !== 'string' || typeof rec.fileSizeBytes !== 'number') {
    throw new BatchComparisonError('invalid_item', 'Batch report item is missing required fields.')
  }
  return {
    fileName: rec.fileName,
    fileSizeBytes: rec.fileSizeBytes,
    status: rec.status,
    videoHash: typeof rec.videoHash === 'string' ? rec.videoHash : null,
    metadataHash: typeof rec.metadataHash === 'string' ? rec.metadataHash : null,
    sourceHash: typeof rec.sourceHash === 'string' ? rec.sourceHash : null,
    tier: typeof rec.tier === 'string' ? rec.tier : null,
    chainStatus: typeof rec.chainStatus === 'string' ? rec.chainStatus : null,
    message: typeof rec.message === 'string' ? rec.message : '',
    duplicateOf: typeof rec.duplicateOf === 'string' ? rec.duplicateOf : null,
    failureReason: typeof rec.failureReason === 'string' ? rec.failureReason : null,
    durationMs: typeof rec.durationMs === 'number' ? rec.durationMs : null,
  }
}

/**
 * Parses and validates a versioned `harpocrates-batch-report` manifest fail-closed.
 */
export function parseBatchReportManifest(input: string | unknown): BatchReportManifest {
  let parsed: unknown = input
  if (typeof input === 'string') {
    try {
      parsed = JSON.parse(input)
    } catch {
      throw new BatchComparisonError('malformed_manifest', 'Batch report manifest is not valid JSON.')
    }
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new BatchComparisonError('malformed_manifest', 'Batch report manifest must be a JSON object.')
  }

  const obj = parsed as Record<string, unknown>
  if (obj.protocol !== 'harpocrates-batch-report') {
    throw new BatchComparisonError(
      'unsupported_protocol',
      `Unsupported batch report protocol: ${String(obj.protocol)}`,
    )
  }
  if (obj.version !== 1) {
    throw new BatchComparisonError(
      'unsupported_version',
      `Unsupported batch report schema version: ${String(obj.version)}`,
    )
  }
  if (!Array.isArray(obj.results)) {
    throw new BatchComparisonError('malformed_manifest', 'Batch report manifest results must be an array.')
  }

  const results = obj.results.map(normalizeReportItem)
  return {
    protocol: 'harpocrates-batch-report',
    version: 1,
    exportedAt: typeof obj.exportedAt === 'string' ? obj.exportedAt : undefined,
    totalCount: typeof obj.totalCount === 'number' ? obj.totalCount : results.length,
    results,
  }
}

function indexManifestByStatement(manifest: BatchReportManifest): Map<string, CleanBatchReportItem> {
  const map = new Map<string, CleanBatchReportItem>()
  for (const item of manifest.results) {
    if (item.status === 'duplicate') {
      continue
    }
    const id = deriveStatementIdentity(item)
    const existing = map.get(id)
    if (existing) {
      if (
        existing.status !== item.status ||
        existing.chainStatus !== item.chainStatus ||
        existing.tier !== item.tier
      ) {
        throw new BatchComparisonError(
          'conflicting_statement_identity',
          `Manifest contains conflicting trust outcomes for statement ${id}.`,
        )
      }
      continue
    }
    map.set(id, item)
  }
  return map
}

function toComparisonItem(statementId: string, item: CleanBatchReportItem): BatchComparisonItem {
  return {
    statementId,
    fileName: item.fileName,
    fileSizeBytes: item.fileSizeBytes,
    videoHash: item.videoHash,
    metadataHash: item.metadataHash,
    sourceHash: item.sourceHash,
    status: item.status,
    chainStatus: item.chainStatus,
    tier: item.tier,
  }
}

/**
 * Deterministically compares two versioned batch result manifests by statement identity,
 * separating trust-context transitions (`status`, `chainStatus`, `tier`) from added or removed files.
 */
export function compareBatchReports(
  baselineInput: string | unknown,
  candidateInput: string | unknown,
): BatchComparisonReport {
  const baseline = parseBatchReportManifest(baselineInput)
  const candidate = parseBatchReportManifest(candidateInput)

  const baseMap = indexManifestByStatement(baseline)
  const candMap = indexManifestByStatement(candidate)

  const allIds = Array.from(new Set([...baseMap.keys(), ...candMap.keys()])).sort((a, b) =>
    a < b ? -1 : a > b ? 1 : 0,
  )

  const trustContextChanges: TrustContextTransition[] = []
  const added: BatchComparisonItem[] = []
  const removed: BatchComparisonItem[] = []
  const unchanged: BatchComparisonItem[] = []

  for (const statementId of allIds) {
    const baseItem = baseMap.get(statementId)
    const candItem = candMap.get(statementId)

    if (!baseItem && candItem) {
      added.push(toComparisonItem(statementId, candItem))
      continue
    }
    if (baseItem && !candItem) {
      removed.push(toComparisonItem(statementId, baseItem))
      continue
    }
    if (baseItem && candItem) {
      const changedFields: Array<'status' | 'chainStatus' | 'tier'> = []
      if (baseItem.status !== candItem.status) changedFields.push('status')
      if (baseItem.chainStatus !== candItem.chainStatus) changedFields.push('chainStatus')
      if (baseItem.tier !== candItem.tier) changedFields.push('tier')

      if (changedFields.length > 0) {
        trustContextChanges.push({
          statementId,
          baselineFileName: baseItem.fileName,
          candidateFileName: candItem.fileName,
          videoHash: candItem.videoHash ?? baseItem.videoHash,
          metadataHash: candItem.metadataHash ?? baseItem.metadataHash,
          sourceHash: candItem.sourceHash ?? baseItem.sourceHash,
          before: {
            status: baseItem.status,
            chainStatus: baseItem.chainStatus,
            tier: baseItem.tier,
          },
          after: {
            status: candItem.status,
            chainStatus: candItem.chainStatus,
            tier: candItem.tier,
          },
          changedFields,
        })
      } else {
        unchanged.push(toComparisonItem(statementId, candItem))
      }
    }
  }

  return {
    protocol: 'harpocrates-batch-comparison',
    version: 1,
    baselineVersion: baseline.version,
    candidateVersion: candidate.version,
    summary: {
      baselineCount: baseMap.size,
      candidateCount: candMap.size,
      trustContextChangedCount: trustContextChanges.length,
      addedCount: added.length,
      removedCount: removed.length,
      unchangedCount: unchanged.length,
    },
    trustContextChanges,
    added,
    removed,
    unchanged,
  }
}

/**
 * Exports a byte-for-byte deterministic JSON comparison report between two batch manifests.
 */
export function exportBatchComparisonJSON(
  baselineInput: string | unknown,
  candidateInput: string | unknown,
): string {
  const comparison = compareBatchReports(baselineInput, candidateInput)
  return JSON.stringify(comparison, null, 2)
}

/**
 * Exports a deterministic CSV comparison report separating trust-context changes,
 * added items, removed items, and unchanged items.
 */
export function exportBatchComparisonCSV(
  baselineInput: string | unknown,
  candidateInput: string | unknown,
): string {
  const comparison = compareBatchReports(baselineInput, candidateInput)
  const headers = [
    'Category',
    'Statement ID',
    'Baseline File',
    'Candidate File',
    'Video Hash',
    'Before Status',
    'After Status',
    'Before Chain Status',
    'After Chain Status',
    'Before Tier',
    'After Tier',
    'Changed Fields',
  ]

  const rows: string[][] = []

  for (const change of comparison.trustContextChanges) {
    rows.push([
      'trust-context-changed',
      escapeCSV(change.statementId),
      escapeCSV(change.baselineFileName),
      escapeCSV(change.candidateFileName),
      escapeCSV(change.videoHash ?? ''),
      escapeCSV(change.before.status),
      escapeCSV(change.after.status),
      escapeCSV(change.before.chainStatus ?? ''),
      escapeCSV(change.after.chainStatus ?? ''),
      escapeCSV(change.before.tier ?? ''),
      escapeCSV(change.after.tier ?? ''),
      escapeCSV(change.changedFields.join(';')),
    ])
  }

  for (const item of comparison.added) {
    rows.push([
      'added',
      escapeCSV(item.statementId),
      '""',
      escapeCSV(item.fileName),
      escapeCSV(item.videoHash ?? ''),
      '""',
      escapeCSV(item.status),
      '""',
      escapeCSV(item.chainStatus ?? ''),
      '""',
      escapeCSV(item.tier ?? ''),
      '""',
    ])
  }

  for (const item of comparison.removed) {
    rows.push([
      'removed',
      escapeCSV(item.statementId),
      escapeCSV(item.fileName),
      '""',
      escapeCSV(item.videoHash ?? ''),
      escapeCSV(item.status),
      '""',
      escapeCSV(item.chainStatus ?? ''),
      '""',
      escapeCSV(item.tier ?? ''),
      '""',
      '""',
    ])
  }

  for (const item of comparison.unchanged) {
    rows.push([
      'unchanged',
      escapeCSV(item.statementId),
      escapeCSV(item.fileName),
      escapeCSV(item.fileName),
      escapeCSV(item.videoHash ?? ''),
      escapeCSV(item.status),
      escapeCSV(item.status),
      escapeCSV(item.chainStatus ?? ''),
      escapeCSV(item.chainStatus ?? ''),
      escapeCSV(item.tier ?? ''),
      escapeCSV(item.tier ?? ''),
      '""',
    ])
  }

  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
}

function escapeCSV(val: string): string {
  if (!val) return '""'
  const needsQuotes = val.includes(',') || val.includes('"') || val.includes('\n')
  const escaped = val.replace(/"/g, '""')
  return needsQuotes ? `"${escaped}"` : escaped
}
