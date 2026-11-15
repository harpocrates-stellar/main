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

export type ConflictingInputSummary = {
  id: string
  fileName: string
  status: string
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  tier: string | null
  chainStatus: string | null
}

export type BatchStatementConflict = {
  statementId: string
  conflictingFields: string[]
  inputs: ConflictingInputSummary[]
}

export type BatchConflictInspection = {
  hasConflicts: boolean
  validResults: BatchItemResult[]
  conflicts: BatchStatementConflict[]
}

export type BatchConflictExportOptions = {
  excludeConflicting?: boolean
}

export class BatchExportConflictError extends Error {
  public readonly conflicts: BatchStatementConflict[]
  public readonly validResults: BatchItemResult[]

  constructor(conflicts: BatchStatementConflict[], validResults: BatchItemResult[]) {
    const summary = conflicts
      .map((c) => `${c.statementId} (${c.inputs.map((i) => i.fileName).join(' vs ')})`)
      .join('; ')
    super(`Batch export rejected due to duplicate conflicting statement identifiers: ${summary}`)
    this.name = 'BatchExportConflictError'
    this.conflicts = conflicts
    this.validResults = validResults
  }
}

/**
 * Resolves the canonical statement identifier for a batch verification row,
 * preferring manifest proofId and falling back to videoHash.
 */
export function getBatchStatementId(item: BatchItemResult): string | null {
  const manifestProofId = item.manifest?.proofId?.trim().toLowerCase()
  if (manifestProofId) {
    return manifestProofId
  }
  const videoHash = item.videoHash?.trim().toLowerCase()
  if (videoHash) {
    return videoHash
  }
  return null
}

function summarizeConflictInput(item: BatchItemResult): ConflictingInputSummary {
  return {
    id: item.id,
    fileName: item.fileName,
    status: item.status,
    videoHash: item.videoHash,
    metadataHash: item.metadataHash,
    sourceHash: item.sourceHash,
    tier: item.tier,
    chainStatus: item.chainStatus,
  }
}

function findPairConflicts(primary: BatchItemResult, other: BatchItemResult): string[] {
  // Benign byte-duplicate rows emitted by BatchVerifier carry status='duplicate'
  // and null metadata/tier/chain fields while referencing the primary file.
  if (
    other.status === 'duplicate' &&
    (other.videoHash === null || other.videoHash.toLowerCase() === primary.videoHash?.toLowerCase()) &&
    other.metadataHash === null &&
    other.sourceHash === null &&
    other.tier === null &&
    other.chainStatus === null &&
    other.manifest === null
  ) {
    return []
  }

  const diffs: string[] = []
  if (primary.status !== other.status) {
    diffs.push('status')
  }
  const pVh = (primary.manifest?.videoHash ?? primary.videoHash)?.toLowerCase() ?? null
  const oVh = (other.manifest?.videoHash ?? other.videoHash)?.toLowerCase() ?? null
  if (pVh !== oVh) {
    diffs.push('videoHash')
  }
  const pMh = (primary.manifest?.metadataHash ?? primary.metadataHash)?.toLowerCase() ?? null
  const oMh = (other.manifest?.metadataHash ?? other.metadataHash)?.toLowerCase() ?? null
  if (pMh !== oMh) {
    diffs.push('metadataHash')
  }
  const pSh = (primary.manifest?.sourceHash ?? primary.sourceHash)?.toLowerCase() ?? null
  const oSh = (other.manifest?.sourceHash ?? other.sourceHash)?.toLowerCase() ?? null
  if (pSh !== oSh) {
    diffs.push('sourceHash')
  }
  const pTier = primary.manifest?.tier ?? primary.tier ?? null
  const oTier = other.manifest?.tier ?? other.tier ?? null
  if (pTier !== oTier) {
    diffs.push('tier')
  }
  if ((primary.chainStatus ?? null) !== (other.chainStatus ?? null)) {
    diffs.push('chainStatus')
  }
  return diffs
}

/**
 * Inspects batch results prior to serialization to detect contradictory rows
 * sharing a statement identifier while preserving valid unique results.
 */
export function inspectBatchStatementConflicts(results: BatchItemResult[]): BatchConflictInspection {
  const groups = new Map<string, BatchItemResult[]>()
  for (const item of results) {
    const statementId = getBatchStatementId(item)
    if (!statementId) continue
    const list = groups.get(statementId)
    if (list) {
      list.push(item)
    } else {
      groups.set(statementId, [item])
    }
  }

  const conflictingIds = new Set<string>()
  const conflicts: BatchStatementConflict[] = []

  for (const [statementId, group] of groups.entries()) {
    if (group.length < 2) continue
    const primary = group.find((item) => item.status !== 'duplicate') ?? group[0]
    const fieldSet = new Set<string>()

    for (const candidate of group) {
      if (candidate === primary) continue
      for (const field of findPairConflicts(primary, candidate)) {
        fieldSet.add(field)
      }
    }

    if (fieldSet.size > 0) {
      conflictingIds.add(statementId)
      conflicts.push({
        statementId,
        conflictingFields: Array.from(fieldSet),
        inputs: group.map(summarizeConflictInput),
      })
    }
  }

  const seenValidStatementIds = new Set<string>()
  const validResults: BatchItemResult[] = []

  for (const item of results) {
    const statementId = getBatchStatementId(item)
    if (!statementId) {
      validResults.push(item)
      continue
    }
    if (conflictingIds.has(statementId)) {
      continue
    }
    if (item.status === 'duplicate') {
      continue
    }
    if (seenValidStatementIds.has(statementId)) {
      continue
    }
    seenValidStatementIds.add(statementId)
    validResults.push(item)
  }

  return {
    hasConflicts: conflicts.length > 0,
    validResults,
    conflicts,
  }
}

function resolveExportableResults(
  results: BatchItemResult[],
  options?: BatchConflictExportOptions,
): BatchItemResult[] {
  const inspection = inspectBatchStatementConflicts(results)
  if (inspection.hasConflicts) {
    if (options?.excludeConflicting) {
      return inspection.validResults
    }
    throw new BatchExportConflictError(inspection.conflicts, inspection.validResults)
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
 * Rejects contradictory duplicate statement identifiers before serialization.
 */
export function exportBatchJSON(
  results: BatchItemResult[],
  options?: BatchConflictExportOptions,
): string {
  const verifiedResults = resolveExportableResults(results, options)
  const clean = sanitizeBatchResults(verifiedResults)
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
 * Rejects contradictory duplicate statement identifiers before serialization.
 */
export function exportBatchCSV(
  results: BatchItemResult[],
  options?: BatchConflictExportOptions,
): string {
  const verifiedResults = resolveExportableResults(results, options)
  const clean = sanitizeBatchResults(verifiedResults)
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
 * Rejects contradictory duplicate statement identifiers before serialization.
 */
export function exportReceiptCollection(
  results: BatchItemResult[],
  options?: BatchConflictExportOptions,
): string {
  const verifiedResults = resolveExportableResults(results, options)
  const manifests: ProofManifest[] = []
  const seenProofIds = new Set<string>()

  for (const item of verifiedResults) {
    if (item.manifest) {
      const pid = item.manifest.proofId.toLowerCase()
      if (!seenProofIds.has(pid)) {
        seenProofIds.add(pid)
        manifests.push(item.manifest)
      }
    } else if (item.status === 'confirmed' && item.videoHash && item.metadataHash && item.tier) {
      const proofId = item.chainProof?.metadataHash ?? item.videoHash
      const pid = proofId.toLowerCase()
      if (!seenProofIds.has(pid)) {
        seenProofIds.add(pid)
        manifests.push({
          protocol: 'harpocrates',
          version: 1,
          proofId,
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
