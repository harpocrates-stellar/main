import {
  BATCH_CHECKPOINT_PROTOCOL,
  BATCH_CHECKPOINT_VERSION,
  BatchCheckpointError,
  isCompletedBatchOutcome,
  type BatchItemResult,
  type BatchOutcome,
  type BatchVerificationCheckpoint,
} from './batchVerifier'
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
 * Serializes a batch verification checkpoint to privacy-safe JSON,
 * persisting only nonsecret file fingerprints, policy/network context,
 * and completed results.
 */
export function exportBatchCheckpoint(checkpoint: BatchVerificationCheckpoint): string {
  const sanitized: BatchVerificationCheckpoint = {
    protocol: BATCH_CHECKPOINT_PROTOCOL,
    version: BATCH_CHECKPOINT_VERSION,
    createdAt: checkpoint.createdAt,
    updatedAt: checkpoint.updatedAt,
    policy: {
      maxFileSizeBytes: checkpoint.policy.maxFileSizeBytes,
      maxTotalSizeBytes: checkpoint.policy.maxTotalSizeBytes,
    },
    networkContext: {
      apiBase: checkpoint.networkContext.apiBase,
      contractId: checkpoint.networkContext.contractId,
      network: checkpoint.networkContext.network,
    },
    files: checkpoint.files.map((f) => ({
      index: f.index,
      fileName: f.fileName,
      fileSizeBytes: f.fileSizeBytes,
      lastModified: f.lastModified,
      mimeType: f.mimeType,
      sampleHash: f.sampleHash,
    })),
    completed: checkpoint.completed
      .filter((item) => isCompletedBatchOutcome(item.status))
      .map((item) => ({
        index: item.index,
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
        durationMs: item.durationMs !== null ? Math.round(item.durationMs) : null,
      })),
  }

  return JSON.stringify(sanitized, null, 2)
}

/**
 * Parses and structurally validates a serialized batch verification checkpoint.
 * Fails closed with BatchCheckpointError on malformed or unsupported payloads.
 */
export function parseBatchCheckpoint(raw: string): BatchVerificationCheckpoint {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new BatchCheckpointError('invalid-format', 'Checkpoint JSON is malformed.')
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new BatchCheckpointError('invalid-format', 'Checkpoint must be a JSON object.')
  }

  const cp = parsed as Partial<BatchVerificationCheckpoint>
  if (cp.protocol !== BATCH_CHECKPOINT_PROTOCOL || cp.version !== BATCH_CHECKPOINT_VERSION) {
    throw new BatchCheckpointError('invalid-format', 'Unsupported checkpoint protocol or version.')
  }

  if (
    typeof cp.createdAt !== 'string' ||
    typeof cp.updatedAt !== 'string' ||
    !cp.policy ||
    typeof cp.policy.maxFileSizeBytes !== 'number' ||
    typeof cp.policy.maxTotalSizeBytes !== 'number' ||
    !cp.networkContext ||
    typeof cp.networkContext.apiBase !== 'string' ||
    typeof cp.networkContext.contractId !== 'string' ||
    typeof cp.networkContext.network !== 'string' ||
    !Array.isArray(cp.files) ||
    !Array.isArray(cp.completed)
  ) {
    throw new BatchCheckpointError('invalid-format', 'Checkpoint is missing required fields.')
  }

  for (const f of cp.files) {
    if (
      !f ||
      typeof f.index !== 'number' ||
      typeof f.fileName !== 'string' ||
      typeof f.fileSizeBytes !== 'number' ||
      typeof f.lastModified !== 'number' ||
      typeof f.mimeType !== 'string' ||
      typeof f.sampleHash !== 'string'
    ) {
      throw new BatchCheckpointError('invalid-format', 'Checkpoint contains an invalid file fingerprint.')
    }
  }

  for (const item of cp.completed) {
    if (
      !item ||
      typeof item.index !== 'number' ||
      typeof item.fileName !== 'string' ||
      typeof item.fileSizeBytes !== 'number' ||
      typeof item.status !== 'string' ||
      !isCompletedBatchOutcome(item.status as BatchOutcome)
    ) {
      throw new BatchCheckpointError(
        'invalid-format',
        'Checkpoint contains an invalid or non-completed result entry.',
      )
    }
  }

  return cp as BatchVerificationCheckpoint
}

function escapeCSV(val: string): string {
  if (!val) return '""'
  const needsQuotes = val.includes(',') || val.includes('"') || val.includes('\n')
  const escaped = val.replace(/"/g, '""')
  return needsQuotes ? `"${escaped}"` : escaped
}
