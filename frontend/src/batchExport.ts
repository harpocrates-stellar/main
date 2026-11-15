import type { BatchItemResult } from './batchVerifier'
import type { ProofManifest } from './proofManifest'

export type BatchExportPrivacyProfile = 'public' | 'owner-only'

export type BatchExportOptions = {
  privacyProfile?: BatchExportPrivacyProfile
}

export const DEFAULT_BATCH_EXPORT_PRIVACY_PROFILE: BatchExportPrivacyProfile = 'owner-only'

export const BATCH_EXPORT_FIELD_SETS = {
  public: [
    'itemRef',
    'fileSizeBytes',
    'status',
    'videoHash',
    'metadataHash',
    'sourceHash',
    'tier',
    'chainStatus',
    'message',
    'duplicateOf',
    'durationMs',
  ],
  'owner-only': [
    'itemRef',
    'fileName',
    'fileSizeBytes',
    'status',
    'videoHash',
    'metadataHash',
    'sourceHash',
    'tier',
    'chainStatus',
    'message',
    'duplicateOf',
    'failureReason',
    'issuerNotes',
    'durationMs',
  ],
} as const satisfies Record<BatchExportPrivacyProfile, readonly string[]>

export type PublicBatchReportItem = {
  itemRef: string
  fileSizeBytes: number
  status: string
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  tier: string | null
  chainStatus: string | null
  message: string
  duplicateOf: string | null
  durationMs: number | null
}

export type OwnerBatchReportItem = PublicBatchReportItem & {
  fileName: string
  failureReason: string | null
  issuerNotes: string | null
}

export type CleanBatchReportItem = PublicBatchReportItem & {
  fileName?: string
  failureReason?: string | null
  issuerNotes?: string | null
}

export type ReceiptCollection = {
  protocol: 'harpocrates-receipt-collection'
  version: 1
  privacyProfile: BatchExportPrivacyProfile
  exportedAt: string
  totalItems: number
  receipts: ProofManifest[]
}

function resolvePrivacyProfile(options?: BatchExportOptions | BatchExportPrivacyProfile): BatchExportPrivacyProfile {
  const profile = typeof options === 'string' ? options : (options?.privacyProfile ?? DEFAULT_BATCH_EXPORT_PRIVACY_PROFILE)
  if (profile !== 'public' && profile !== 'owner-only') {
    throw new Error(`Unsupported batch export privacy profile: ${String(profile)}`)
  }
  return profile
}

function scrubRawFileNames(text: string, rawFileNames: readonly string[]): string {
  if (!text) return text
  let scrubbed = text
  for (const rawName of rawFileNames) {
    if (!rawName) continue
    scrubbed = scrubbed.split(rawName).join('[redacted-filename]')
  }
  return scrubbed
}

/**
 * Strips raw File handles and sensitive memory states, returning a clean,
 * privacy-safe serializable representation of batch verification results
 * scoped to the selected privacy profile (`public` or `owner-only`).
 */
export function sanitizeBatchResults(
  results: BatchItemResult[],
  options?: BatchExportOptions | BatchExportPrivacyProfile,
): CleanBatchReportItem[] {
  const profile = resolvePrivacyProfile(options)
  const rawFileNames = results.map((item) => item.fileName).filter((name) => name.length > 0)
  const fileNameToRef = new Map<string, string>()
  results.forEach((item, index) => {
    if (item.fileName && !fileNameToRef.has(item.fileName)) {
      fileNameToRef.set(item.fileName, `item-${index + 1}`)
    }
  })

  return results.map((item, index) => {
    const itemRef = `item-${index + 1}`
    const durationMs = item.durationMs ? Math.round(item.durationMs) : null

    if (profile === 'public') {
      const publicDuplicateRef = item.duplicateOf
        ? (fileNameToRef.get(item.duplicateOf) ?? 'duplicate-item')
        : null

      return {
        itemRef,
        fileSizeBytes: item.fileSizeBytes,
        status: item.status,
        videoHash: item.videoHash,
        metadataHash: item.metadataHash,
        sourceHash: item.sourceHash,
        tier: item.tier,
        chainStatus: item.chainStatus,
        message: scrubRawFileNames(item.message, rawFileNames),
        duplicateOf: publicDuplicateRef,
        durationMs,
      }
    }

    return {
      itemRef,
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
      issuerNotes: item.issuerNotes ?? null,
      durationMs,
    }
  })
}

/**
 * Export privacy-safe JSON representation of batch results.
 */
export function exportBatchJSON(
  results: BatchItemResult[],
  options?: BatchExportOptions | BatchExportPrivacyProfile,
): string {
  const profile = resolvePrivacyProfile(options)
  const clean = sanitizeBatchResults(results, profile)
  const report = {
    protocol: 'harpocrates-batch-report',
    version: 1,
    privacyProfile: profile,
    fieldSet: [...BATCH_EXPORT_FIELD_SETS[profile]],
    exportedAt: new Date().toISOString(),
    totalCount: clean.length,
    results: clean,
  }
  return JSON.stringify(report, null, 2)
}

/**
 * Export privacy-safe CSV representation of batch results.
 */
export function exportBatchCSV(
  results: BatchItemResult[],
  options?: BatchExportOptions | BatchExportPrivacyProfile,
): string {
  const profile = resolvePrivacyProfile(options)
  const clean = sanitizeBatchResults(results, profile)

  if (profile === 'public') {
    const headers = [
      'Item Ref',
      'Size (Bytes)',
      'Status',
      'Video Hash',
      'Metadata Hash',
      'Source Hash',
      'Tier',
      'Chain Status',
      'Message',
      'Duplicate Of',
      'Duration (ms)',
    ]
    const rows = clean.map((item) => [
      escapeCSV(item.itemRef),
      String(item.fileSizeBytes),
      escapeCSV(item.status),
      escapeCSV(item.videoHash ?? ''),
      escapeCSV(item.metadataHash ?? ''),
      escapeCSV(item.sourceHash ?? ''),
      escapeCSV(item.tier ?? ''),
      escapeCSV(item.chainStatus ?? ''),
      escapeCSV(item.message),
      escapeCSV(item.duplicateOf ?? ''),
      item.durationMs !== null ? String(item.durationMs) : '',
    ])
    return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
  }

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
    'Issuer Notes',
    'Duration (ms)',
  ]

  const rows = clean.map((item) => [
    escapeCSV(item.fileName ?? ''),
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
    escapeCSV(item.issuerNotes ?? ''),
    item.durationMs !== null ? String(item.durationMs) : '',
  ])

  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
}

/**
 * Export standalone collection of valid ProofManifest receipts from the batch.
 */
export function exportReceiptCollection(
  results: BatchItemResult[],
  options?: BatchExportOptions | BatchExportPrivacyProfile,
): string {
  const profile = resolvePrivacyProfile(options)
  const manifests: ProofManifest[] = []

  for (const item of results) {
    if (item.manifest) {
      const copy = { ...item.manifest } as ProofManifest & Record<string, unknown>
      if (profile === 'public') {
        delete copy.fileName
        delete copy.issuerNotes
      }
      manifests.push(copy)
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
    privacyProfile: profile,
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
