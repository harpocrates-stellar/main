import type { BatchItemResult } from './batchVerifier'
import type { ProofManifest } from './proofManifest'

export type ExportPrivacyProfile = 'public' | 'owner-only'

export const DEFAULT_EXPORT_PRIVACY_PROFILE: ExportPrivacyProfile = 'owner-only'

export const PUBLIC_EXPORT_FIELDS = [
  'status',
  'videoHash',
  'metadataHash',
  'sourceHash',
  'tier',
  'chainStatus',
  'fileSizeBytes',
  'durationMs',
] as const

export const OWNER_ONLY_EXPORT_FIELDS = [
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
  'durationMs',
  'issuerNote',
] as const

export type ExportPrivacyProfileDefinition = {
  id: ExportPrivacyProfile
  label: string
  description: string
  fields: readonly string[]
}

export const EXPORT_PRIVACY_PROFILES: Record<ExportPrivacyProfile, ExportPrivacyProfileDefinition> = {
  public: {
    id: 'public',
    label: 'Public (Redacted)',
    description:
      'Shareable verification outcomes and cryptographic commitments only. Excludes raw filenames, duplicate filename references, diagnostic messages, and private issuer notes.',
    fields: PUBLIC_EXPORT_FIELDS,
  },
  'owner-only': {
    id: 'owner-only',
    label: 'Owner-Only (Full)',
    description:
      'Complete local audit export including raw filenames, duplicate references, failure diagnostics, and private issuer notes. Intended for owner-controlled storage only.',
    fields: OWNER_ONLY_EXPORT_FIELDS,
  },
}

export function assertValidExportPrivacyProfile(
  profile: string,
): asserts profile is ExportPrivacyProfile {
  if (profile !== 'public' && profile !== 'owner-only') {
    throw new Error(
      `Unsupported export privacy profile "${profile}". Expected "public" or "owner-only".`,
    )
  }
}

export type PublicBatchReportItem = {
  status: string
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  tier: string | null
  chainStatus: string | null
  fileSizeBytes: number
  durationMs: number | null
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
  issuerNote?: string | null
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
 * privacy-safe serializable representation of batch verification results
 * according to the selected privacy profile.
 */
export function sanitizeBatchResults(
  results: BatchItemResult[],
  profile: 'public',
): PublicBatchReportItem[]
export function sanitizeBatchResults(
  results: BatchItemResult[],
  profile?: 'owner-only',
): CleanBatchReportItem[]
export function sanitizeBatchResults(
  results: BatchItemResult[],
  profile: ExportPrivacyProfile,
): PublicBatchReportItem[] | CleanBatchReportItem[]
export function sanitizeBatchResults(
  results: BatchItemResult[],
  profile: ExportPrivacyProfile = DEFAULT_EXPORT_PRIVACY_PROFILE,
): PublicBatchReportItem[] | CleanBatchReportItem[] {
  assertValidExportPrivacyProfile(profile)

  if (profile === 'public') {
    return results.map((item) => ({
      status: item.status,
      videoHash: item.videoHash,
      metadataHash: item.metadataHash,
      sourceHash: item.sourceHash,
      tier: item.tier,
      chainStatus: item.chainStatus,
      fileSizeBytes: item.fileSizeBytes,
      durationMs: item.durationMs !== null ? Math.round(item.durationMs) : null,
    }))
  }

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
    durationMs: item.durationMs !== null ? Math.round(item.durationMs) : null,
    ...(item.issuerNote !== undefined ? { issuerNote: item.issuerNote } : {}),
  }))
}

/**
 * Export privacy-safe JSON representation of batch results.
 */
export function exportBatchJSON(
  results: BatchItemResult[],
  profile: ExportPrivacyProfile = DEFAULT_EXPORT_PRIVACY_PROFILE,
): string {
  assertValidExportPrivacyProfile(profile)
  const clean = sanitizeBatchResults(results, profile)
  const report = {
    protocol: 'harpocrates-batch-report',
    version: 1,
    privacyProfile: profile,
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
  profile: ExportPrivacyProfile = DEFAULT_EXPORT_PRIVACY_PROFILE,
): string {
  assertValidExportPrivacyProfile(profile)

  if (profile === 'public') {
    const clean = sanitizeBatchResults(results, 'public')
    const headers = [
      'Status',
      'Video Hash',
      'Metadata Hash',
      'Source Hash',
      'Tier',
      'Chain Status',
      'Size (Bytes)',
      'Duration (ms)',
    ]

    const rows = clean.map((item) => [
      escapeCSV(item.status),
      escapeCSV(item.videoHash ?? ''),
      escapeCSV(item.metadataHash ?? ''),
      escapeCSV(item.sourceHash ?? ''),
      escapeCSV(item.tier ?? ''),
      escapeCSV(item.chainStatus ?? ''),
      String(item.fileSizeBytes),
      item.durationMs !== null ? String(item.durationMs) : '',
    ])

    return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
  }

  const clean = sanitizeBatchResults(results, 'owner-only')
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
    'Issuer Note',
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
    escapeCSV(item.issuerNote ?? ''),
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
