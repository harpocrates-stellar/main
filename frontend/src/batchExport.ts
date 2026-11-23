import type { BatchItemResult, BatchPreflightReport } from './batchVerifier'
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

export const BATCH_REPORT_PROTOCOL = 'harpocrates-batch-report' as const
export const BATCH_REPORT_VERSION = 1 as const
export const BATCH_COMPARISON_PROTOCOL = 'harpocrates-batch-comparison' as const
export const BATCH_COMPARISON_VERSION = 1 as const

export const DEFAULT_MAX_ARCHIVE_FILENAME_LENGTH = 96
export const MIN_ARCHIVE_FILENAME_LENGTH = 16
export const MAX_ARCHIVE_FILENAME_LENGTH = 255
export const MAX_ARCHIVE_EXTENSION_LENGTH = 16

const WINDOWS_RESERVED_NAME_RE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/g
const UNSAFE_FILENAME_CHARS_RE = /[^A-Za-z0-9._-]+/g

export type ArchiveFilenameOptions = {
  /** Maximum length of the generated filename (excluding optional directory prefix). Defaults to 96. */
  maxLength?: number
  /** Optional replacement extension (e.g. ".json"). */
  extension?: string
  /** Optional sanitized relative directory prefix (e.g. "receipts"). */
  directory?: string
}

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

/**
 * Privacy-safe, serializable batch report entry bound to its original selected
 * input identity (`id` and `inputIndex`) without raw `File` handles or media bytes.
 */
export type CleanBatchReportItem = {
  sourceItemId: string
  fileName: string
  archiveFileName: string
  fileSizeBytes: number
  status: string
  resultCategory: BatchResultCategory
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

export type BatchResultManifest = {
  protocol: typeof BATCH_REPORT_PROTOCOL
  version: typeof BATCH_REPORT_VERSION
  exportedAt: string
  totalCount: number
  results: CleanBatchReportItem[]
}

export type TrustContextField =
  | 'chainStatus'
  | 'metadataHash'
  | 'sourceHash'
  | 'status'
  | 'tier'

export type TrustContextSnapshot = {
  status: string
  tier: string | null
  chainStatus: string | null
  metadataHash: string | null
  sourceHash: string | null
}

export type BatchComparisonFileEntry = {
  statementId: string
  fileName: string
  fileSizeBytes: number
  videoHash: string | null
  trustContext: TrustContextSnapshot
}

export type BatchTrustContextChange = {
  statementId: string
  fileName: string
  baselineFileName: string
  videoHash: string | null
  changedFields: TrustContextField[]
  before: TrustContextSnapshot
  after: TrustContextSnapshot
}

export type BatchComparisonSummary = {
  baselineCount: number
  candidateCount: number
  addedCount: number
  removedCount: number
  trustContextChangedCount: number
  unchangedCount: number
}

export type BatchComparisonReport = {
  protocol: typeof BATCH_COMPARISON_PROTOCOL
  version: typeof BATCH_COMPARISON_VERSION
  baseline: {
    protocol: typeof BATCH_REPORT_PROTOCOL
    version: typeof BATCH_REPORT_VERSION
    exportedAt: string
    totalCount: number
  }
  candidate: {
    protocol: typeof BATCH_REPORT_PROTOCOL
    version: typeof BATCH_REPORT_VERSION
    exportedAt: string
    totalCount: number
  }
  summary: BatchComparisonSummary
  trustContextChanges: BatchTrustContextChange[]
  added: BatchComparisonFileEntry[]
  removed: BatchComparisonFileEntry[]
  unchanged: string[]
}

export type ReceiptCollection = {
  protocol: 'harpocrates-receipt-collection'
  version: 1
  exportedAt: string
  totalItems: number
  receipts: ProofManifest[]
}

const TRUST_CONTEXT_FIELDS: readonly TrustContextField[] = [
  'chainStatus',
  'metadataHash',
  'sourceHash',
  'status',
  'tier',
]

function compareCodeUnits(a: string, b: string): number {
  if (a < b) return -1
  if (a > b) return 1
  return 0
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string'
}

function isNullableNumber(value: unknown): value is number | null {
  return value === null || (typeof value === 'number' && Number.isFinite(value))
}

function normalizeNullableHash(value: string | null): string | null {
  return value === null ? null : value.toLowerCase()
}

function extractTrustContext(item: CleanBatchReportItem): TrustContextSnapshot {
  return {
    status: item.status,
    tier: item.tier,
    chainStatus: item.chainStatus,
    metadataHash: normalizeNullableHash(item.metadataHash),
    sourceHash: normalizeNullableHash(item.sourceHash),
  }
}

/**
 * Derives a deterministic statement identity for a batch report item.
 * Hashed items are keyed by their canonical videoHash (with duplicate entries
 * disambiguated by filename), while unhashed items fall back to filename + size.
 */
export function deriveStatementIdentity(item: CleanBatchReportItem): string {
  const normalizedVideoHash = item.videoHash?.trim().toLowerCase() ?? ''
  if (normalizedVideoHash.length > 0) {
    if (item.status === 'duplicate') {
      return `duplicate:${normalizedVideoHash}:${item.fileName}`
    }
    return `video:${normalizedVideoHash}`
  }
  return `file:${item.fileName}:${item.fileSizeBytes}`
}

/**
 * Parses and validates a versioned Harpocrates batch result manifest.
 * Fails closed on malformed JSON, unsupported protocol/version, or invalid items.
 */
export function parseBatchResultManifest(
  input: string | BatchResultManifest,
): BatchResultManifest {
  let raw: unknown
  if (typeof input === 'string') {
    try {
      raw = JSON.parse(input) as unknown
    } catch {
      throw new Error('Invalid batch result manifest: malformed JSON.')
    }
  } else {
    raw = input
  }

  if (!isRecord(raw)) {
    throw new Error('Invalid batch result manifest: expected a JSON object.')
  }

  if (raw.protocol !== BATCH_REPORT_PROTOCOL) {
    throw new Error(
      `Unsupported batch result manifest protocol: expected "${BATCH_REPORT_PROTOCOL}".`,
    )
  }

  if (raw.version !== BATCH_REPORT_VERSION) {
    throw new Error(
      `Unsupported batch result manifest version: expected ${BATCH_REPORT_VERSION}.`,
    )
  }

  if (typeof raw.exportedAt !== 'string' || raw.exportedAt.trim().length === 0) {
    throw new Error('Invalid batch result manifest: missing exportedAt timestamp.')
  }

  if (!Array.isArray(raw.results)) {
    throw new Error('Invalid batch result manifest: results must be an array.')
  }

  if (
    typeof raw.totalCount !== 'number' ||
    !Number.isInteger(raw.totalCount) ||
    raw.totalCount !== raw.results.length
  ) {
    throw new Error(
      'Invalid batch result manifest: totalCount must match results.length.',
    )
  }

  const validatedResults: CleanBatchReportItem[] = raw.results.map((entry, idx) => {
    if (!isRecord(entry)) {
      throw new Error(`Invalid batch result item at index ${idx}: expected an object.`)
    }
    if (typeof entry.fileName !== 'string' || entry.fileName.length === 0) {
      throw new Error(`Invalid batch result item at index ${idx}: missing fileName.`)
    }
    if (
      typeof entry.fileSizeBytes !== 'number' ||
      !Number.isFinite(entry.fileSizeBytes) ||
      entry.fileSizeBytes < 0
    ) {
      throw new Error(`Invalid batch result item at index ${idx}: invalid fileSizeBytes.`)
    }
    if (typeof entry.status !== 'string' || entry.status.length === 0) {
      throw new Error(`Invalid batch result item at index ${idx}: missing status.`)
    }
    if (
      !isNullableString(entry.videoHash) ||
      !isNullableString(entry.metadataHash) ||
      !isNullableString(entry.sourceHash) ||
      !isNullableString(entry.tier) ||
      !isNullableString(entry.chainStatus) ||
      typeof entry.message !== 'string' ||
      !isNullableString(entry.duplicateOf) ||
      !isNullableString(entry.failureReason) ||
      !isNullableNumber(entry.durationMs)
    ) {
      throw new Error(`Invalid batch result item at index ${idx}: invalid field types.`)
    }

    return {
      fileName: entry.fileName,
      fileSizeBytes: entry.fileSizeBytes,
      status: entry.status,
      videoHash: entry.videoHash,
      metadataHash: entry.metadataHash,
      sourceHash: entry.sourceHash,
      tier: entry.tier,
      chainStatus: entry.chainStatus,
      message: entry.message,
      duplicateOf: entry.duplicateOf,
      failureReason: entry.failureReason,
      durationMs: entry.durationMs,
    }
  })

  return {
    protocol: BATCH_REPORT_PROTOCOL,
    version: BATCH_REPORT_VERSION,
    exportedAt: raw.exportedAt,
    totalCount: validatedResults.length,
    results: validatedResults,
  }
}

function indexManifestByStatement(
  manifest: BatchResultManifest,
  label: 'baseline' | 'candidate',
): Map<string, CleanBatchReportItem> {
  const indexed = new Map<string, CleanBatchReportItem>()
  for (const item of manifest.results) {
    const statementId = deriveStatementIdentity(item)
    if (indexed.has(statementId)) {
      throw new Error(
        `Duplicate statement identity in ${label} manifest: "${statementId}".`,
      )
    }
    indexed.set(statementId, item)
  }
  return indexed
}

/**
 * Deterministically compares two versioned batch result manifests by statement identity,
 * separating trust-context changes from added or removed files.
 */
export function compareBatchManifests(
  baselineInput: string | BatchResultManifest,
  candidateInput: string | BatchResultManifest,
): BatchComparisonReport {
  const baseline = parseBatchResultManifest(baselineInput)
  const candidate = parseBatchResultManifest(candidateInput)

  const baselineMap = indexManifestByStatement(baseline, 'baseline')
  const candidateMap = indexManifestByStatement(candidate, 'candidate')

  const allStatementIds = Array.from(
    new Set([...baselineMap.keys(), ...candidateMap.keys()]),
  ).sort(compareCodeUnits)

  const trustContextChanges: BatchTrustContextChange[] = []
  const added: BatchComparisonFileEntry[] = []
  const removed: BatchComparisonFileEntry[] = []
  const unchanged: string[] = []

  for (const statementId of allStatementIds) {
    const beforeItem = baselineMap.get(statementId)
    const afterItem = candidateMap.get(statementId)

    if (!beforeItem && afterItem) {
      added.push({
        statementId,
        fileName: afterItem.fileName,
        fileSizeBytes: afterItem.fileSizeBytes,
        videoHash: normalizeNullableHash(afterItem.videoHash),
        trustContext: extractTrustContext(afterItem),
      })
      continue
    }

    if (beforeItem && !afterItem) {
      removed.push({
        statementId,
        fileName: beforeItem.fileName,
        fileSizeBytes: beforeItem.fileSizeBytes,
        videoHash: normalizeNullableHash(beforeItem.videoHash),
        trustContext: extractTrustContext(beforeItem),
      })
      continue
    }

    if (beforeItem && afterItem) {
      const beforeContext = extractTrustContext(beforeItem)
      const afterContext = extractTrustContext(afterItem)

      const changedFields = TRUST_CONTEXT_FIELDS.filter(
        (field) => beforeContext[field] !== afterContext[field],
      )

      if (changedFields.length > 0) {
        trustContextChanges.push({
          statementId,
          fileName: afterItem.fileName,
          baselineFileName: beforeItem.fileName,
          videoHash: normalizeNullableHash(afterItem.videoHash),
          changedFields,
          before: beforeContext,
          after: afterContext,
        })
      } else {
        unchanged.push(statementId)
      }
    }
  }

  return {
    protocol: BATCH_COMPARISON_PROTOCOL,
    version: BATCH_COMPARISON_VERSION,
    baseline: {
      protocol: baseline.protocol,
      version: baseline.version,
      exportedAt: baseline.exportedAt,
      totalCount: baseline.totalCount,
    },
    candidate: {
      protocol: candidate.protocol,
      version: candidate.version,
      exportedAt: candidate.exportedAt,
      totalCount: candidate.totalCount,
    },
    summary: {
      baselineCount: baseline.totalCount,
      candidateCount: candidate.totalCount,
      addedCount: added.length,
      removedCount: removed.length,
      trustContextChangedCount: trustContextChanges.length,
      unchangedCount: unchanged.length,
    },
    trustContextChanges,
    added,
    removed,
    unchanged,
  }
}

/**
 * Exports a deterministic, privacy-safe JSON comparison report between two
 * versioned batch result manifests.
 */
export function exportBatchComparisonJSON(
  baselineInput: string | BatchResultManifest,
  candidateInput: string | BatchResultManifest,
): string {
  const report = compareBatchManifests(baselineInput, candidateInput)
  return JSON.stringify(report, null, 2)
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
    archiveFileName: archivePaths[index],
    fileSizeBytes: item.fileSizeBytes,
    status: item.status,
    resultCategory: classifyBatchOutcome(item.status),
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
 * Builds collision-safe archive entries preserving the 1:1 association between
 * every exported result, its bounded output path, and its source batch item.
 */
export function buildBatchArchiveEntries(
  results: BatchItemResult[],
  options: ArchiveFilenameOptions = {},
): BatchArchiveEntry[] {
  const sanitized = sanitizeBatchResults(results, options)
  return sanitized.map((result, index) => ({
    sourceItemId: results[index].id,
    sourceFileName: results[index].fileName,
    outputPath: result.archiveFileName,
    result,
  }))
}

/**
 * Exports a deterministic JSON archive manifest mapping every source batch item
 * to its bounded, collision-safe output path and sanitized verification result.
 */
export function exportBatchArchiveManifest(
  results: BatchItemResult[],
  options: ArchiveFilenameOptions = {},
): string {
  const maxFileNameLength = resolveMaxArchiveFilenameLength(options.maxLength)
  const entries = buildBatchArchiveEntries(results, options)
  const manifest: BatchArchiveManifest = {
    protocol: 'harpocrates-batch-archive',
    version: 1,
    exportedAt: new Date().toISOString(),
    maxFileNameLength,
    totalEntries: entries.length,
    entries,
  }
  return JSON.stringify(manifest, null, 2)
}

/**
 * Export privacy-safe JSON representation of batch results.
 * Throws {@link BatchExportConflictError} if duplicate conflicting statement
 * identifiers are detected.
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
    counts,
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
 * Throws {@link BatchExportConflictError} if duplicate conflicting statement
 * identifiers are detected.
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
 * Throws {@link BatchExportConflictError} if duplicate conflicting statement
 * identifiers are detected.
 */
export function exportReceiptCollection(results: BatchItemResult[]): string {
  const validated = validateBatchExportResults(results)
  const manifests: ProofManifest[] = []

  for (const item of results) {
    if (item.manifest && item.status === 'manifest-valid') {
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
  const neutralized = FORMULA_PREFIX_RE.test(val) ? `'${val}` : val
  const needsQuotes =
    neutralized.includes(',') ||
    neutralized.includes('"') ||
    neutralized.includes('\n') ||
    neutralized.includes('\r')
  const escaped = neutralized.replace(/"/g, '""')
  return needsQuotes ? `"${escaped}"` : escaped
}
