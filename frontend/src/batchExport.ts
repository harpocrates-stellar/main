import type { BatchItemResult } from './batchVerifier'
import type { ProofManifest } from './proofManifest'

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

export type CleanBatchReportItem = {
  sourceItemId: string
  fileName: string
  archiveFileName: string
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

export type BatchArchiveEntry = {
  sourceItemId: string
  sourceFileName: string
  outputPath: string
  result: CleanBatchReportItem
}

export type BatchArchiveManifest = {
  protocol: 'harpocrates-batch-archive'
  version: 1
  exportedAt: string
  maxFileNameLength: number
  totalEntries: number
  entries: BatchArchiveEntry[]
}

export type ReceiptCollection = {
  protocol: 'harpocrates-receipt-collection'
  version: 1
  exportedAt: string
  totalItems: number
  receipts: ProofManifest[]
}

function resolveMaxArchiveFilenameLength(maxLength?: number): number {
  const resolved = maxLength ?? DEFAULT_MAX_ARCHIVE_FILENAME_LENGTH
  if (
    !Number.isInteger(resolved) ||
    resolved < MIN_ARCHIVE_FILENAME_LENGTH ||
    resolved > MAX_ARCHIVE_FILENAME_LENGTH
  ) {
    throw new RangeError(
      `Archive filename maxLength must be an integer between ${MIN_ARCHIVE_FILENAME_LENGTH} and ${MAX_ARCHIVE_FILENAME_LENGTH}, received ${String(maxLength)}.`,
    )
  }
  return resolved
}

function sanitizeExtension(rawExtension: string): string {
  const cleaned = rawExtension
    .replace(CONTROL_CHARS_RE, '')
    .replace(/[^A-Za-z0-9.]+/g, '')
    .replace(/^\.+/, '')
  if (!cleaned) return ''
  const bounded = cleaned.slice(0, MAX_ARCHIVE_EXTENSION_LENGTH - 1)
  return `.${bounded}`
}

function sanitizeDirectory(directory?: string): string {
  if (!directory) return ''
  const segments = directory
    .replace(CONTROL_CHARS_RE, '')
    .split(/[/\\]+/)
    .map((segment) =>
      segment
        .replace(UNSAFE_FILENAME_CHARS_RE, '_')
        .replace(/_+/g, '_')
        .replace(/^[._]+|[._]+$/g, ''),
    )
    .filter((segment) => segment.length > 0 && segment !== '.' && segment !== '..')
  return segments.join('/')
}

function parseSanitizedNameParts(
  fileName: string,
  overrideExtension?: string,
): { stem: string; extension: string } {
  const stripped = fileName.replace(CONTROL_CHARS_RE, '').trim()
  const pathSegments = stripped
    .split(/[/\\]+/)
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0 && segment !== '.' && segment !== '..')

  const baseName = pathSegments.length > 0 ? pathSegments[pathSegments.length - 1] : ''

  let rawStem = baseName
  let extension = ''

  if (overrideExtension !== undefined) {
    extension = sanitizeExtension(overrideExtension)
    const dotIndex = baseName.lastIndexOf('.')
    if (dotIndex > 0) {
      rawStem = baseName.slice(0, dotIndex)
    }
  } else {
    const dotIndex = baseName.lastIndexOf('.')
    if (dotIndex > 0 && dotIndex < baseName.length - 1) {
      const candidateExt = baseName.slice(dotIndex + 1)
      if (/^[A-Za-z0-9]{1,15}$/.test(candidateExt)) {
        rawStem = baseName.slice(0, dotIndex)
        extension = `.${candidateExt}`
      }
    }
  }

  let stem = rawStem
    .replace(UNSAFE_FILENAME_CHARS_RE, '_')
    .replace(/_+/g, '_')
    .replace(/^[._]+|[._]+$/g, '')

  if (!stem) {
    stem = 'item'
  }

  if (WINDOWS_RESERVED_NAME_RE.test(stem)) {
    stem = `item_${stem}`
  }

  return { stem, extension }
}

function buildBoundedFileName(
  stem: string,
  extension: string,
  maxLength: number,
  suffix = '',
): string {
  const maxStemLength = Math.max(1, maxLength - extension.length - suffix.length)
  let boundedStem = stem.slice(0, maxStemLength).replace(/[._]+$/g, '')
  if (!boundedStem) {
    boundedStem = 'item'.slice(0, maxStemLength)
  }
  return `${boundedStem}${suffix}${extension}`
}

/**
 * Normalizes and bounds a single batch archive filename, removing path traversal,
 * control characters, unsafe filesystem characters, and reserved device names.
 */
export function boundArchiveFilename(
  fileName: string,
  options: ArchiveFilenameOptions = {},
): string {
  const maxLength = resolveMaxArchiveFilenameLength(options.maxLength)
  const { stem, extension } = parseSanitizedNameParts(fileName, options.extension)
  const boundedName = buildBoundedFileName(stem, extension, maxLength)
  const dir = sanitizeDirectory(options.directory)
  return dir ? `${dir}/${boundedName}` : boundedName
}

function allocateArchivePaths(
  results: BatchItemResult[],
  options: ArchiveFilenameOptions = {},
): string[] {
  const maxLength = resolveMaxArchiveFilenameLength(options.maxLength)
  const dir = sanitizeDirectory(options.directory)
  const usedPaths = new Set<string>()

  return results.map((item) => {
    const { stem, extension } = parseSanitizedNameParts(item.fileName, options.extension)
    let fileName = buildBoundedFileName(stem, extension, maxLength)
    let outputPath = dir ? `${dir}/${fileName}` : fileName
    let key = outputPath.toLowerCase()

    if (usedPaths.has(key)) {
      let counter = 2
      while (usedPaths.has(key)) {
        const suffix = `-${counter}`
        fileName = buildBoundedFileName(stem, extension, maxLength, suffix)
        outputPath = dir ? `${dir}/${fileName}` : fileName
        key = outputPath.toLowerCase()
        counter += 1
      }
    }

    usedPaths.add(key)
    return outputPath
  })
}

/**
 * Strips raw File handles and sensitive memory states, returning a clean,
 * privacy-safe serializable representation of batch verification results
 * with bounded, collision-safe deterministic archive filenames.
 */
export function sanitizeBatchResults(
  results: BatchItemResult[],
  options: ArchiveFilenameOptions = {},
): CleanBatchReportItem[] {
  const archivePaths = allocateArchivePaths(results, options)

  return results.map((item, index) => ({
    sourceItemId: item.id,
    fileName: item.fileName,
    archiveFileName: archivePaths[index],
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

function escapeCSV(val: string): string {
  if (!val) return '""'
  const needsQuotes = val.includes(',') || val.includes('"') || val.includes('\n')
  const escaped = val.replace(/"/g, '""')
  return needsQuotes ? `"${escaped}"` : escaped
}
