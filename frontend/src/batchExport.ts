import type { BatchItemResult } from './batchVerifier'
import type { ProofManifest } from './proofManifest'

export const MAX_ARCHIVE_STEM_LENGTH = 48
export const MAX_ARCHIVE_PATH_LENGTH = 96

const WINDOWS_RESERVED_STEMS = new Set([
  'con',
  'prn',
  'aux',
  'nul',
  'com1',
  'com2',
  'com3',
  'com4',
  'com5',
  'com6',
  'com7',
  'com8',
  'com9',
  'lpt1',
  'lpt2',
  'lpt3',
  'lpt4',
  'lpt5',
  'lpt6',
  'lpt7',
  'lpt8',
  'lpt9',
])

export type BatchArchiveOptions = {
  directory?: string
  extension?: string
}

export type BatchArchiveEntry = {
  sourceItemId: string
  sourceIndex: number
  sourceFileName: string
  entryFileName: string
  outputPath: string
  videoHash: string | null
  status: string
  collisionResolved: boolean
}

export type CleanBatchReportItem = {
  sourceItemId: string
  sourceIndex: number
  outputPath: string
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
  itemAssociations: Array<{
    sourceItemId: string
    sourceIndex: number
    outputPath: string
    proofId: string
  }>
}

function deterministicShortDigest(input: string): string {
  let hash = 0x811c9dc5
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i)
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash.toString(16).padStart(8, '0')
}

function sanitizeDirectorySegment(segment: string): string {
  const cleaned = segment
    .normalize('NFKC')
    .replace(/[^A-Za-z0-9_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
  if (!cleaned || cleaned === '.' || cleaned === '..') {
    return ''
  }
  return WINDOWS_RESERVED_STEMS.has(cleaned.toLowerCase()) ? `dir-${cleaned}` : cleaned
}

function normalizeArchiveDirectory(directory?: string): string {
  if (directory === undefined) return 'items'
  const parts = directory
    .replace(/\\/g, '/')
    .split('/')
    .map(sanitizeDirectorySegment)
    .filter((part) => part.length > 0)
  return parts.join('/')
}

function normalizeArchiveExtension(extension?: string): string {
  const raw = (extension ?? '.json').trim()
  const withoutLeadingDots = raw.replace(/^\.+/, '')
  const cleaned = withoutLeadingDots.replace(/[^A-Za-z0-9]+/g, '').toLowerCase()
  return `.${cleaned || 'json'}`
}

/**
 * Produces a bounded, traversal-free, cross-platform-safe filename stem.
 */
export function sanitizeArchiveStem(rawName: string, maxStemLength: number = MAX_ARCHIVE_STEM_LENGTH): string {
  if (!Number.isInteger(maxStemLength) || maxStemLength < 4) {
    throw new Error('Archive stem length budget must be at least 4 characters.')
  }
  const normalizedSlashes = (rawName ?? '').replace(/\\/g, '/')
  const segments = normalizedSlashes.split('/').filter((seg) => seg.length > 0 && seg !== '.' && seg !== '..')
  const baseName = segments.length > 0 ? segments[segments.length - 1] : ''
  const lastDot = baseName.lastIndexOf('.')
  const rawStem = lastDot > 0 ? baseName.slice(0, lastDot) : baseName

  let cleaned = rawStem
    .normalize('NFKC')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/\.{2,}/g, '.')
    .replace(/-{2,}/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '')

  if (!cleaned) {
    cleaned = 'item'
  }
  if (WINDOWS_RESERVED_STEMS.has(cleaned.toLowerCase())) {
    cleaned = `item-${cleaned}`
  }
  if (cleaned.length > maxStemLength) {
    cleaned = cleaned.slice(0, maxStemLength).replace(/[.-]+$/g, '') || 'item'
  }
  return cleaned
}

/**
 * Generates collision-safe, length-bounded deterministic archive entries while
 * preserving the exact mapping back to every source BatchItemResult.
 */
export function buildBatchArchiveEntries(
  results: BatchItemResult[],
  options?: BatchArchiveOptions,
): BatchArchiveEntry[] {
  const dir = normalizeArchiveDirectory(options?.directory)
  const ext = normalizeArchiveExtension(options?.extension)
  const prefix = dir ? `${dir}/` : ''
  const maxEntryNameLength = MAX_ARCHIVE_PATH_LENGTH - prefix.length
  const maxStemForPath = Math.min(MAX_ARCHIVE_STEM_LENGTH, maxEntryNameLength - ext.length)

  if (maxStemForPath < 12) {
    throw new Error('Archive directory and extension exceed bounded archive path budget.')
  }

  const baseStems = results.map((item) => sanitizeArchiveStem(item.fileName, maxStemForPath))
  const stemCounts = new Map<string, number>()
  for (const stem of baseStems) {
    const key = stem.toLowerCase()
    stemCounts.set(key, (stemCounts.get(key) ?? 0) + 1)
  }

  const usedPaths = new Set<string>()

  return results.map((item, index) => {
    const baseStem = baseStems[index]
    const needsDisambiguation = (stemCounts.get(baseStem.toLowerCase()) ?? 0) > 1
    const digestTag =
      item.videoHash && /^[0-9a-f]{8}/i.test(item.videoHash)
        ? item.videoHash.slice(0, 8).toLowerCase()
        : deterministicShortDigest(`${index}:${item.id}:${item.fileName}:${item.fileSizeBytes}`)

    let chosenStem = baseStem
    let collisionResolved = false

    const makeCandidatePath = (stem: string) => `${prefix}${stem}${ext}`

    if (needsDisambiguation || usedPaths.has(makeCandidatePath(chosenStem).toLowerCase())) {
      collisionResolved = true
      let attempt = 1
      while (true) {
        const suffix = attempt === 1 ? `-${digestTag}` : `-${digestTag}-${attempt}`
        const allowedBaseLen = Math.max(4, maxStemForPath - suffix.length)
        const trimmedBase = baseStem.slice(0, allowedBaseLen).replace(/[.-]+$/g, '') || 'item'
        const candidateStem = `${trimmedBase}${suffix}`
        const candidatePath = makeCandidatePath(candidateStem)
        if (!usedPaths.has(candidatePath.toLowerCase())) {
          chosenStem = candidateStem
          break
        }
        attempt += 1
      }
    }

    const entryFileName = `${chosenStem}${ext}`
    const outputPath = `${prefix}${entryFileName}`
    usedPaths.add(outputPath.toLowerCase())

    return {
      sourceItemId: item.id,
      sourceIndex: index,
      sourceFileName: item.fileName,
      entryFileName,
      outputPath,
      videoHash: item.videoHash,
      status: item.status,
      collisionResolved,
    }
  })
}

/**
 * Strips raw File handles and sensitive memory states, returning a clean,
 * privacy-safe serializable representation of batch verification results
 * with deterministic collision-safe output paths and source-item bindings.
 */
export function sanitizeBatchResults(
  results: BatchItemResult[],
  archiveOptions?: BatchArchiveOptions,
): CleanBatchReportItem[] {
  const archiveEntries = buildBatchArchiveEntries(results, archiveOptions)
  return results.map((item, index) => ({
    sourceItemId: item.id,
    sourceIndex: index,
    outputPath: archiveEntries[index].outputPath,
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
export function exportBatchJSON(results: BatchItemResult[], archiveOptions?: BatchArchiveOptions): string {
  const archiveEntries = buildBatchArchiveEntries(results, archiveOptions)
  const clean = sanitizeBatchResults(results, archiveOptions)
  const report = {
    protocol: 'harpocrates-batch-report',
    version: 1,
    exportedAt: new Date().toISOString(),
    totalCount: clean.length,
    archiveEntries,
    results: clean,
  }
  return JSON.stringify(report, null, 2)
}

/**
 * Export deterministic bounded archive manifest mapping each collision-safe
 * output path back to its source item.
 */
export function exportBatchArchiveManifest(
  results: BatchItemResult[],
  archiveOptions?: BatchArchiveOptions,
): string {
  const entries = buildBatchArchiveEntries(results, archiveOptions)
  const items = sanitizeBatchResults(results, archiveOptions)
  return JSON.stringify(
    {
      protocol: 'harpocrates-batch-archive-manifest',
      version: 1,
      exportedAt: new Date().toISOString(),
      maxStemLength: MAX_ARCHIVE_STEM_LENGTH,
      maxPathLength: MAX_ARCHIVE_PATH_LENGTH,
      totalEntries: entries.length,
      entries,
      items,
    },
    null,
    2,
  )
}

/**
 * Export privacy-safe CSV representation of batch results.
 */
export function exportBatchCSV(results: BatchItemResult[], archiveOptions?: BatchArchiveOptions): string {
  const clean = sanitizeBatchResults(results, archiveOptions)
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
    'Source Item ID',
    'Output Path',
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
    escapeCSV(item.sourceItemId),
    escapeCSV(item.outputPath),
  ])

  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
}

/**
 * Export standalone collection of valid ProofManifest receipts from the batch.
 */
export function exportReceiptCollection(results: BatchItemResult[], archiveOptions?: BatchArchiveOptions): string {
  const archiveEntries = buildBatchArchiveEntries(results, { extension: '.receipt.json', ...archiveOptions })
  const manifests: ProofManifest[] = []
  const itemAssociations: ReceiptCollection['itemAssociations'] = []

  results.forEach((item, index) => {
    if (item.manifest) {
      manifests.push(item.manifest)
      itemAssociations.push({
        sourceItemId: item.id,
        sourceIndex: index,
        outputPath: archiveEntries[index].outputPath,
        proofId: item.manifest.proofId,
      })
    } else if (item.status === 'confirmed' && item.videoHash && item.metadataHash && item.tier) {
      const proofId = item.chainProof?.metadataHash ?? item.videoHash
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
      itemAssociations.push({
        sourceItemId: item.id,
        sourceIndex: index,
        outputPath: archiveEntries[index].outputPath,
        proofId,
      })
    }
  })

  const collection: ReceiptCollection = {
    protocol: 'harpocrates-receipt-collection',
    version: 1,
    exportedAt: new Date().toISOString(),
    totalItems: manifests.length,
    receipts: manifests,
    itemAssociations,
  }

  return JSON.stringify(collection, null, 2)
}

function escapeCSV(val: string): string {
  if (!val) return '""'
  const needsQuotes = val.includes(',') || val.includes('"') || val.includes('\n')
  const escaped = val.replace(/"/g, '""')
  return needsQuotes ? `"${escaped}"` : escaped
}
