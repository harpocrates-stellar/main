import type { ChainProofRecord } from './stellar'
import { verifyArtifact, type VerificationEvent } from './verificationFlow'
import type { ProofManifest } from './proofManifest'
import { appConfig } from './config'

export type BatchOutcome =
  | 'pending'
  | 'hashing'
  | 'processing'
  | 'confirmed'
  | 'revoked'
  | 'metadata-only'
  | 'database-only'
  | 'manifest-valid'
  | 'manifest-invalid'
  | 'malformed'
  | 'oversized'
  | 'duplicate'
  | 'unsupported'
  | 'error'
  | 'unavailable'
  | 'cancelled'

export type BatchConfig = {
  maxConcurrency: number
  maxFileSizeBytes: number
  maxTotalSizeBytes: number
  apiBase: string
  contractId: string
  wallet?: string
}

export type BatchItemResult = {
  id: string
  file: File
  fileName: string
  fileSizeBytes: number
  status: BatchOutcome
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  tier: string | null
  chainStatus: string | null
  message: string
  events: VerificationEvent[]
  chainProof: ChainProofRecord | null
  duplicateOf: string | null
  manifest: ProofManifest | null
  durationMs: number | null
  failureReason: string | null
}

export type BatchProgress = {
  totalFiles: number
  completedFiles: number
  processedBytes: number
  totalBytes: number
  activeCount: number
  isCancelled: boolean
  isDone: boolean
}

export type BatchSummary = {
  totalFiles: number
  confirmed: number
  revoked: number
  unconfirmed: number
  manifests: number
  duplicates: number
  unsupported: number
  errors: number
  cancelled: number
  totalBytes: number
  durationMs: number
}

export type PreflightDuplicateItem = {
  index: number
  fileName: string
  fileSizeBytes: number
  duplicateOf: string
  reason: string
}

export type PreflightUnsupportedItem = {
  index: number
  fileName: string
  fileSizeBytes: number
  mimeType: string
  extension: string
  reason: string
}

export type PreflightOversizedItem = {
  index: number
  fileName: string
  fileSizeBytes: number
  maxAllowedBytes: number
  reason: string
}

export type BatchPreflightReport = {
  totalFiles: number
  totalBytes: number
  validCount: number
  duplicateCount: number
  unsupportedCount: number
  oversizedCount: number
  duplicates: PreflightDuplicateItem[]
  unsupported: PreflightUnsupportedItem[]
  oversized: PreflightOversizedItem[]
  hasIssues: boolean
  canProceed: boolean
  completedAt: string
}

export const SUPPORTED_VIDEO_EXTENSIONS = ['.mp4', '.mov', '.webm', '.mkv', '.avi'] as const
export const SUPPORTED_MANIFEST_EXTENSIONS = ['.json'] as const

/**
 * Checks if a file is supported based on its file extension and MIME type.
 */
export function isSupportedFormat(file: { name: string; type?: string }): {
  isSupported: boolean
  extension: string
  mimeType: string
  reason?: string
} {
  const name = file.name || ''
  const dotIndex = name.lastIndexOf('.')
  const extension = dotIndex !== -1 ? name.slice(dotIndex).toLowerCase() : ''
  const mimeType = (file.type || '').toLowerCase()

  const isVideoExt = (SUPPORTED_VIDEO_EXTENSIONS as readonly string[]).includes(extension)
  const isManifestExt = (SUPPORTED_MANIFEST_EXTENSIONS as readonly string[]).includes(extension)
  const isVideoMime = mimeType.startsWith('video/')
  const isJsonMime = mimeType === 'application/json'

  const isSupported = isVideoExt || isManifestExt || isVideoMime || isJsonMime

  if (!isSupported) {
    return {
      isSupported: false,
      extension,
      mimeType,
      reason: `Unsupported format '${extension || mimeType || 'unknown'}'. Harpocrates accepts MP4, MOV, WEBM, MKV, AVI videos or JSON proof manifests.`,
    }
  }

  return {
    isSupported: true,
    extension,
    mimeType,
  }
}

/**
 * Formats a raw byte count into human-readable metric string.
 */
export function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const val = bytes / Math.pow(1024, i)
  return `${val.toFixed(val >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

/**
 * Fast inspection of batch candidates before expensive hashing or proving.
 * Reports duplicate inputs, total bytes, unsupported formats, and oversized files.
 */
export function runBatchPreflight(
  files: File[],
  config: Partial<BatchConfig> = {},
): BatchPreflightReport {
  const maxFileSizeBytes = config.maxFileSizeBytes ?? DEFAULT_BATCH_CONFIG.maxFileSizeBytes
  const maxTotalSizeBytes = config.maxTotalSizeBytes ?? DEFAULT_BATCH_CONFIG.maxTotalSizeBytes

  const duplicates: PreflightDuplicateItem[] = []
  const unsupported: PreflightUnsupportedItem[] = []
  const oversized: PreflightOversizedItem[] = []

  let totalBytes = 0
  let cumulativeBytes = 0

  const seenByNameAndSize = new Map<string, string>()
  const seenByName = new Map<string, string>()

  const invalidIndices = new Set<number>()

  for (let i = 0; i < files.length; i++) {
    const file = files[i]
    totalBytes += file.size

    // 1. Format check
    const formatCheck = isSupportedFormat(file)
    if (!formatCheck.isSupported) {
      invalidIndices.add(i)
      unsupported.push({
        index: i,
        fileName: file.name,
        fileSizeBytes: file.size,
        mimeType: formatCheck.mimeType,
        extension: formatCheck.extension,
        reason: formatCheck.reason ?? `Unsupported format for '${file.name}'.`,
      })
    }

    // 2. Duplicate inputs check (matched before hashing)
    const nameKey = file.name.toLowerCase()
    const sizeKey = `${nameKey}:${file.size}`
    if (seenByNameAndSize.has(sizeKey)) {
      invalidIndices.add(i)
      const orig = seenByNameAndSize.get(sizeKey)!
      duplicates.push({
        index: i,
        fileName: file.name,
        fileSizeBytes: file.size,
        duplicateOf: orig,
        reason: `Duplicate input matching '${orig}' (${file.size} bytes).`,
      })
    } else if (seenByName.has(nameKey)) {
      invalidIndices.add(i)
      const orig = seenByName.get(nameKey)!
      duplicates.push({
        index: i,
        fileName: file.name,
        fileSizeBytes: file.size,
        duplicateOf: orig,
        reason: `Duplicate input file name matching '${orig}'.`,
      })
    } else {
      seenByNameAndSize.set(sizeKey, file.name)
      seenByName.set(nameKey, file.name)
    }

    // 3. Size check
    if (file.size > maxFileSizeBytes) {
      invalidIndices.add(i)
      const limitMb = Math.round(maxFileSizeBytes / (1024 * 1024))
      const fileMb = (file.size / (1024 * 1024)).toFixed(1)
      oversized.push({
        index: i,
        fileName: file.name,
        fileSizeBytes: file.size,
        maxAllowedBytes: maxFileSizeBytes,
        reason: `File exceeds size limit (${fileMb}MB > ${limitMb}MB limit).`,
      })
    } else if (cumulativeBytes + file.size > maxTotalSizeBytes) {
      invalidIndices.add(i)
      const totalLimitMb = Math.round(maxTotalSizeBytes / (1024 * 1024))
      oversized.push({
        index: i,
        fileName: file.name,
        fileSizeBytes: file.size,
        maxAllowedBytes: maxTotalSizeBytes,
        reason: `Total batch size limit exceeded (${totalLimitMb}MB max).`,
      })
    } else {
      cumulativeBytes += file.size
    }
  }

  const validCount = files.length - invalidIndices.size

  return {
    totalFiles: files.length,
    totalBytes,
    validCount,
    duplicateCount: duplicates.length,
    unsupportedCount: unsupported.length,
    oversizedCount: oversized.length,
    duplicates,
    unsupported,
    oversized,
    hasIssues: duplicates.length > 0 || unsupported.length > 0 || oversized.length > 0,
    canProceed: validCount > 0,
    completedAt: new Date().toISOString(),
  }
}

export const DEFAULT_BATCH_CONFIG: BatchConfig = {
  maxConcurrency: 3,
  maxFileSizeBytes: 100 * 1024 * 1024, // 100 MB
  maxTotalSizeBytes: 500 * 1024 * 1024, // 500 MB
  apiBase: appConfig.apiBase,
  contractId: appConfig.registryId,
}

/**
 * Computes SHA-256 hex string from a File or Blob in bounded slices while
 * listening for cancellation.
 */
export async function computeChunkedSha256(
  file: File | Blob,
  signal?: AbortSignal,
  chunkSize: number = 4 * 1024 * 1024,
): Promise<string> {
  if (signal?.aborted) {
    throw new Error('Operation cancelled.')
  }

  // For small files (< 16MB), compute directly using WebCrypto
  if (file.size <= 16 * 1024 * 1024) {
    const buffer = await file.arrayBuffer()
    if (signal?.aborted) throw new Error('Operation cancelled.')
    const digest = await crypto.subtle.digest('SHA-256', buffer)
    return hex(digest)
  }

  // For larger files, read in chunks to allow responsive cancellation and avoid UI hide
  let offset = 0
  const chunks: Uint8Array[] = []
  let totalRead = 0

  while (offset < file.size) {
    if (signal?.aborted) {
      throw new Error('Operation cancelled.')
    }
    const end = Math.min(offset + chunkSize, file.size)
    const slice = file.slice(offset, end)
    const buf = await slice.arrayBuffer()
    chunks.push(new Uint8Array(buf))
    totalRead += buf.byteLength
    offset = end
  }

  if (signal?.aborted) {
    throw new Error('Operation cancelled.')
  }

  // Concatenate chunks and digest
  const combined = new Uint8Array(totalRead)
  let pos = 0
  for (const chunk of chunks) {
    combined.set(chunk, pos)
    pos += chunk.length
  }

  const digest = await crypto.subtle.digest('SHA-256', combined.buffer)
  return hex(digest)
}

function hex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Validates whether a file is a standalone JSON proof manifest receipt.
 */
export async function tryParseManifest(file: File): Promise<ProofManifest | null> {
  if (!file.name.endsWith('.json') && file.type !== 'application/json') {
    return null
  }

  try {
    const text = await file.text()
    const parsed = JSON.parse(text) as Record<string, unknown>
    if (
      parsed &&
      parsed.protocol === 'harpocrates' &&
      typeof parsed.version === 'number' &&
      typeof parsed.videoHash === 'string' &&
      typeof parsed.metadataHash === 'string'
    ) {
      return parsed as ProofManifest
    }
    return null
  } catch {
    return null
  }
}

/**
 * Worker pool class for managing batch verification with bounded concurrency
 * and resource safety.
 */
export class BatchVerifier {
  private config: BatchConfig
  private items: BatchItemResult[] = []
  private abortController: AbortController | null = null
  private onProgressCallback?: (progress: BatchProgress, items: BatchItemResult[]) => void
  private processedHashes = new Map<string, string>() // videoHash -> itemId
  private accumulatedTotalBytes = 0
  private lastPreflight: BatchPreflightReport | null = null

  constructor(config: Partial<BatchConfig> = {}) {
    this.config = { ...DEFAULT_BATCH_CONFIG, ...config }
  }

  public updateConfig(config: Partial<BatchConfig>): void {
    this.config = { ...this.config, ...config }
  }

  public getConfig(): BatchConfig {
    return { ...this.config }
  }

  public getItems(): BatchItemResult[] {
    return [...this.items]
  }

  public setOnProgress(cb: (progress: BatchProgress, items: BatchItemResult[]) => void): void {
    this.onProgressCallback = cb
  }

  /**
   * Runs preflight check on batch inputs before expensive hashing or proving.
   */
  public runPreflight(files?: File[]): BatchPreflightReport {
    const targetFiles = files ?? this.items.map((i) => i.file)
    const report = runBatchPreflight(targetFiles, this.config)
    this.lastPreflight = report
    return report
  }

  /**
   * Returns the most recent preflight report, if available.
   */
  public getLastPreflight(): BatchPreflightReport | null {
    return this.lastPreflight
  }

  public cancel(): void {
    if (this.abortController) {
      this.abortController.abort()
    }
    for (const item of this.items) {
      if (item.status === 'pending' || item.status === 'hashing' || item.status === 'processing') {
        item.status = 'cancelled'
        item.message = 'Cancelled by user.'
        item.failureReason = 'Batch execution was aborted by user request.'
      }
    }
    this.notifyProgress(true, true)
  }

  public async runBatch(
    files: File[],
    onProgress?: (progress: BatchProgress, items: BatchItemResult[]) => void,
  ): Promise<{ items: BatchItemResult[]; summary: BatchSummary; preflight: BatchPreflightReport }> {
    if (onProgress) {
      this.onProgressCallback = onProgress
    }

    this.abortController = new AbortController()
    const signal = this.abortController.signal

    // Initialize item results
    const startTime = performance.now()
    this.processedHashes.clear()
    this.accumulatedTotalBytes = 0

    // Step 1: Preflight check completes FIRST. No hashing or proving starts until preflight completes.
    const preflight = this.runPreflight(files)
    const unsupMap = new Map(preflight.unsupported.map((u) => [u.index, u]))
    const dupMap = new Map(preflight.duplicates.map((d) => [d.index, d]))
    const overMap = new Map(preflight.oversized.map((o) => [o.index, o]))

    this.items = files.map((file, idx) => {
      const id = `item-${idx}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
      const item: BatchItemResult = {
        id,
        file,
        fileName: file.name,
        fileSizeBytes: file.size,
        status: 'pending',
        videoHash: null,
        metadataHash: null,
        sourceHash: null,
        tier: null,
        chainStatus: null,
        message: 'Queued for verification.',
        events: [],
        chainProof: null,
        duplicateOf: null,
        manifest: null,
        durationMs: null,
        failureReason: null,
      }

      // Check preflight flags upfront before any worker or hashing
      if (unsupMap.has(idx)) {
        const u = unsupMap.get(idx)!
        item.status = 'unsupported'
        item.message = u.reason
        item.failureReason = u.reason
      } else if (dupMap.has(idx)) {
        const d = dupMap.get(idx)!
        item.status = 'duplicate'
        item.duplicateOf = d.duplicateOf
        item.message = d.reason
        item.failureReason = d.reason
      } else if (overMap.has(idx)) {
        const o = overMap.get(idx)!
        item.status = 'oversized'
        item.message = o.reason
        item.failureReason = o.reason
      }

      return item
    })

    this.accumulatedTotalBytes = this.items
      .filter((i) => i.status === 'pending')
      .reduce((sum, i) => sum + i.fileSizeBytes, 0)

    this.notifyProgress(false, false)

    // Execute with bounded concurrency ONLY for pending (valid, non-duplicate, supported) items
    const queue = this.items.filter((item) => item.status === 'pending')
    const concurrency = Math.max(1, Math.min(8, this.config.maxConcurrency))

    const worker = async () => {
      while (queue.length > 0) {
        if (signal.aborted) break
        const item = queue.shift()
        if (!item) break

        await this.processItem(item, signal)
        this.notifyProgress(false, queue.length === 0)
      }
    }

    const workers = Array.from({ length: concurrency }, () => worker())
    await Promise.all(workers)

    // Ensure all remaining pending/hashing items are updated if cancelled
    if (signal.aborted) {
      for (const item of this.items) {
        if (item.status === 'pending' || item.status === 'hashing' || item.status === 'processing') {
          item.status = 'cancelled'
          item.message = 'Cancelled by user.'
          item.failureReason = 'Batch execution was aborted by user request.'
        }
      }
    }

    const endTime = performance.now()
    const summary = this.computeSummary(endTime - startTime)
    this.notifyProgress(signal.aborted, true)

    return { items: [...this.items], summary, preflight }
  }

  private async processItem(item: BatchItemResult, signal: AbortSignal): Promise<void> {
    const itemStart = performance.now()
    try {
      if (signal.aborted) {
        item.status = 'cancelled'
        item.message = 'Cancelled before starting.'
        return
      }

      // Check if item is a standalone JSON proof manifest receipt
      const manifest = await tryParseManifest(item.file)
      if (manifest) {
        item.manifest = manifest
        item.videoHash = manifest.videoHash
        item.metadataHash = manifest.metadataHash
        item.sourceHash = manifest.sourceHash
        item.tier = manifest.tier

        // Verify JSON manifest hashes match
        item.status = 'manifest-valid'
        item.message = `Valid Harpocrates JSON manifest for ${manifest.videoHash.slice(0, 8)}...`

        // Check on-chain record for manifest's video hash
        if (this.config.contractId && manifest.videoHash) {
          try {
            const { getProofByVideoHash } = await import('./stellar')
            const chainProof = await getProofByVideoHash(
              this.config.contractId,
              manifest.videoHash,
              this.config.wallet,
            )
            item.chainProof = chainProof
            if (chainProof) {
              item.chainStatus = chainProof.status === 2 ? 'Revoked' : 'Active'
              if (chainProof.status === 2) {
                item.status = 'revoked'
                item.message = 'Manifest matches revoked on-chain record.'
              }
            }
          } catch {
            // Non-fatal for manifest check
          }
        }

        item.durationMs = performance.now() - itemStart
        return
      }

      // Standard Evidence Video Processing
      item.status = 'hashing'
      item.message = 'Computing local SHA-256 commitment...'
      this.notifyProgress(false, false)

      const videoHash = await computeChunkedSha256(item.file, signal)
      item.videoHash = videoHash

      if (signal.aborted) {
        item.status = 'cancelled'
        item.message = 'Cancelled during hashing.'
        return
      }

      // Duplicate Check
      if (this.processedHashes.has(videoHash)) {
        const existingId = this.processedHashes.get(videoHash)!
        const originalItem = this.items.find((i) => i.id === existingId)
        item.status = 'duplicate'
        item.duplicateOf = originalItem ? originalItem.fileName : existingId
        item.message = `Duplicate file detected (identical hash to ${item.duplicateOf}).`
        item.durationMs = performance.now() - itemStart
        return
      }

      this.processedHashes.set(videoHash, item.id)

      // Verification Flow
      item.status = 'processing'
      item.message = 'Extracting stego metadata and checking Stellar registry...'
      this.notifyProgress(false, false)

      const result = await verifyArtifact({
        apiBase: this.config.apiBase,
        contractId: this.config.contractId,
        wallet: this.config.wallet,
        file: item.file,
        signal,
        onEvent: (event) => {
          item.events.push(event)
          if (event.message) {
            item.message = event.message
          }
          this.notifyProgress(false, false)
        },
      })

      item.videoHash = result.videoHash ?? item.videoHash
      item.metadataHash = result.metadataHash ?? null
      item.sourceHash = result.sourceHash ?? null
      item.tier = result.tier ?? null
      item.chainProof = result.chainProof ?? null
      item.chainStatus = result.chainStatus ?? null
      item.status = result.status
      item.message = result.message
      item.failureReason = result.failureReason ?? null
      item.durationMs = performance.now() - itemStart
    } catch (err) {
      if (signal.aborted) {
        item.status = 'cancelled'
        item.message = 'Cancelled.'
        item.failureReason = 'Batch execution was aborted by user request.'
      } else {
        item.status = 'error'
        item.message = err instanceof Error ? err.message : 'Unknown error.'
        item.failureReason = item.message
      }
      item.durationMs = performance.now() - itemStart
    }
  }

  private notifyProgress(isCancelled: boolean, isDone: boolean): void {
    if (!this.onProgressCallback) return
    const totalFiles = this.items.length
    const completedFiles = this.items.filter(
      (i) => i.status !== 'pending' && i.status !== 'hashing' && i.status !== 'processing',
    ).length
    const activeCount = this.items.filter(
      (i) => i.status === 'hashing' || i.status === 'processing',
    ).length
    const processedBytes = this.items.reduce((acc, i) => {
      if (i.status === 'pending' || i.status === 'hashing') return acc
      return acc + i.fileSizeBytes
    }, 0)
    this.onProgressCallback(
      {
        totalFiles,
        completedFiles,
        processedBytes,
        totalBytes: this.accumulatedTotalBytes,
        activeCount,
        isCancelled,
        isDone,
      },
      [...this.items],
    )
  }

  private computeSummary(durationMs: number): BatchSummary {
    const summary: BatchSummary = {
      totalFiles: this.items.length,
      confirmed: 0,
      revoked: 0,
      unconfirmed: 0,
      manifests: 0,
      duplicates: 0,
      unsupported: 0,
      errors: 0,
      cancelled: 0,
      totalBytes: 0,
      durationMs,
    }

    for (const item of this.items) {
      summary.totalBytes += item.fileSizeBytes
      switch (item.status) {
        case 'confirmed':
          summary.confirmed++
          break
        case 'revoked':
          summary.revoked++
          break
        case 'manifest-valid':
        case 'manifest-invalid':
          summary.manifests++
          break
        case 'duplicate':
          summary.duplicates++
          break
        case 'cancelled':
          summary.cancelled++
          break
        case 'error':
        case 'malformed':
        case 'oversized':
        case 'unavailable':
          summary.errors++
          break
        default:
          summary.unconfirmed++
          break
      }
    }

    return summary
  }
}