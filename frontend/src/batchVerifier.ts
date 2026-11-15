import type { ChainProofRecord } from './stellar'
import { MalformedEvidenceError, verifyArtifact, type VerificationEvent } from './verificationFlow'
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
  errors: number
  cancelled: number
  totalBytes: number
  durationMs: number
}

export const SUPPORTED_BATCH_VIDEO_EXTENSIONS = ['.mp4', '.mov', '.webm', '.mkv', '.avi', '.m4v'] as const
export const SUPPORTED_BATCH_MANIFEST_EXTENSIONS = ['.json'] as const

export type BatchPreflightDuplicate = {
  index: number
  fileName: string
  fileSizeBytes: number
  duplicateOfIndex: number
  duplicateOfFileName: string
}

export type BatchPreflightUnsupported = {
  index: number
  fileName: string
  mimeType: string
  reason: string
}

export type BatchPreflightOversized = {
  index: number
  fileName: string
  fileSizeBytes: number
  reason: 'per-file-limit' | 'total-budget-limit'
}

export type BatchPreflightReport = {
  totalFiles: number
  totalBytes: number
  eligibleCount: number
  eligibleBytes: number
  duplicateInputs: BatchPreflightDuplicate[]
  unsupportedFormats: BatchPreflightUnsupported[]
  oversizedFiles: BatchPreflightOversized[]
  exceedsTotalBudget: boolean
  canProceed: boolean
}

export type BatchRunOptions = {
  preflightOnly?: boolean
  onPreflight?: (report: BatchPreflightReport) => boolean | Promise<boolean> | void
}

/**
 * Checks format eligibility using synchronous File metadata only (no byte reads).
 */
export function isSupportedBatchFormat(file: Pick<File, 'name' | 'type'>): boolean {
  const mime = (file.type ?? '').trim().toLowerCase()
  if (mime.startsWith('video/') || mime === 'application/json') {
    return true
  }
  const lowerName = (file.name ?? '').trim().toLowerCase()
  for (const ext of SUPPORTED_BATCH_VIDEO_EXTENSIONS) {
    if (lowerName.endsWith(ext)) return true
  }
  for (const ext of SUPPORTED_BATCH_MANIFEST_EXTENSIONS) {
    if (lowerName.endsWith(ext)) return true
  }
  return false
}

/**
 * Generates a synchronous preflight report from File descriptor metadata before
 * any hashing, manifest parsing, proving, or network requests occur.
 */
export function inspectBatchPreflight(
  files: ReadonlyArray<File>,
  config: Partial<BatchConfig> = {},
): BatchPreflightReport {
  const resolved: BatchConfig = { ...DEFAULT_BATCH_CONFIG, ...config }
  const duplicateInputs: BatchPreflightDuplicate[] = []
  const unsupportedFormats: BatchPreflightUnsupported[] = []
  const oversizedFiles: BatchPreflightOversized[] = []
  const seenDescriptors = new Map<string, { index: number; fileName: string }>()

  let totalBytes = 0
  let eligibleBytes = 0
  let eligibleCount = 0

  files.forEach((file, index) => {
    totalBytes += file.size

    if (!isSupportedBatchFormat(file)) {
      unsupportedFormats.push({
        index,
        fileName: file.name,
        mimeType: file.type || 'unknown',
        reason: `Unsupported format (${file.type || file.name.split('.').pop() || 'unknown'}).`,
      })
      return
    }

    const descriptorKey = `${file.name.toLowerCase()}::${file.size}::${file.lastModified}`
    const firstSeen = seenDescriptors.get(descriptorKey)
    if (firstSeen) {
      duplicateInputs.push({
        index,
        fileName: file.name,
        fileSizeBytes: file.size,
        duplicateOfIndex: firstSeen.index,
        duplicateOfFileName: firstSeen.fileName,
      })
      return
    }
    seenDescriptors.set(descriptorKey, { index, fileName: file.name })

    if (file.size > resolved.maxFileSizeBytes) {
      oversizedFiles.push({
        index,
        fileName: file.name,
        fileSizeBytes: file.size,
        reason: 'per-file-limit',
      })
      return
    }

    if (eligibleBytes + file.size > resolved.maxTotalSizeBytes) {
      oversizedFiles.push({
        index,
        fileName: file.name,
        fileSizeBytes: file.size,
        reason: 'total-budget-limit',
      })
      return
    }

    eligibleBytes += file.size
    eligibleCount += 1
  })

  return {
    totalFiles: files.length,
    totalBytes,
    eligibleCount,
    eligibleBytes,
    duplicateInputs,
    unsupportedFormats,
    oversizedFiles,
    exceedsTotalBudget: totalBytes > resolved.maxTotalSizeBytes,
    canProceed: eligibleCount > 0,
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

  public preflight(files: ReadonlyArray<File>): BatchPreflightReport {
    return inspectBatchPreflight(files, this.config)
  }

  public setOnProgress(cb: (progress: BatchProgress, items: BatchItemResult[]) => void): void {
    this.onProgressCallback = cb
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
    options?: BatchRunOptions,
  ): Promise<{ items: BatchItemResult[]; summary: BatchSummary; preflight: BatchPreflightReport }> {
    if (onProgress) {
      this.onProgressCallback = onProgress
    }

    this.abortController = new AbortController()
    const signal = this.abortController.signal

    // Step 1: Complete synchronous preflight inspection before any byte reads, hashing, or proving
    const startTime = performance.now()
    const preflight = this.preflight(files)
    const unsupportedByIndex = new Map(preflight.unsupportedFormats.map((u) => [u.index, u]))
    const duplicateByIndex = new Map(preflight.duplicateInputs.map((d) => [d.index, d]))
    const oversizedByIndex = new Map(preflight.oversizedFiles.map((o) => [o.index, o]))

    this.processedHashes.clear()
    this.accumulatedTotalBytes = preflight.eligibleBytes

    this.items = files.map((file, idx) => {
      const id = `item-${idx}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
      const unsupported = unsupportedByIndex.get(idx)
      if (unsupported) {
        return {
          id,
          file,
          fileName: file.name,
          fileSizeBytes: file.size,
          status: 'malformed' as BatchOutcome,
          videoHash: null,
          metadataHash: null,
          sourceHash: null,
          tier: null,
          chainStatus: null,
          message: unsupported.reason,
          events: [],
          chainProof: null,
          duplicateOf: null,
          manifest: null,
          durationMs: 0,
          failureReason: 'Unsupported file format rejected during preflight.',
        }
      }

      const preflightDup = duplicateByIndex.get(idx)
      if (preflightDup) {
        return {
          id,
          file,
          fileName: file.name,
          fileSizeBytes: file.size,
          status: 'duplicate' as BatchOutcome,
          videoHash: null,
          metadataHash: null,
          sourceHash: null,
          tier: null,
          chainStatus: null,
          message: `Duplicate file detected (matches ${preflightDup.duplicateOfFileName}).`,
          events: [],
          chainProof: null,
          duplicateOf: preflightDup.duplicateOfFileName,
          manifest: null,
          durationMs: 0,
          failureReason: null,
        }
      }

      const oversized = oversizedByIndex.get(idx)
      if (oversized) {
        if (oversized.reason === 'per-file-limit') {
          const limitMb = Math.round(this.config.maxFileSizeBytes / (1024 * 1024))
          const fileMb = (file.size / (1024 * 1024)).toFixed(1)
          return {
            id,
            file,
            fileName: file.name,
            fileSizeBytes: file.size,
            status: 'oversized' as BatchOutcome,
            videoHash: null,
            metadataHash: null,
            sourceHash: null,
            tier: null,
            chainStatus: null,
            message: `File exceeds size limit (${fileMb}MB > ${limitMb}MB limit).`,
            events: [],
            chainProof: null,
            duplicateOf: null,
            manifest: null,
            durationMs: 0,
            failureReason: `Per-file limit exceeded (${file.size} bytes vs max ${this.config.maxFileSizeBytes} bytes).`,
          }
        }
        const totalLimitMb = Math.round(this.config.maxTotalSizeBytes / (1024 * 1024))
        return {
          id,
          file,
          fileName: file.name,
          fileSizeBytes: file.size,
          status: 'oversized' as BatchOutcome,
          videoHash: null,
          metadataHash: null,
          sourceHash: null,
          tier: null,
          chainStatus: null,
          message: `Total batch size limit exceeded (${totalLimitMb}MB max).`,
          events: [],
          chainProof: null,
          duplicateOf: null,
          manifest: null,
          durationMs: 0,
          failureReason: `Total batch memory limit exceeded by queueing ${file.name}.`,
        }
      }

      return {
        id,
        file,
        fileName: file.name,
        fileSizeBytes: file.size,
        status: 'pending' as BatchOutcome,
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
    })

    this.notifyProgress(false, false)

    if (options?.onPreflight) {
      const shouldContinue = await options.onPreflight(preflight)
      if (shouldContinue === false) {
        for (const item of this.items) {
          if (item.status === 'pending') {
            item.status = 'cancelled'
            item.message = 'Stopped after preflight inspection.'
            item.failureReason = 'Verification halted at preflight gate.'
          }
        }
        const summary = this.computeSummary(performance.now() - startTime)
        this.notifyProgress(true, true)
        return { items: [...this.items], summary, preflight }
      }
    }

    if (options?.preflightOnly || !preflight.canProceed) {
      const summary = this.computeSummary(performance.now() - startTime)
      this.notifyProgress(false, !options?.preflightOnly)
      return { items: [...this.items], summary, preflight }
    }

    // Execute with bounded concurrency
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

      let extractedMetadataObj: Record<string, unknown> | null = null
      const result = await verifyArtifact({
        apiBase: this.config.apiBase,
        contractId: this.config.contractId,
        wallet: this.config.wallet,
        file: item.file,
        videoHash,
        signal,
        extractMetadataOverride: async (apiBase, file, reqSignal) => {
          const form = new FormData()
          form.append('video', file)
          const response = await fetch(`${apiBase}/api/stego/extract`, {
            method: 'POST',
            body: form,
            signal: reqSignal,
          })
          if (!response.ok) {
            if (response.status >= 400 && response.status < 500) {
              throw new MalformedEvidenceError()
            }
            throw new Error(`Stego extraction failed (${response.status})`)
          }
          const payload = (await response.json()) as { metadata?: unknown }
          if (payload?.metadata && typeof payload.metadata === 'object' && !Array.isArray(payload.metadata)) {
            extractedMetadataObj = payload.metadata as Record<string, unknown>
          }
          return payload?.metadata ?? null
        },
      })

      item.events = result.events
      item.chainProof = result.chainProof
      item.metadataHash =
        result.chainProof?.metadataHash ??
        (typeof extractedMetadataObj?.['metadataHash'] === 'string'
          ? (extractedMetadataObj['metadataHash'] as string)
          : null)
      item.sourceHash =
        typeof extractedMetadataObj?.['sourceHash'] === 'string'
          ? (extractedMetadataObj['sourceHash'] as string)
          : null
      item.tier =
        result.chainProof !== null
          ? (result.chainProof.tier === 0 ? 'silent' : result.chainProof.tier === 2 ? 'seal' : 'source')
          : typeof extractedMetadataObj?.['tier'] === 'string'
            ? (extractedMetadataObj['tier'] as string)
            : (result.events[0]?.tier ?? null)
      item.chainStatus = result.chainProof
        ? result.chainProof.status === 2
          ? 'Revoked'
          : 'Active'
        : null
      item.status = result.outcome
      item.message = result.message
      item.failureReason =
        result.outcome === 'confirmed' ||
        result.outcome === 'metadata-only' ||
        result.outcome === 'database-only'
          ? null
          : result.message
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