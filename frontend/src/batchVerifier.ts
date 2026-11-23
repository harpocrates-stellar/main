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

/**
 * Explicit input descriptor binding a selected File to a caller-supplied
 * identity and zero-based selection index so batch results remain stably
 * ordered across concurrent completions and subset retries.
 */
export type BatchInputItem = {
  /** Stable identifier for the selected input (auto-generated when omitted). */
  id?: string
  /** Zero-based position in the original selected input list (defaults to array index). */
  inputIndex?: number
  /** Selected evidence File or standalone JSON proof manifest. */
  file: File
}

/**
 * Accepted input entry for {@link BatchVerifier.runBatch}: either a raw `File`
 * (indexed by its array position) or a {@link BatchInputItem} with an explicit
 * original input identity.
 */
export type BatchInput = File | BatchInputItem

export type BatchItemResult = {
  id: string
  /** Zero-based position of this item in the original selected input list. */
  inputIndex?: number
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
 * Returns a new array of batch results ordered by their original selected
 * `inputIndex`, never by asynchronous completion order or duration.
 *
 * Items carrying a finite `inputIndex` are placed first in ascending order
 * (with ties broken by relative array position); legacy items without a finite
 * `inputIndex` preserve their relative array position afterwards.
 */
export function orderBatchResults(results: readonly BatchItemResult[]): BatchItemResult[] {
  return results
    .map((item, position) => ({ item, position }))
    .sort((a, b) => {
      const aHasIndex =
        typeof a.item.inputIndex === 'number' && Number.isFinite(a.item.inputIndex)
      const bHasIndex =
        typeof b.item.inputIndex === 'number' && Number.isFinite(b.item.inputIndex)

      if (aHasIndex && bHasIndex) {
        const diff = (a.item.inputIndex as number) - (b.item.inputIndex as number)
        if (diff !== 0) return diff
        return a.position - b.position
      }
      if (aHasIndex) return -1
      if (bHasIndex) return 1
      return a.position - b.position
    })
    .map(({ item }) => item)
}

type HashClaim = {
  owner: BatchItemResult
  duplicates: BatchItemResult[]
  verificationPromise: Promise<void>
}

/**
 * Worker pool class for managing batch verification with bounded concurrency,
 * resource safety, and stable input-order result association regardless of
 * asynchronous completion order.
 */
export class BatchVerifier {
  private config: BatchConfig
  private items: BatchItemResult[] = []
  private abortController: AbortController | null = null
  private onProgressCallback?: (progress: BatchProgress, items: BatchItemResult[]) => void
  private hashClaims = new Map<string, HashClaim>()
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
    return this.snapshotItems()
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

  /**
   * Verifies a batch of selected files or {@link BatchInputItem} descriptors
   * with bounded concurrency.
   *
   * Results delivered to `onProgress` and returned on resolution are always
   * associated with their original selected input identities (`id` and
   * `inputIndex`) and ordered by `inputIndex`, never by worker completion order.
   */
  public async runBatch(
    inputs: readonly BatchInput[],
    onProgress?: (progress: BatchProgress, items: BatchItemResult[]) => void,
  ): Promise<{ items: BatchItemResult[]; summary: BatchSummary }> {
    if (onProgress) {
      this.onProgressCallback = onProgress
    }

    this.abortController = new AbortController()
    const signal = this.abortController.signal

    // Initialize item results bound to their original selected input identities
    const startTime = performance.now()
    this.hashClaims.clear()
    this.accumulatedTotalBytes = 0

    const batchNonce = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
    const initialItems: BatchItemResult[] = inputs.map((entry, idx) => {
      const isFile = entry instanceof File
      const file = isFile ? entry : entry.file
      const inputIndex =
        !isFile && typeof entry.inputIndex === 'number' && Number.isFinite(entry.inputIndex)
          ? entry.inputIndex
          : idx
      const id = !isFile && entry.id ? entry.id : `item-${idx}-${batchNonce}`
      return {
        id,
        inputIndex,
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
    })

    this.items = orderBatchResults(initialItems)

    this.notifyProgress(false, false)

    // Filter oversized files upfront based on total and per-file limits
    let currentBatchBytes = 0
    for (const item of this.items) {
      if (item.fileSizeBytes > this.config.maxFileSizeBytes) {
        item.status = 'oversized'
        const limitMb = Math.round(this.config.maxFileSizeBytes / (1024 * 1024))
        const fileMb = (item.fileSizeBytes / (1024 * 1024)).toFixed(1)
        item.message = `File exceeds size limit (${fileMb}MB > ${limitMb}MB limit).`
        item.failureReason = `Per-file limit exceeded (${item.fileSizeBytes} bytes vs max ${this.config.maxFileSizeBytes} bytes).`
        continue
      }

      if (currentBatchBytes + item.fileSizeBytes > this.config.maxTotalSizeBytes) {
        item.status = 'oversized'
        const totalLimitMb = Math.round(this.config.maxTotalSizeBytes / (1024 * 1024))
        item.message = `Total batch size limit exceeded (${totalLimitMb}MB max).`
        item.failureReason = `Total batch memory limit exceeded by queueing ${item.fileName}.`
        continue
      }

      currentBatchBytes += item.fileSizeBytes
    }

    this.accumulatedTotalBytes = currentBatchBytes
    this.notifyProgress(false, false)

    // Execute with bounded concurrency while writing back to fixed input slots
    const queue = this.items.filter((item) => item.status === 'pending')
    const concurrency = Math.max(1, Math.min(8, this.config.maxConcurrency))

    const worker = async () => {
      while (queue.length > 0) {
        if (signal.aborted) break
        const item = queue.shift()
        if (!item) break

        await this.processItem(item, signal)
        this.notifyProgress(false, false)
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

    return { items: this.snapshotItems(), summary }
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

      // Duplicate Check — deterministic by original inputIndex, not completion order
      const existingClaim = this.hashClaims.get(videoHash)
      if (existingClaim) {
        if (this.compareInputOrder(item, existingClaim.owner) < 0) {
          // An item with a later inputIndex hashed first; await its single
          // verification pass and transfer canonical ownership to this earlier item.
          await existingClaim.verificationPromise
          if (signal.aborted) {
            item.status = 'cancelled'
            item.message = 'Cancelled.'
            item.failureReason = 'Batch execution was aborted by user request.'
            item.durationMs = performance.now() - itemStart
            return
          }
          if (this.compareInputOrder(item, existingClaim.owner) < 0) {
            const previousOwner = existingClaim.owner
            item.videoHash = previousOwner.videoHash ?? videoHash
            item.metadataHash = previousOwner.metadataHash
            item.sourceHash = previousOwner.sourceHash
            item.tier = previousOwner.tier
            item.chainProof = previousOwner.chainProof
            item.chainStatus = previousOwner.chainStatus
            item.status = previousOwner.status
            item.message = previousOwner.message
            item.events = [...previousOwner.events]
            item.failureReason = previousOwner.failureReason
            item.duplicateOf = null
            item.durationMs = performance.now() - itemStart

            previousOwner.metadataHash = null
            previousOwner.sourceHash = null
            previousOwner.tier = null
            previousOwner.chainProof = null
            previousOwner.chainStatus = null
            previousOwner.events = []
            previousOwner.failureReason = null
            existingClaim.duplicates.push(previousOwner)
            existingClaim.owner = item

            for (const dup of existingClaim.duplicates) {
              dup.status = 'duplicate'
              dup.duplicateOf = item.fileName
              dup.message = `Duplicate file detected (identical hash to ${item.fileName}).`
            }
            return
          }
        }

        this.markAsDuplicate(item, existingClaim.owner, itemStart)
        existingClaim.duplicates.push(item)
        return
      }

      const verificationPromise = this.runVerification(item, signal, itemStart)
      this.hashClaims.set(videoHash, {
        owner: item,
        duplicates: [],
        verificationPromise,
      })
      await verificationPromise
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

  private async runVerification(
    item: BatchItemResult,
    signal: AbortSignal,
    itemStart: number,
  ): Promise<void> {
    try {
      // Verification Flow
      item.status = 'processing'
      item.message = 'Extracting stego metadata and checking Stellar registry...'
      this.notifyProgress(false, false)

      const result = await verifyArtifact({
        apiBase: this.config.apiBase,
        contractId: this.config.contractId,
        wallet: this.config.wallet,
        file: item.file,
        videoHash: item.videoHash ?? '',
        signal,
      })

      item.events = [...result.events]
      item.chainProof = result.chainProof ?? null
      item.chainStatus = result.chainProof
        ? result.chainProof.status === 2
          ? 'Revoked'
          : 'Active'
        : null
      item.metadataHash = result.chainProof?.metadataHash ?? null
      item.sourceHash = null
      item.tier = result.events[0]?.tier ?? null
      item.status = result.outcome
      item.message = result.message
      item.failureReason =
        result.outcome === 'malformed' ||
        result.outcome === 'unavailable' ||
        result.outcome === 'revoked'
          ? result.message
          : null
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

  private compareInputOrder(a: BatchItemResult, b: BatchItemResult): number {
    const aIdx = typeof a.inputIndex === 'number' && Number.isFinite(a.inputIndex) ? a.inputIndex : Number.MAX_SAFE_INTEGER
    const bIdx = typeof b.inputIndex === 'number' && Number.isFinite(b.inputIndex) ? b.inputIndex : Number.MAX_SAFE_INTEGER
    if (aIdx !== bIdx) return aIdx - bIdx
    return this.items.indexOf(a) - this.items.indexOf(b)
  }

  private markAsDuplicate(item: BatchItemResult, originalItem: BatchItemResult, itemStart: number): void {
    item.status = 'duplicate'
    item.duplicateOf = originalItem.fileName
    item.message = `Duplicate file detected (identical hash to ${item.duplicateOf}).`
    item.durationMs = performance.now() - itemStart
  }

  private snapshotItems(): BatchItemResult[] {
    return orderBatchResults(this.items).map((item) => ({
      ...item,
      events: [...item.events],
    }))
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
      this.snapshotItems(),
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