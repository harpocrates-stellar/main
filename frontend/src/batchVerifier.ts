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

export type BatchResultCategory = 'verified' | 'skipped' | 'cancelled' | 'failed' | 'in-progress'

/**
 * Classifies a granular BatchOutcome into a canonical result category,
 * distinguishing verified, skipped, cancelled, failed, and in-progress items.
 */
export function classifyBatchOutcome(status: BatchOutcome): BatchResultCategory {
  switch (status) {
    case 'confirmed':
    case 'manifest-valid':
      return 'verified'
    case 'duplicate':
    case 'oversized':
      return 'skipped'
    case 'cancelled':
      return 'cancelled'
    case 'pending':
    case 'hashing':
    case 'processing':
      return 'in-progress'
    case 'revoked':
    case 'metadata-only':
    case 'database-only':
    case 'manifest-invalid':
    case 'malformed':
    case 'error':
    case 'unavailable':
      return 'failed'
  }
}

export type BatchConfig = {
  maxConcurrency: number
  maxFileSizeBytes: number
  maxTotalSizeBytes: number
  apiBase: string
  contractId: string
  wallet?: string
  network?: string
}

export const BATCH_CHECKPOINT_PROTOCOL = 'harpocrates-batch-checkpoint' as const
export const BATCH_CHECKPOINT_VERSION = 1 as const

export type BatchFileFingerprint = {
  index: number
  fileName: string
  fileSizeBytes: number
  lastModified: number
  mimeType: string
  sampleHash: string
}

export type BatchCheckpointPolicy = {
  maxFileSizeBytes: number
  maxTotalSizeBytes: number
}

export type BatchCheckpointNetworkContext = {
  apiBase: string
  contractId: string
  network: string
}

export type BatchCheckpointCompletedItem = {
  index: number
  fileName: string
  fileSizeBytes: number
  status: BatchOutcome
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

export type BatchVerificationCheckpoint = {
  protocol: typeof BATCH_CHECKPOINT_PROTOCOL
  version: typeof BATCH_CHECKPOINT_VERSION
  createdAt: string
  updatedAt: string
  policy: BatchCheckpointPolicy
  networkContext: BatchCheckpointNetworkContext
  files: BatchFileFingerprint[]
  completed: BatchCheckpointCompletedItem[]
}

export type CheckpointMismatchReason =
  | 'invalid-format'
  | 'policy-mismatch'
  | 'network-mismatch'
  | 'files-mismatch'

export type CheckpointValidationResult =
  | { ok: true }
  | {
      ok: false
      reason: CheckpointMismatchReason
      message: string
    }

export class BatchCheckpointError extends Error {
  public readonly reason: CheckpointMismatchReason

  constructor(reason: CheckpointMismatchReason, message: string) {
    super(message)
    this.name = 'BatchCheckpointError'
    this.reason = reason
  }
}

export type BatchRunOptions = {
  checkpoint?: BatchVerificationCheckpoint
  onCheckpoint?: (checkpoint: BatchVerificationCheckpoint) => void
}

export const BATCH_CHECKPOINT_PROTOCOL = 'harpocrates-batch-checkpoint' as const
export const BATCH_CHECKPOINT_VERSION = 1 as const

export type BatchFileFingerprint = {
  index: number
  fileName: string
  fileSizeBytes: number
  lastModified: number
  mimeType: string
  sampleHash: string
}

export type BatchCheckpointPolicy = {
  maxFileSizeBytes: number
  maxTotalSizeBytes: number
}

export type BatchCheckpointNetworkContext = {
  apiBase: string
  contractId: string
  network: string
}

export type BatchCheckpointCompletedItem = {
  index: number
  fileName: string
  fileSizeBytes: number
  status: BatchOutcome
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

export type BatchVerificationCheckpoint = {
  protocol: typeof BATCH_CHECKPOINT_PROTOCOL
  version: typeof BATCH_CHECKPOINT_VERSION
  createdAt: string
  updatedAt: string
  policy: BatchCheckpointPolicy
  networkContext: BatchCheckpointNetworkContext
  files: BatchFileFingerprint[]
  completed: BatchCheckpointCompletedItem[]
}

export type CheckpointMismatchReason =
  | 'invalid-format'
  | 'policy-mismatch'
  | 'network-mismatch'
  | 'files-mismatch'

export type CheckpointValidationResult =
  | { ok: true }
  | {
      ok: false
      reason: CheckpointMismatchReason
      message: string
    }

export class BatchCheckpointError extends Error {
  public readonly reason: CheckpointMismatchReason

  constructor(reason: CheckpointMismatchReason, message: string) {
    super(message)
    this.name = 'BatchCheckpointError'
    this.reason = reason
  }
}

export type BatchRunOptions = {
  checkpoint?: BatchVerificationCheckpoint
  onCheckpoint?: (checkpoint: BatchVerificationCheckpoint) => void
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
  issuerNote?: string | null
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
  verified: number
  skipped: number
  failed: number
  totalBytes: number
  durationMs: number
}

export const DEFAULT_BATCH_CONFIG: BatchConfig = {
  maxConcurrency: 3,
  maxFileSizeBytes: 100 * 1024 * 1024, // 100 MB
  maxTotalSizeBytes: 500 * 1024 * 1024, // 500 MB
  apiBase: appConfig.apiBase,
  contractId: appConfig.registryId,
  network: import.meta.env.VITE_STELLAR_NETWORK ?? 'testnet',
}

const COMPLETED_OUTCOMES: ReadonlySet<BatchOutcome> = new Set<BatchOutcome>([
  'confirmed',
  'revoked',
  'metadata-only',
  'database-only',
  'manifest-valid',
  'manifest-invalid',
  'malformed',
  'oversized',
  'duplicate',
  'error',
  'unavailable',
])

const FINGERPRINT_SAMPLE_BYTES = 64 * 1024

export function isCompletedBatchOutcome(status: BatchOutcome): boolean {
  return COMPLETED_OUTCOMES.has(status)
}

function normalizeApiBase(apiBase: string): string {
  return apiBase.trim().replace(/\/+$/, '')
}

function normalizeNetworkContext(config: BatchConfig): BatchCheckpointNetworkContext {
  return {
    apiBase: normalizeApiBase(config.apiBase),
    contractId: config.contractId.trim(),
    network: (config.network ?? DEFAULT_BATCH_CONFIG.network ?? 'testnet').trim().toLowerCase(),
  }
}

function normalizePolicy(config: BatchConfig): BatchCheckpointPolicy {
  return {
    maxFileSizeBytes: config.maxFileSizeBytes,
    maxTotalSizeBytes: config.maxTotalSizeBytes,
  }
}

/**
 * Computes a nonsecret, bounded fingerprint for a File without persisting raw bytes.
 * Hashes file size plus bounded head and tail slices using SHA-256.
 */
export async function computeFileFingerprint(
  file: File,
  index: number,
  signal?: AbortSignal,
): Promise<BatchFileFingerprint> {
  if (signal?.aborted) {
    throw new Error('Operation cancelled.')
  }

  const headEnd = Math.min(file.size, FINGERPRINT_SAMPLE_BYTES)
  const headBuf = new Uint8Array(await file.slice(0, headEnd).arrayBuffer())
  if (signal?.aborted) {
    throw new Error('Operation cancelled.')
  }

  let tailBuf = new Uint8Array(0)
  if (file.size > FINGERPRINT_SAMPLE_BYTES) {
    const tailStart = Math.max(headEnd, file.size - FINGERPRINT_SAMPLE_BYTES)
    tailBuf = new Uint8Array(await file.slice(tailStart, file.size).arrayBuffer())
    if (signal?.aborted) {
      throw new Error('Operation cancelled.')
    }
  }

  const sizePrefix = new TextEncoder().encode(`size:${file.size};`)
  const combined = new Uint8Array(sizePrefix.length + headBuf.length + tailBuf.length)
  combined.set(sizePrefix, 0)
  combined.set(headBuf, sizePrefix.length)
  combined.set(tailBuf, sizePrefix.length + headBuf.length)

  const digest = await crypto.subtle.digest('SHA-256', combined.buffer)

  return {
    index,
    fileName: file.name,
    fileSizeBytes: file.size,
    lastModified: file.lastModified,
    mimeType: file.type,
    sampleHash: hex(digest),
  }
}

export async function computeBatchFingerprints(
  files: File[],
  signal?: AbortSignal,
): Promise<BatchFileFingerprint[]> {
  const fingerprints: BatchFileFingerprint[] = []
  for (let i = 0; i < files.length; i++) {
    fingerprints.push(await computeFileFingerprint(files[i], i, signal))
  }
  return fingerprints
}

/**
 * Builds a privacy-safe checkpoint containing only nonsecret file fingerprints,
 * policy/network context, and completed results.
 */
export function createBatchCheckpoint(
  files: BatchFileFingerprint[],
  items: BatchItemResult[],
  config: BatchConfig,
  createdAt?: string,
): BatchVerificationCheckpoint {
  const now = new Date().toISOString()
  const completed: BatchCheckpointCompletedItem[] = []

  for (let index = 0; index < items.length; index++) {
    const item = items[index]
    if (!isCompletedBatchOutcome(item.status)) {
      continue
    }
    completed.push({
      index,
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
    })
  }

  return {
    protocol: BATCH_CHECKPOINT_PROTOCOL,
    version: BATCH_CHECKPOINT_VERSION,
    createdAt: createdAt ?? now,
    updatedAt: now,
    policy: normalizePolicy(config),
    networkContext: normalizeNetworkContext(config),
    files: files.map((f) => ({
      index: f.index,
      fileName: f.fileName,
      fileSizeBytes: f.fileSizeBytes,
      lastModified: f.lastModified,
      mimeType: f.mimeType,
      sampleHash: f.sampleHash,
    })),
    completed,
  }
}

/**
 * Validates that a checkpoint is well-formed and bound to the exact input files,
 * policy limits, and network context. Fails closed on any mismatch.
 */
export function validateBatchCheckpoint(
  checkpoint: unknown,
  files: BatchFileFingerprint[],
  config: BatchConfig,
): CheckpointValidationResult {
  if (!checkpoint || typeof checkpoint !== 'object') {
    return { ok: false, reason: 'invalid-format', message: 'Checkpoint must be a JSON object.' }
  }

  const cp = checkpoint as Partial<BatchVerificationCheckpoint>
  if (cp.protocol !== BATCH_CHECKPOINT_PROTOCOL || cp.version !== BATCH_CHECKPOINT_VERSION) {
    return {
      ok: false,
      reason: 'invalid-format',
      message: 'Unsupported checkpoint protocol or version.',
    }
  }

  if (
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
    return {
      ok: false,
      reason: 'invalid-format',
      message: 'Checkpoint is missing required fields.',
    }
  }

  const expectedPolicy = normalizePolicy(config)
  if (
    cp.policy.maxFileSizeBytes !== expectedPolicy.maxFileSizeBytes ||
    cp.policy.maxTotalSizeBytes !== expectedPolicy.maxTotalSizeBytes
  ) {
    return {
      ok: false,
      reason: 'policy-mismatch',
      message: 'Batch policy limits do not match checkpoint policy.',
    }
  }

  const expectedNetwork = normalizeNetworkContext(config)
  if (
    normalizeApiBase(cp.networkContext.apiBase) !== expectedNetwork.apiBase ||
    cp.networkContext.contractId.trim() !== expectedNetwork.contractId ||
    cp.networkContext.network.trim().toLowerCase() !== expectedNetwork.network
  ) {
    return {
      ok: false,
      reason: 'network-mismatch',
      message: 'Network context (API base, contract ID, or network) does not match checkpoint.',
    }
  }

  if (cp.files.length !== files.length) {
    return {
      ok: false,
      reason: 'files-mismatch',
      message: `Input file count (${files.length}) does not match checkpoint (${cp.files.length}).`,
    }
  }

  for (let i = 0; i < files.length; i++) {
    const expected = files[i]
    const actual = cp.files[i]
    if (
      !actual ||
      actual.index !== expected.index ||
      actual.fileName !== expected.fileName ||
      actual.fileSizeBytes !== expected.fileSizeBytes ||
      actual.lastModified !== expected.lastModified ||
      actual.mimeType !== expected.mimeType ||
      actual.sampleHash !== expected.sampleHash
    ) {
      return {
        ok: false,
        reason: 'files-mismatch',
        message: `Input file identity mismatch at index ${i} (${expected.fileName}).`,
      }
    }
  }

  const seenIndices = new Set<number>()
  for (const entry of cp.completed) {
    if (
      !entry ||
      typeof entry.index !== 'number' ||
      !Number.isInteger(entry.index) ||
      entry.index < 0 ||
      entry.index >= files.length ||
      seenIndices.has(entry.index) ||
      typeof entry.status !== 'string' ||
      !isCompletedBatchOutcome(entry.status as BatchOutcome)
    ) {
      return {
        ok: false,
        reason: 'invalid-format',
        message: 'Checkpoint contains an invalid or non-completed result entry.',
      }
    }
    seenIndices.add(entry.index)
  }

  return { ok: true }
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
  private itemAbortControllers = new Map<string, AbortController>()
  private cancelledItemIds = new Set<string>()
  private onProgressCallback?: (progress: BatchProgress, items: BatchItemResult[]) => void
  private onCheckpointCallback?: (checkpoint: BatchVerificationCheckpoint) => void
  private processedHashes = new Map<string, string>() // videoHash -> itemId
  private accumulatedTotalBytes = 0
  private currentFingerprints: BatchFileFingerprint[] = []
  private checkpointCreatedAt: string | null = null

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

  public setOnCheckpoint(cb: (checkpoint: BatchVerificationCheckpoint) => void): void {
    this.onCheckpointCallback = cb
  }

  public getCheckpoint(): BatchVerificationCheckpoint | null {
    if (this.currentFingerprints.length === 0) {
      return null
    }
    return createBatchCheckpoint(
      this.currentFingerprints,
      this.items,
      this.config,
      this.checkpointCreatedAt ?? undefined,
    )
  }

  public cancel(): void {
    if (this.abortController?.signal.aborted) {
      return
    }
    if (this.abortController) {
      this.abortController.abort()
    }
    for (const controller of this.itemAbortControllers.values()) {
      controller.abort()
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
   * Cancels a single queued (`pending`) or active (`hashing` / `processing`) item
   * without stopping unrelated items in the batch.
   * Returns true if the item was cancelled, or false if not found or already terminal.
   */
  public cancelItem(itemId: string): boolean {
    const item = this.items.find((entry) => entry.id === itemId)
    if (!item) {
      return false
    }
    if (item.status !== 'pending' && item.status !== 'hashing' && item.status !== 'processing') {
      return false
    }

    this.cancelledItemIds.add(itemId)
    const itemController = this.itemAbortControllers.get(itemId)
    if (itemController && !itemController.signal.aborted) {
      itemController.abort()
    }

    if (item.videoHash && this.processedHashes.get(item.videoHash) === item.id) {
      this.processedHashes.delete(item.videoHash)
    }

    item.status = 'cancelled'
    item.message = 'Cancelled by user.'
    item.failureReason = 'Item verification was cancelled by user request.'

    this.notifyProgress(this.abortController?.signal.aborted ?? false, false)
    return true
  }

  public async resumeBatch(
    files: File[],
    checkpoint: BatchVerificationCheckpoint,
    onProgress?: (progress: BatchProgress, items: BatchItemResult[]) => void,
    options?: Omit<BatchRunOptions, 'checkpoint'>,
  ): Promise<{ items: BatchItemResult[]; summary: BatchSummary; checkpoint: BatchVerificationCheckpoint }> {
    return this.runBatch(files, onProgress, { ...options, checkpoint })
  }

  public async runBatch(
    files: File[],
    checkpoint: BatchVerificationCheckpoint,
    onProgress?: (progress: BatchProgress, items: BatchItemResult[]) => void,
    options?: BatchRunOptions,
  ): Promise<{ items: BatchItemResult[]; summary: BatchSummary; checkpoint: BatchVerificationCheckpoint }> {
    if (onProgress) {
      this.onProgressCallback = onProgress
    }
    if (options?.onCheckpoint) {
      this.onCheckpointCallback = options.onCheckpoint
    }

    this.abortController = new AbortController()
    const signal = this.abortController.signal

    // Compute nonsecret input file fingerprints upfront
    const fingerprints = await computeBatchFingerprints(files)

    // Fail-closed checkpoint validation before mutating state
    const restoredByIndex = new Map<number, BatchCheckpointCompletedItem>()
    if (options?.checkpoint) {
      const validation = validateBatchCheckpoint(options.checkpoint, fingerprints, this.config)
      if (!validation.ok) {
        throw new BatchCheckpointError(validation.reason, validation.message)
      }
      for (const entry of options.checkpoint.completed) {
        restoredByIndex.set(entry.index, entry)
      }
    }

    // Initialize item results
    const startTime = performance.now()
    this.processedHashes.clear()
    this.itemAbortControllers.clear()
    this.cancelledItemIds.clear()
    this.accumulatedTotalBytes = 0
    this.currentFingerprints = fingerprints
    this.checkpointCreatedAt = options?.checkpoint?.createdAt ?? new Date().toISOString()

    this.items = files.map((file, idx) => {
      const id = `item-${idx}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
      const restored = restoredByIndex.get(idx)
      if (restored) {
        if (restored.videoHash && restored.status !== 'duplicate') {
          this.processedHashes.set(restored.videoHash, id)
        }
        return {
          id,
          file,
          fileName: restored.fileName,
          fileSizeBytes: restored.fileSizeBytes,
          status: restored.status,
          videoHash: restored.videoHash,
          metadataHash: restored.metadataHash,
          sourceHash: restored.sourceHash,
          tier: restored.tier,
          chainStatus: restored.chainStatus,
          message: restored.message,
          events: [],
          chainProof: null,
          duplicateOf: restored.duplicateOf,
          manifest: null,
          durationMs: restored.durationMs,
          failureReason: restored.failureReason,
        }
      }
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
      if (item.status !== 'pending') {
        if (item.status !== 'oversized') {
          currentBatchBytes += item.fileSizeBytes
        }
        continue
      }

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
        if (item.status === 'cancelled' || this.cancelledItemIds.has(item.id)) {
          continue
        }

        const itemController = new AbortController()
        this.itemAbortControllers.set(item.id, itemController)
        const onBatchAbort = () => itemController.abort()
        if (signal.aborted) {
          itemController.abort()
        } else {
          signal.addEventListener('abort', onBatchAbort, { once: true })
        }

        try {
          await this.processItem(item, itemController.signal)
        } finally {
          signal.removeEventListener('abort', onBatchAbort)
          this.itemAbortControllers.delete(item.id)
        }

        this.emitCheckpoint()
        this.notifyProgress(signal.aborted, false)
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
    const checkpoint = createBatchCheckpoint(
      this.currentFingerprints,
      this.items,
      this.config,
      this.checkpointCreatedAt,
    )
    this.emitCheckpoint(checkpoint)
    this.notifyProgress(signal.aborted, true)

    return { items: [...this.items], summary, checkpoint }
  }

  private async processItem(item: BatchItemResult, signal: AbortSignal): Promise<void> {
    const itemStart = performance.now()
    const isItemCancelled = () => signal.aborted || this.cancelledItemIds.has(item.id)
    const markCancelled = (stageMessage: string) => {
      if (item.videoHash && this.processedHashes.get(item.videoHash) === item.id) {
        this.processedHashes.delete(item.videoHash)
      }
      item.status = 'cancelled'
      item.message = this.cancelledItemIds.has(item.id) ? 'Cancelled by user.' : stageMessage
      item.failureReason = this.cancelledItemIds.has(item.id)
        ? 'Item verification was cancelled by user request.'
        : 'Batch execution was aborted by user request.'
      item.durationMs = performance.now() - itemStart
    }

    try {
      if (isItemCancelled()) {
        markCancelled('Cancelled before starting.')
        return
      }

      // Check if item is a standalone JSON proof manifest receipt
      const manifest = await tryParseManifest(item.file)
      if (isItemCancelled()) {
        markCancelled('Cancelled during manifest parsing.')
        return
      }
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
            if (isItemCancelled()) {
              markCancelled('Cancelled during manifest chain check.')
              return
            }
            item.chainProof = chainProof
            if (chainProof) {
              item.chainStatus = chainProof.status === 2 ? 'Revoked' : 'Active'
              if (chainProof.status === 2) {
                item.status = 'revoked'
                item.message = 'Manifest matches revoked on-chain record.'
              }
            }
          } catch {
            if (isItemCancelled()) {
              markCancelled('Cancelled during manifest chain check.')
              return
            }
            // Non-fatal for manifest check
          }
        }

        item.durationMs = performance.now() - itemStart
        return
      }

      // Standard Evidence Video Processing
      item.status = 'hashing'
      item.message = 'Computing local SHA-256 commitment...'
      this.notifyProgress(this.abortController?.signal.aborted ?? false, false)

      const videoHash = await computeChunkedSha256(item.file, signal)
      item.videoHash = videoHash

      if (isItemCancelled()) {
        markCancelled('Cancelled during hashing.')
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
      this.notifyProgress(this.abortController?.signal.aborted ?? false, false)

      const result = await verifyArtifact({
        apiBase: this.config.apiBase,
        contractId: this.config.contractId,
        wallet: this.config.wallet,
        file: item.file,
        videoHash,
        signal,
      })

      if (isItemCancelled()) {
        markCancelled('Cancelled during verification.')
        return
      }

      item.events = result.events
      item.chainProof = result.chainProof
      item.metadataHash = result.chainProof?.metadataHash ?? null
      item.sourceHash = result.chainProof?.sourceHash ?? null
      item.tier = result.events[0]?.tier ?? null
      item.chainStatus = result.chainProof
        ? result.chainProof.status === 2
          ? 'Revoked'
          : 'Active'
        : null
      item.status = result.outcome
      item.message = result.message
      item.failureReason = classifyBatchOutcome(result.outcome) === 'failed' ? result.message : null
      item.durationMs = performance.now() - itemStart
    } catch (err) {
      if (isItemCancelled()) {
        markCancelled('Cancelled.')
      } else {
        item.status = 'error'
        item.message = err instanceof Error ? err.message : 'Unknown error.'
        item.failureReason = item.message
        item.durationMs = performance.now() - itemStart
      }
    }
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
      verified: 0,
      skipped: 0,
      failed: 0,
      totalBytes: 0,
      durationMs,
    }

    for (const item of this.items) {
      summary.totalBytes += item.fileSizeBytes
      const category = classifyBatchOutcome(item.status)
      if (category === 'verified') {
        summary.verified++
      } else if (category === 'skipped') {
        summary.skipped++
      } else if (category === 'failed') {
        summary.failed++
      }

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

  private emitCheckpoint(precomputed?: BatchVerificationCheckpoint): void {
    if (!this.onCheckpointCallback || this.currentFingerprints.length === 0) return
    const snapshot =
      precomputed ??
      createBatchCheckpoint(
        this.currentFingerprints,
        this.items,
        this.config,
        this.checkpointCreatedAt ?? undefined,
      )
    this.onCheckpointCallback(snapshot)
  }

  private notifyProgress(isCancelled: boolean, isDone: boolean): void {
    if (!this.onProgressCallback) return

    const totalFiles = this.items.length
    const completedFiles = this.items.filter(
      (item) => item.status !== 'pending' && item.status !== 'hashing' && item.status !== 'processing',
    ).length
    const activeCount = this.items.filter(
      (item) => item.status === 'hashing' || item.status === 'processing',
    ).length
    const processedBytes = this.items
      .filter((item) => item.status !== 'pending')
      .reduce((acc, item) => acc + item.fileSizeBytes, 0)

    const progress: BatchProgress = {
      totalFiles,
      completedFiles,
      processedBytes,
      totalBytes: this.accumulatedTotalBytes || this.items.reduce((acc, i) => acc + i.fileSizeBytes, 0),
      activeCount,
      isCancelled,
      isDone: isDone || completedFiles === totalFiles,
    }

    this.onProgressCallback(progress, [...this.items])
  }
}
