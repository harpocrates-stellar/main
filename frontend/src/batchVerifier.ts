import type { ChainProofRecord } from './stellar'
import { CONTRACT_NETWORK_PASSPHRASE } from './harpocratesRegistry'
import { CheckpointStorage } from './lib/checkpointStorage'
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
  networkPassphrase?: string
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

export const DEFAULT_BATCH_CONFIG: BatchConfig = {
  maxConcurrency: 3,
  maxFileSizeBytes: 100 * 1024 * 1024, // 100 MB
  maxTotalSizeBytes: 500 * 1024 * 1024, // 500 MB
  apiBase: appConfig.apiBase,
  contractId: appConfig.registryId,
  networkPassphrase: CONTRACT_NETWORK_PASSPHRASE,
}

export type BatchInputFingerprint = {
  inputIndex: number
  sizeBytes: number
  lastModified: number
  mimeType: string
  fingerprintId: string
}

export type BatchCompletedCheckpointEntry = {
  inputIndex: number
  fingerprintId: string
  status: BatchOutcome
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  tier: string | null
  chainStatus: string | null
  message: string
  duplicateOfIndex: number | null
  manifest: ProofManifest | null
  durationMs: number | null
  failureReason: string | null
}

export type BatchCheckpointPolicyBinding = {
  maxFileSizeBytes: number
  maxTotalSizeBytes: number
}

export type BatchCheckpointNetworkBinding = {
  apiBase: string
  contractId: string
  networkPassphrase: string
}

export type BatchVerificationCheckpoint = {
  protocol: 'harpocrates-batch-checkpoint'
  version: 1
  createdAt: string
  policy: BatchCheckpointPolicyBinding
  network: BatchCheckpointNetworkBinding
  inputFingerprints: BatchInputFingerprint[]
  completedEntries: BatchCompletedCheckpointEntry[]
}

export type BatchCheckpointErrorCode =
  | 'malformed_checkpoint'
  | 'unsupported_version'
  | 'files_mismatch'
  | 'policy_mismatch'
  | 'network_mismatch'

export class BatchCheckpointError extends Error {
  public readonly code: BatchCheckpointErrorCode

  constructor(code: BatchCheckpointErrorCode, message: string) {
    super(message)
    this.name = 'BatchCheckpointError'
    this.code = code
  }
}

const CHECKPOINTABLE_TERMINAL_OUTCOMES = new Set<BatchOutcome>([
  'confirmed',
  'revoked',
  'manifest-valid',
  'manifest-invalid',
  'duplicate',
  'oversized',
])

function fnv1aHex(input: string): string {
  let h1 = 0x811c9dc5
  let h2 = 0x01000193
  for (let i = 0; i < input.length; i += 1) {
    const ch = input.charCodeAt(i)
    h1 ^= ch
    h1 = Math.imul(h1, 0x01000193) >>> 0
    h2 ^= ch + (i & 0xff)
    h2 = Math.imul(h2, 0x85ebca6b) >>> 0
  }
  return `${h1.toString(16).padStart(8, '0')}${h2.toString(16).padStart(8, '0')}`
}

function extractSafeBaseName(rawName: string): string {
  const normalized = (rawName ?? '').replace(/\\/g, '/')
  const parts = normalized.split('/').filter((seg) => seg.length > 0)
  return parts.length > 0 ? parts[parts.length - 1] : ''
}

function normalizeApiBase(apiBase: string): string {
  return (apiBase ?? '').trim().replace(/\/+$/, '')
}

/**
 * Computes a non-secret descriptor fingerprint for a selected File without
 * embedding raw file paths, media buffers, or private credentials.
 */
export function computeBatchInputFingerprint(
  file: Pick<File, 'name' | 'size' | 'type'> & { lastModified?: number },
  inputIndex: number,
): BatchInputFingerprint {
  const baseName = extractSafeBaseName(file.name)
  const sizeBytes = file.size
  const lastModified =
    typeof file.lastModified === 'number' && Number.isFinite(file.lastModified) ? file.lastModified : 0
  const mimeType = (file.type ?? '').trim().toLowerCase()
  const descriptor = `v1|${inputIndex}|${sizeBytes}|${lastModified}|${mimeType}|${baseName}`
  return {
    inputIndex,
    sizeBytes,
    lastModified,
    mimeType,
    fingerprintId: `fp-${inputIndex}-${fnv1aHex(descriptor)}`,
  }
}

/**
 * Builds a privacy-safe checkpoint containing only non-secret input fingerprints
 * and completed terminal verification outcomes.
 */
export function createBatchCheckpoint(
  files: ReadonlyArray<File>,
  items: ReadonlyArray<BatchItemResult>,
  config: Partial<BatchConfig> = {},
): BatchVerificationCheckpoint {
  const resolved: BatchConfig = { ...DEFAULT_BATCH_CONFIG, ...config }
  const inputFingerprints = files.map((file, idx) => computeBatchInputFingerprint(file, idx))
  const fileNameToFirstIndex = new Map<string, number>()
  files.forEach((file, idx) => {
    if (!fileNameToFirstIndex.has(file.name)) {
      fileNameToFirstIndex.set(file.name, idx)
    }
  })

  const completedEntries: BatchCompletedCheckpointEntry[] = []

  items.forEach((item, idx) => {
    if (idx >= inputFingerprints.length) return
    if (!CHECKPOINTABLE_TERMINAL_OUTCOMES.has(item.status)) return

    const fp = inputFingerprints[idx]
    const duplicateOfIndex =
      item.duplicateOf !== null ? (fileNameToFirstIndex.get(item.duplicateOf) ?? null) : null

    completedEntries.push({
      inputIndex: idx,
      fingerprintId: fp.fingerprintId,
      status: item.status,
      videoHash: item.videoHash,
      metadataHash: item.metadataHash,
      sourceHash: item.sourceHash,
      tier: item.tier,
      chainStatus: item.chainStatus,
      message: item.duplicateOf
        ? 'Duplicate file detected (identical hash to earlier batch item).'
        : item.message,
      duplicateOfIndex,
      manifest: item.manifest,
      durationMs: item.durationMs ? Math.round(item.durationMs) : null,
      failureReason: item.status === 'oversized' ? 'Size limit exceeded.' : item.failureReason,
    })
  })

  return {
    protocol: 'harpocrates-batch-checkpoint',
    version: 1,
    createdAt: new Date().toISOString(),
    policy: {
      maxFileSizeBytes: resolved.maxFileSizeBytes,
      maxTotalSizeBytes: resolved.maxTotalSizeBytes,
    },
    network: {
      apiBase: normalizeApiBase(resolved.apiBase),
      contractId: resolved.contractId,
      networkPassphrase: resolved.networkPassphrase ?? CONTRACT_NETWORK_PASSPHRASE,
    },
    inputFingerprints,
    completedEntries,
  }
}

/**
 * Validates a serialized or parsed checkpoint against the active files, batch policy,
 * and network/contract context fail-closed.
 */
export function validateBatchCheckpoint(
  checkpointInput: string | unknown,
  files: ReadonlyArray<File>,
  config: Partial<BatchConfig> = {},
): BatchVerificationCheckpoint {
  const resolved: BatchConfig = { ...DEFAULT_BATCH_CONFIG, ...config }
  let raw: unknown = checkpointInput

  if (typeof checkpointInput === 'string') {
    try {
      raw = JSON.parse(checkpointInput)
    } catch {
      throw new BatchCheckpointError('malformed_checkpoint', 'Checkpoint payload is not valid JSON.')
    }
  }

  if (!raw || typeof raw !== 'object') {
    throw new BatchCheckpointError('malformed_checkpoint', 'Checkpoint payload must be an object.')
  }

  const obj = raw as Record<string, unknown>
  if (obj.protocol !== 'harpocrates-batch-checkpoint') {
    throw new BatchCheckpointError('malformed_checkpoint', 'Invalid batch checkpoint protocol identifier.')
  }
  if (obj.version !== 1) {
    throw new BatchCheckpointError(
      'unsupported_version',
      `Unsupported batch checkpoint version: ${String(obj.version)}`,
    )
  }

  const policy = obj.policy as Record<string, unknown> | undefined
  const network = obj.network as Record<string, unknown> | undefined
  if (
    !policy ||
    typeof policy.maxFileSizeBytes !== 'number' ||
    typeof policy.maxTotalSizeBytes !== 'number' ||
    !network ||
    typeof network.apiBase !== 'string' ||
    typeof network.contractId !== 'string' ||
    typeof network.networkPassphrase !== 'string' ||
    !Array.isArray(obj.inputFingerprints) ||
    !Array.isArray(obj.completedEntries)
  ) {
    throw new BatchCheckpointError('malformed_checkpoint', 'Checkpoint is missing required binding fields.')
  }

  if (
    policy.maxFileSizeBytes !== resolved.maxFileSizeBytes ||
    policy.maxTotalSizeBytes !== resolved.maxTotalSizeBytes
  ) {
    throw new BatchCheckpointError(
      'policy_mismatch',
      'Batch size policy limits do not match the saved checkpoint.',
    )
  }

  const expectedApiBase = normalizeApiBase(resolved.apiBase)
  const expectedPassphrase = resolved.networkPassphrase ?? CONTRACT_NETWORK_PASSPHRASE
  if (
    normalizeApiBase(network.apiBase) !== expectedApiBase ||
    network.contractId !== resolved.contractId ||
    network.networkPassphrase !== expectedPassphrase
  ) {
    throw new BatchCheckpointError(
      'network_mismatch',
      'Network, API base, or contract context does not match the saved checkpoint.',
    )
  }

  if (obj.inputFingerprints.length !== files.length) {
    throw new BatchCheckpointError(
      'files_mismatch',
      `Selected file count (${files.length}) does not match checkpoint (${obj.inputFingerprints.length}).`,
    )
  }

  const verifiedFingerprints: BatchInputFingerprint[] = []
  for (let i = 0; i < files.length; i += 1) {
    const actualFp = computeBatchInputFingerprint(files[i], i)
    const savedFp = obj.inputFingerprints[i] as Record<string, unknown> | undefined
    if (
      !savedFp ||
      savedFp.inputIndex !== actualFp.inputIndex ||
      savedFp.sizeBytes !== actualFp.sizeBytes ||
      savedFp.lastModified !== actualFp.lastModified ||
      savedFp.mimeType !== actualFp.mimeType ||
      savedFp.fingerprintId !== actualFp.fingerprintId
    ) {
      throw new BatchCheckpointError(
        'files_mismatch',
        `Selected input at index ${i} does not match the saved checkpoint fingerprint.`,
      )
    }
    verifiedFingerprints.push(actualFp)
  }

  const verifiedEntries: BatchCompletedCheckpointEntry[] = []
  const seenIndices = new Set<number>()
  for (const rawEntry of obj.completedEntries) {
    if (!rawEntry || typeof rawEntry !== 'object') {
      throw new BatchCheckpointError('malformed_checkpoint', 'Invalid completed entry in checkpoint.')
    }
    const rec = rawEntry as Record<string, unknown>
    const idx = rec.inputIndex
    if (
      typeof idx !== 'number' ||
      !Number.isInteger(idx) ||
      idx < 0 ||
      idx >= verifiedFingerprints.length ||
      seenIndices.has(idx) ||
      rec.fingerprintId !== verifiedFingerprints[idx].fingerprintId ||
      typeof rec.status !== 'string' ||
      !CHECKPOINTABLE_TERMINAL_OUTCOMES.has(rec.status as BatchOutcome)
    ) {
      throw new BatchCheckpointError(
        'malformed_checkpoint',
        'Checkpoint completed entry does not match bound input fingerprint or valid terminal status.',
      )
    }
    seenIndices.add(idx)
    verifiedEntries.push({
      inputIndex: idx,
      fingerprintId: verifiedFingerprints[idx].fingerprintId,
      status: rec.status as BatchOutcome,
      videoHash: typeof rec.videoHash === 'string' ? rec.videoHash : null,
      metadataHash: typeof rec.metadataHash === 'string' ? rec.metadataHash : null,
      sourceHash: typeof rec.sourceHash === 'string' ? rec.sourceHash : null,
      tier: typeof rec.tier === 'string' ? rec.tier : null,
      chainStatus: typeof rec.chainStatus === 'string' ? rec.chainStatus : null,
      message: typeof rec.message === 'string' ? rec.message : '',
      duplicateOfIndex: typeof rec.duplicateOfIndex === 'number' ? rec.duplicateOfIndex : null,
      manifest: (rec.manifest as ProofManifest | null) ?? null,
      durationMs: typeof rec.durationMs === 'number' ? rec.durationMs : null,
      failureReason: typeof rec.failureReason === 'string' ? rec.failureReason : null,
    })
  }

  return {
    protocol: 'harpocrates-batch-checkpoint',
    version: 1,
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : new Date().toISOString(),
    policy: {
      maxFileSizeBytes: policy.maxFileSizeBytes,
      maxTotalSizeBytes: policy.maxTotalSizeBytes,
    },
    network: {
      apiBase: normalizeApiBase(network.apiBase),
      contractId: network.contractId,
      networkPassphrase: network.networkPassphrase,
    },
    inputFingerprints: verifiedFingerprints,
    completedEntries: verifiedEntries,
  }
}

export function saveBatchCheckpointToStorage(
  checkpoint: BatchVerificationCheckpoint,
  storage: CheckpointStorage<BatchVerificationCheckpoint> = new CheckpointStorage<BatchVerificationCheckpoint>(),
  workflowId: string = 'batch-verification',
): boolean {
  return storage.save(workflowId, 'latest', checkpoint)
}

export function loadBatchCheckpointFromStorage(
  storage: CheckpointStorage<BatchVerificationCheckpoint> = new CheckpointStorage<BatchVerificationCheckpoint>(),
  workflowId: string = 'batch-verification',
): BatchVerificationCheckpoint | null {
  return storage.load(workflowId, 'latest')
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
  private lastFiles: File[] = []
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

  public createCheckpoint(files?: ReadonlyArray<File>): BatchVerificationCheckpoint {
    const sourceFiles = files ?? this.lastFiles
    return createBatchCheckpoint(sourceFiles, this.items, this.config)
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
  ): Promise<{ items: BatchItemResult[]; summary: BatchSummary }> {
    if (onProgress) {
      this.onProgressCallback = onProgress
    }

    this.abortController = new AbortController()
    const signal = this.abortController.signal

    // Initialize item results
    const startTime = performance.now()
    this.lastFiles = [...files]
    this.processedHashes.clear()
    this.accumulatedTotalBytes = 0

    this.items = files.map((file, idx) => {
      const id = `item-${idx}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
      return {
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
    })

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

    return { items: [...this.items], summary }
  }

  /**
   * Resumes a batch verification run from a validated checkpoint, skipping
   * hashing and network calls for already-completed items while rejecting
   * mismatched files, policy, or network contexts fail-closed.
   */
  public async resumeBatch(
    files: File[],
    checkpointInput: string | BatchVerificationCheckpoint,
    onProgress?: (progress: BatchProgress, items: BatchItemResult[]) => void,
  ): Promise<{ items: BatchItemResult[]; summary: BatchSummary; resumedCount: number }> {
    const validated = validateBatchCheckpoint(checkpointInput, files, this.config)

    if (onProgress) {
      this.onProgressCallback = onProgress
    }

    this.abortController = new AbortController()
    const signal = this.abortController.signal
    const startTime = performance.now()
    this.lastFiles = [...files]
    this.processedHashes.clear()
    this.accumulatedTotalBytes = 0

    const completedMap = new Map(validated.completedEntries.map((entry) => [entry.inputIndex, entry]))

    this.items = files.map((file, idx) => {
      const id = `item-${idx}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
      const saved = completedMap.get(idx)
      if (saved) {
        const duplicateOfName =
          saved.duplicateOfIndex !== null && files[saved.duplicateOfIndex]
            ? files[saved.duplicateOfIndex].name
            : null
        return {
          id,
          file,
          fileName: file.name,
          fileSizeBytes: file.size,
          status: saved.status,
          videoHash: saved.videoHash,
          metadataHash: saved.metadataHash,
          sourceHash: saved.sourceHash,
          tier: saved.tier,
          chainStatus: saved.chainStatus,
          message: duplicateOfName
            ? `Duplicate file detected (identical hash to ${duplicateOfName}).`
            : saved.message,
          events: [],
          chainProof: null,
          duplicateOf: duplicateOfName,
          manifest: saved.manifest,
          durationMs: saved.durationMs,
          failureReason: saved.failureReason,
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

    // Seed processedHashes with already-verified items so remaining items still detect duplicates
    for (const item of this.items) {
      if (item.videoHash && item.status !== 'duplicate' && !this.processedHashes.has(item.videoHash)) {
        this.processedHashes.set(item.videoHash, item.id)
      }
    }

    let currentBatchBytes = 0
    for (const item of this.items) {
      if (item.status === 'oversized') {
        continue
      }
      if (item.status !== 'pending') {
        currentBatchBytes += item.fileSizeBytes
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

    return {
      items: [...this.items],
      summary,
      resumedCount: validated.completedEntries.length,
    }
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