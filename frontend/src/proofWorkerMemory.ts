import benchLock from '../../zk/bench/bench.lock.json'
import browserArtifactManifest from '../../zk/browser.artifacts.manifest.json'
import { CircuitInputError } from './circuitInputSchema'

type BrowserArtifactEntry = {
  path: string
  raw_bytes?: number
}

type JsonResponseLike = {
  headers?: Pick<Headers, 'get'>
  body?: ReadableStream<Uint8Array> | null
  arrayBuffer?: () => Promise<ArrayBuffer>
  text?: () => Promise<string>
  json?: () => Promise<unknown>
}

export type ProofWorkerMemoryUsage = {
  artifactBytes?: number | null
  witnessBytes?: number | null
  proofBytes?: number | null
  publicInputBytes?: number | null
  publicInputLimitBytes?: number | null
  secretBytes?: number | null
}

const manifestArtifacts = (browserArtifactManifest.artifacts ?? []) as BrowserArtifactEntry[]
const publishedArtifactBytes = manifestArtifacts.reduce(
  (total, entry) => total + safeBytes(entry.raw_bytes),
  0,
)

export const PROOF_WORKER_MEMORY_LIMITS = Object.freeze({
  maxArtifactBytes: Number(benchLock.limits.max_witness_bytes),
  maxWitnessBytes: Number(benchLock.limits.max_witness_bytes),
  maxProofBytes: Number(benchLock.limits.max_proof_bytes),
  maxPublicInputBytes: Number(benchLock.limits.max_public_input_bytes),
  maxRuntimeBytes:
    Number(benchLock.limits.max_witness_bytes) +
    Number(benchLock.limits.max_proof_bytes) +
    Number(benchLock.limits.max_public_input_bytes) +
    publishedArtifactBytes,
})

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

function safeBytes(value: unknown): number {
  return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : 0
}

function failMemoryLimit(): never {
  throw new CircuitInputError('proof_worker_memory_exceeded')
}

function assertByteCount(value: number | null | undefined, limit: number): number {
  if (value === null || value === undefined) return 0
  if (!Number.isSafeInteger(value) || value < 0 || value > limit) failMemoryLimit()
  return value
}

export function browserArtifactByteLimit(path: string): number {
  const normalized = path.startsWith('/noir/')
    ? `frontend/public/noir/${path.slice('/noir/'.length)}`
    : path.replace(/\\/g, '/')
  const entry = manifestArtifacts.find((artifact) => artifact.path === normalized)
  return safeBytes(entry?.raw_bytes) || PROOF_WORKER_MEMORY_LIMITS.maxArtifactBytes
}

export function assertProofWorkerMemoryBudget(usage: ProofWorkerMemoryUsage): void {
  const artifactBytes = assertByteCount(
    usage.artifactBytes,
    PROOF_WORKER_MEMORY_LIMITS.maxArtifactBytes,
  )
  const witnessBytes = assertByteCount(
    usage.witnessBytes,
    PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes,
  )
  const proofBytes = assertByteCount(
    usage.proofBytes,
    PROOF_WORKER_MEMORY_LIMITS.maxProofBytes,
  )
  const publicInputLimitBytes = assertByteCount(
    usage.publicInputLimitBytes ?? PROOF_WORKER_MEMORY_LIMITS.maxPublicInputBytes,
    PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes,
  )
  const publicInputBytes = assertByteCount(
    usage.publicInputBytes,
    publicInputLimitBytes,
  )
  const secretBytes = assertByteCount(
    usage.secretBytes,
    PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes,
  )
  const runtimeLimit =
    PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes +
    PROOF_WORKER_MEMORY_LIMITS.maxProofBytes +
    publicInputLimitBytes +
    Math.max(artifactBytes, publishedArtifactBytes)
  if (artifactBytes + witnessBytes + proofBytes + publicInputBytes + secretBytes > runtimeLimit) {
    failMemoryLimit()
  }
}

export function byteLengthOfProofWorkerValue(value: unknown): number {
  return boundedByteLength(value, PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes + 1, new WeakSet()) ??
    PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes + 1
}

function boundedByteLength(value: unknown, limit: number, seen: WeakSet<object>): number | null {
  if (value === null || value === undefined) return 0
  if (typeof value === 'string') return textEncoder.encode(value).byteLength
  if (typeof value === 'number') return Number.isFinite(value) ? 8 : null
  if (typeof value === 'bigint') return 32
  if (typeof value === 'boolean') return 1
  if (value instanceof ArrayBuffer) return value.byteLength
  if (ArrayBuffer.isView(value)) return value.byteLength
  if (typeof value !== 'object') return null
  if (seen.has(value)) return 0
  seen.add(value)

  let total = 0
  const add = (next: number | null): boolean => {
    if (next === null) return false
    total += next
    return total <= limit
  }

  if (value instanceof Map) {
    for (const [key, item] of value.entries()) {
      if (!add(boundedByteLength(key, limit - total, seen))) return limit + 1
      if (!add(boundedByteLength(item, limit - total, seen))) return limit + 1
    }
    return total
  }
  if (value instanceof Set) {
    for (const item of value.values()) {
      if (!add(boundedByteLength(item, limit - total, seen))) return limit + 1
    }
    return total
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      if (!add(boundedByteLength(item, limit - total, seen))) return limit + 1
    }
    return total
  }

  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (!add(textEncoder.encode(key).byteLength)) return limit + 1
    if (!add(boundedByteLength(item, limit - total, seen))) return limit + 1
  }
  return total
}

export async function readBoundedCircuitArtifact<T>(
  response: JsonResponseLike,
  path: string,
  limitBytes = browserArtifactByteLimit(path),
): Promise<{ value: T; rawBytes: number }> {
  const announced = parseContentLength(response.headers?.get?.('content-length'))
  if (announced !== null && announced > limitBytes) failMemoryLimit()

  if (response.body && typeof response.body.getReader === 'function') {
    return parseBoundedJson(await readStream(response.body, limitBytes)) as { value: T; rawBytes: number }
  }
  if (typeof response.arrayBuffer === 'function') {
    const data = await response.arrayBuffer()
    if (data.byteLength > limitBytes) failMemoryLimit()
    return parseBoundedJson(new Uint8Array(data)) as { value: T; rawBytes: number }
  }
  if (typeof response.text === 'function') {
    const text = await response.text()
    const rawBytes = textEncoder.encode(text).byteLength
    if (rawBytes > limitBytes) failMemoryLimit()
    return parseTextJson(text, rawBytes) as { value: T; rawBytes: number }
  }
  if (typeof response.json === 'function') {
    const value = await response.json()
    const rawBytes = textEncoder.encode(JSON.stringify(value)).byteLength
    if (rawBytes > limitBytes) failMemoryLimit()
    return { value: value as T, rawBytes }
  }
  throw new CircuitInputError('circuit_load_failed')
}

function parseContentLength(value: string | null | undefined): number | null {
  if (value === null || value === undefined || !/^[0-9]+$/.test(value)) return null
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) ? parsed : null
}

async function readStream(
  stream: ReadableStream<Uint8Array>,
  limitBytes: number,
): Promise<Uint8Array> {
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > limitBytes) failMemoryLimit()
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

function parseBoundedJson(data: Uint8Array): { value: unknown; rawBytes: number } {
  return parseTextJson(textDecoder.decode(data), data.byteLength)
}

function parseTextJson(text: string, rawBytes: number): { value: unknown; rawBytes: number } {
  try {
    return { value: JSON.parse(text), rawBytes }
  } catch {
    throw new CircuitInputError('circuit_load_failed')
  }
}

export type WorkerOwnershipErrorCode =
  | 'WORKER_OWNERSHIP_CONFLICT'
  | 'UNOWNED_WORKER_OPERATION'
  | 'STALE_WORKER_GENERATION'

export class ProofWorkerOwnershipError extends Error {
  readonly code: WorkerOwnershipErrorCode

  constructor(code: WorkerOwnershipErrorCode, message: string) {
    super(message)
    this.name = 'ProofWorkerOwnershipError'
    this.code = code
  }
}

export type WorkerOwnershipLease = {
  readonly leaseId: string
  readonly ownerId: string
  readonly acquiredAtEpoch: number
}

export type OwnedOperationStamp = {
  readonly ownerId: string
  readonly leaseId: string
  readonly operationId: string
  readonly workerEpoch: number
  readonly operationGeneration: number
}

export type WorkerReplacementReason =
  | 'cancel_restart'
  | 'timeout_restart'
  | 'crash_restart'
  | 'manual_restart'
  | 'destroy'

export type StaleWorkerMessageKind = 'progress' | 'proof' | 'error' | 'cancelled'

export type StaleMessageRejectionReason =
  | 'no_active_operation'
  | 'owner_mismatch'
  | 'lease_mismatch'
  | 'stale_worker_epoch'
  | 'stale_operation_generation'
  | 'operation_id_mismatch'
  | 'malformed_stamp'

export type WorkerEnvelopeStampInput = {
  readonly kind: StaleWorkerMessageKind
  readonly operationId?: unknown
  readonly workerEpoch?: unknown
  readonly operationGeneration?: unknown
  readonly ownerId?: unknown
  readonly leaseId?: unknown
}

export type WorkerEnvelopeOwnershipVerdict =
  | { readonly accepted: true; readonly stamp: OwnedOperationStamp }
  | {
      readonly accepted: false
      readonly reason: StaleMessageRejectionReason
      readonly kind: StaleWorkerMessageKind
    }

export type WorkerOwnershipSnapshot = {
  readonly activeLease: WorkerOwnershipLease | null
  readonly activeOperation: OwnedOperationStamp | null
  readonly workerEpoch: number
  readonly operationGeneration: number
  readonly rejectedStaleProgressCount: number
  readonly rejectedStaleProofCount: number
  readonly rejectedStaleOtherCount: number
}

function assertNonEmptyIdentifier(value: unknown): string {
  if (typeof value !== 'string') {
    throw new CircuitInputError('invalid_input')
  }
  const trimmed = value.trim()
  if (trimmed.length === 0 || trimmed.length > 128) {
    throw new CircuitInputError('invalid_input')
  }
  return trimmed
}

/**
 * Single-ownership and monotonic generation coordinator for browser proving
 * workers. Tracks `workerEpoch` and `operationGeneration` across worker
 * replacements and rejects stale progress/proof messages after cancellation or
 * restart without inspecting secret witness material.
 */
export class ProofWorkerOwnershipProtocol {
  private workerEpoch = 1
  private operationGeneration = 0
  private leaseSequence = 0
  private activeLease: WorkerOwnershipLease | null = null
  private ephemeralLease = false
  private activeOperation: OwnedOperationStamp | null = null
  private rejectedStaleProgressCount = 0
  private rejectedStaleProofCount = 0
  private rejectedStaleOtherCount = 0

  claimOwnership(ownerId: string): WorkerOwnershipLease {
    const normalizedOwner = assertNonEmptyIdentifier(ownerId)
    if (this.activeLease !== null) {
      if (this.activeLease.ownerId !== normalizedOwner) {
        throw new ProofWorkerOwnershipError(
          'WORKER_OWNERSHIP_CONFLICT',
          'Browser proof worker is already owned by another caller.',
        )
      }
      if (this.ephemeralLease) {
        this.ephemeralLease = false
      }
      return this.activeLease
    }

    this.leaseSequence += 1
    const lease: WorkerOwnershipLease = Object.freeze({
      leaseId: `lease_${this.leaseSequence}`,
      ownerId: normalizedOwner,
      acquiredAtEpoch: this.workerEpoch,
    })
    this.activeLease = lease
    this.ephemeralLease = false
    return lease
  }

  releaseOwnership(ownerId: string, leaseId?: string): void {
    const normalizedOwner = assertNonEmptyIdentifier(ownerId)
    if (this.activeLease === null) return
    if (
      this.activeLease.ownerId !== normalizedOwner ||
      (leaseId !== undefined && this.activeLease.leaseId !== leaseId)
    ) {
      throw new ProofWorkerOwnershipError(
        'WORKER_OWNERSHIP_CONFLICT',
        'Cannot release browser proof worker owned by another caller.',
      )
    }
    if (this.activeOperation !== null) {
      this.operationGeneration += 1
      this.activeOperation = null
    }
    this.activeLease = null
    this.ephemeralLease = false
  }

  startOperation(params: { operationId: string; ownerId?: string }): OwnedOperationStamp {
    const operationId = assertNonEmptyIdentifier(params.operationId)
    if (this.activeOperation !== null) {
      throw new ProofWorkerOwnershipError(
        'WORKER_OWNERSHIP_CONFLICT',
        'Browser proof worker already has an active owned operation.',
      )
    }

    if (this.activeLease !== null) {
      if (params.ownerId === undefined) {
        throw new ProofWorkerOwnershipError(
          'UNOWNED_WORKER_OPERATION',
          'Browser proof worker requires the active owner identifier.',
        )
      }
      const callerOwner = assertNonEmptyIdentifier(params.ownerId)
      if (callerOwner !== this.activeLease.ownerId) {
        throw new ProofWorkerOwnershipError(
          'WORKER_OWNERSHIP_CONFLICT',
          'Browser proof worker is already owned by another caller.',
        )
      }
    } else {
      const resolvedOwner =
        params.ownerId !== undefined
          ? assertNonEmptyIdentifier(params.ownerId)
          : 'implicit-default-owner'
      this.leaseSequence += 1
      this.activeLease = Object.freeze({
        leaseId: `lease_${this.leaseSequence}`,
        ownerId: resolvedOwner,
        acquiredAtEpoch: this.workerEpoch,
      })
      this.ephemeralLease = true
    }

    this.operationGeneration += 1
    const stamp: OwnedOperationStamp = Object.freeze({
      ownerId: this.activeLease.ownerId,
      leaseId: this.activeLease.leaseId,
      operationId,
      workerEpoch: this.workerEpoch,
      operationGeneration: this.operationGeneration,
    })
    this.activeOperation = stamp
    return stamp
  }

  completeOperation(operationId: string): boolean {
    if (this.activeOperation === null || this.activeOperation.operationId !== operationId) {
      return false
    }
    this.activeOperation = null
    if (this.ephemeralLease) {
      this.activeLease = null
      this.ephemeralLease = false
    }
    return true
  }

  invalidateForCancel(operationId?: string): { workerEpoch: number; operationGeneration: number } {
    if (
      operationId !== undefined &&
      this.activeOperation !== null &&
      this.activeOperation.operationId !== operationId
    ) {
      return {
        workerEpoch: this.workerEpoch,
        operationGeneration: this.operationGeneration,
      }
    }
    this.operationGeneration += 1
    this.activeOperation = null
    if (this.ephemeralLease) {
      this.activeLease = null
      this.ephemeralLease = false
    }
    return {
      workerEpoch: this.workerEpoch,
      operationGeneration: this.operationGeneration,
    }
  }

  recordWorkerReplacement(
    reason: WorkerReplacementReason = 'manual_restart',
  ): { workerEpoch: number; operationGeneration: number } {
    this.workerEpoch += 1
    this.operationGeneration += 1
    this.activeOperation = null
    if (this.ephemeralLease || reason === 'destroy') {
      this.activeLease = null
      this.ephemeralLease = false
    }
    return {
      workerEpoch: this.workerEpoch,
      operationGeneration: this.operationGeneration,
    }
  }

  private recordStaleRejection(
    kind: StaleWorkerMessageKind,
    reason: StaleMessageRejectionReason,
  ): WorkerEnvelopeOwnershipVerdict {
    if (kind === 'progress') {
      this.rejectedStaleProgressCount += 1
    } else if (kind === 'proof') {
      this.rejectedStaleProofCount += 1
    } else {
      this.rejectedStaleOtherCount += 1
    }
    return Object.freeze({
      accepted: false as const,
      reason,
      kind,
    })
  }

  validateIncomingMessage(envelope: WorkerEnvelopeStampInput): WorkerEnvelopeOwnershipVerdict {
    const validOperationId =
      typeof envelope.operationId === 'string' && envelope.operationId.trim().length > 0
    const validWorkerEpoch =
      typeof envelope.workerEpoch === 'number' &&
      Number.isSafeInteger(envelope.workerEpoch) &&
      envelope.workerEpoch >= 1
    const validGeneration =
      typeof envelope.operationGeneration === 'number' &&
      Number.isSafeInteger(envelope.operationGeneration) &&
      envelope.operationGeneration >= 1

    if (!validOperationId || !validWorkerEpoch || !validGeneration) {
      return this.recordStaleRejection(envelope.kind, 'malformed_stamp')
    }
    if (this.activeOperation === null) {
      return this.recordStaleRejection(envelope.kind, 'no_active_operation')
    }
    if (envelope.workerEpoch !== this.activeOperation.workerEpoch) {
      return this.recordStaleRejection(envelope.kind, 'stale_worker_epoch')
    }
    if (envelope.operationGeneration !== this.activeOperation.operationGeneration) {
      return this.recordStaleRejection(envelope.kind, 'stale_operation_generation')
    }
    if (envelope.operationId !== this.activeOperation.operationId) {
      return this.recordStaleRejection(envelope.kind, 'operation_id_mismatch')
    }
    if (envelope.ownerId !== undefined && envelope.ownerId !== this.activeOperation.ownerId) {
      return this.recordStaleRejection(envelope.kind, 'owner_mismatch')
    }
    if (envelope.leaseId !== undefined && envelope.leaseId !== this.activeOperation.leaseId) {
      return this.recordStaleRejection(envelope.kind, 'lease_mismatch')
    }

    return Object.freeze({
      accepted: true as const,
      stamp: this.activeOperation,
    })
  }

  getSnapshot(): WorkerOwnershipSnapshot {
    return Object.freeze({
      activeLease: this.activeLease,
      activeOperation: this.activeOperation,
      workerEpoch: this.workerEpoch,
      operationGeneration: this.operationGeneration,
      rejectedStaleProgressCount: this.rejectedStaleProgressCount,
      rejectedStaleProofCount: this.rejectedStaleProofCount,
      rejectedStaleOtherCount: this.rejectedStaleOtherCount,
    })
  }
}
