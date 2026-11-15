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

export type SessionBufferKind = 'witness' | 'proof' | 'transfer'

export type SessionBufferCleanupSummary = {
  readonly operationId: string
  readonly clearedSlots: number
  readonly zeroedBytes: number
  readonly detachedSlotsSkipped: number
  readonly referencesReleased: true
  readonly reusable: true
}

export class WorkerSessionReuseError extends Error {
  readonly code = 'UNCLEARED_SESSION_BUFFERS' as const

  constructor(message = 'Cannot reuse proof worker session before completed buffers are cleared.') {
    super(message)
    this.name = 'WorkerSessionReuseError'
  }
}

type TrackedBufferSlot = {
  slotId: string
  kind: SessionBufferKind
  target: ArrayBuffer | ArrayBufferView | null
  released: boolean
}

const VALID_SESSION_OP_ID = /^[A-Za-z0-9._:-]{1,128}$/

function zeroBufferTarget(target: ArrayBuffer | ArrayBufferView): {
  zeroedBytes: number
  detached: boolean
} {
  if (target instanceof ArrayBuffer) {
    if (target.byteLength === 0) {
      return { zeroedBytes: 0, detached: true }
    }
    const view = new Uint8Array(target)
    view.fill(0)
    return { zeroedBytes: view.byteLength, detached: false }
  }
  const backing = target.buffer
  if (backing.byteLength === 0 || target.byteLength === 0) {
    return { zeroedBytes: 0, detached: backing.byteLength === 0 }
  }
  const view = new Uint8Array(backing, target.byteOffset, target.byteLength)
  view.fill(0)
  return { zeroedBytes: view.byteLength, detached: false }
}

/**
 * Guards reusable worker sessions by tracking witness, transfer, and proof
 * buffers for the active operation, zeroing non-detached memory, dropping
 * object references after transfer/export, and blocking session reuse until
 * cleanup completes.
 */
export class WorkerSessionBufferGuard {
  private activeOperationId: string | null = null
  private slots: Map<string, TrackedBufferSlot> = new Map()
  private nextSlotSeq = 1
  private cumulativeZeroedBytes = 0
  private cumulativeDetachedSkipped = 0

  beginOperation(operationId: string): void {
    if (typeof operationId !== 'string' || !VALID_SESSION_OP_ID.test(operationId)) {
      throw new CircuitInputError('invalid_input')
    }
    if (this.activeOperationId !== null || this.slots.size > 0) {
      throw new WorkerSessionReuseError()
    }
    this.activeOperationId = operationId
    this.cumulativeZeroedBytes = 0
    this.cumulativeDetachedSkipped = 0
  }

  registerBuffer(
    operationId: string,
    kind: SessionBufferKind,
    buffer: ArrayBuffer | ArrayBufferView,
  ): string {
    if (this.activeOperationId === null) {
      this.beginOperation(operationId)
    } else if (this.activeOperationId !== operationId) {
      throw new WorkerSessionReuseError()
    }
    if (kind !== 'witness' && kind !== 'proof' && kind !== 'transfer') {
      throw new CircuitInputError('invalid_input')
    }
    if (!(buffer instanceof ArrayBuffer) && !ArrayBuffer.isView(buffer)) {
      throw new CircuitInputError('invalid_input')
    }

    const slotId = `slot_${this.nextSlotSeq++}`
    this.slots.set(slotId, {
      slotId,
      kind,
      target: buffer,
      released: false,
    })
    return slotId
  }

  releaseAfterTransferOrExport(
    operationId: string,
    slotId: string,
  ): { zeroedBytes: number; detached: boolean; released: true } {
    if (this.activeOperationId !== operationId) {
      throw new CircuitInputError('invalid_input')
    }
    const slot = this.slots.get(slotId)
    if (!slot) {
      throw new CircuitInputError('invalid_input')
    }
    if (slot.released || slot.target === null) {
      this.slots.delete(slotId)
      return Object.freeze({ zeroedBytes: 0, detached: false, released: true as const })
    }

    const scrubbed = zeroBufferTarget(slot.target)
    slot.target = null
    slot.released = true
    this.slots.delete(slotId)
    this.cumulativeZeroedBytes += scrubbed.zeroedBytes
    if (scrubbed.detached) {
      this.cumulativeDetachedSkipped += 1
    }

    return Object.freeze({
      zeroedBytes: scrubbed.zeroedBytes,
      detached: scrubbed.detached,
      released: true as const,
    })
  }

  clearCompletedOperation(operationId: string): SessionBufferCleanupSummary {
    if (this.activeOperationId !== operationId) {
      throw new CircuitInputError('invalid_input')
    }

    let clearedSlots = 0
    for (const [slotId, slot] of [...this.slots.entries()]) {
      if (slot.target !== null && !slot.released) {
        const scrubbed = zeroBufferTarget(slot.target)
        this.cumulativeZeroedBytes += scrubbed.zeroedBytes
        if (scrubbed.detached) {
          this.cumulativeDetachedSkipped += 1
        }
      }
      slot.target = null
      slot.released = true
      this.slots.delete(slotId)
      clearedSlots += 1
    }

    const zeroedBytes = this.cumulativeZeroedBytes
    const detachedSlotsSkipped = this.cumulativeDetachedSkipped
    this.activeOperationId = null
    this.cumulativeZeroedBytes = 0
    this.cumulativeDetachedSkipped = 0

    return Object.freeze({
      operationId,
      clearedSlots,
      zeroedBytes,
      detachedSlotsSkipped,
      referencesReleased: true as const,
      reusable: true as const,
    })
  }

  isReadyForReuse(): boolean {
    return this.activeOperationId === null && this.slots.size === 0
  }

  assertReadyForReuse(): void {
    if (!this.isReadyForReuse()) {
      throw new WorkerSessionReuseError()
    }
  }

  forceClearAll(): void {
    for (const slot of this.slots.values()) {
      if (slot.target !== null && !slot.released) {
        zeroBufferTarget(slot.target)
      }
      slot.target = null
      slot.released = true
    }
    this.slots.clear()
    this.activeOperationId = null
    this.cumulativeZeroedBytes = 0
    this.cumulativeDetachedSkipped = 0
  }
}
