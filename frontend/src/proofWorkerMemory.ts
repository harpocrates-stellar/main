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


export const PROOF_MEMORY_BUFFER_CLASSES = [
  'artifact',
  'witness',
  'proof',
  'publicInput',
  'secret',
] as const

export type ProofMemoryBufferClass = (typeof PROOF_MEMORY_BUFFER_CLASSES)[number]

export const PROOF_MEMORY_ACCOUNTING_LIMITS = Object.freeze({
  maxClassAllocations: 1024,
  maxTrackedOperations: 32,
})

export type ProofBufferClassCounter = {
  readonly allocatedCount: number
  readonly releasedCount: number
  readonly allocatedBytes: number
  readonly releasedBytes: number
  readonly activeBytes: number
  readonly peakBytes: number
}

export type ProofOperationMemoryStatus =
  | 'active'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'timed_out'

export type ProofOperationMemoryReport = {
  readonly operationId: string
  readonly operation: string
  readonly status: ProofOperationMemoryStatus
  /**
   * Scopes these counters strictly to tracked operation buffer classes.
   * Does not claim browser-wide heap, WASM, or OS-level memory precision.
   */
  readonly precision: 'operation-buffer-estimate'
  readonly browserWidePrecision: false
  readonly classes: Readonly<Record<ProofMemoryBufferClass, ProofBufferClassCounter>>
  readonly totals: ProofBufferClassCounter
}

export type ProofOperationMemoryOptions = {
  publicInputLimitBytes?: number
  maxClassAllocations?: number
}

type MutableBufferClassCounter = {
  allocatedCount: number
  releasedCount: number
  allocatedBytes: number
  releasedBytes: number
  activeBytes: number
  peakBytes: number
}

const VALID_BUFFER_CLASSES = new Set<string>(PROOF_MEMORY_BUFFER_CLASSES)

function isProofMemoryBufferClass(value: string): value is ProofMemoryBufferClass {
  return VALID_BUFFER_CLASSES.has(value)
}

function emptyClassCounter(): MutableBufferClassCounter {
  return {
    allocatedCount: 0,
    releasedCount: 0,
    allocatedBytes: 0,
    releasedBytes: 0,
    activeBytes: 0,
    peakBytes: 0,
  }
}

/**
 * Tracks allocated and released buffer classes for a single proof-worker
 * operation using bounded counters. Never stores witness, proof, or secret
 * payloads and explicitly marks reports as operation-level buffer estimates
 * rather than browser-wide memory measurements.
 */
export class ProofOperationMemoryAccountant {
  private readonly operationId: string
  private readonly operation: string
  private readonly publicInputLimitBytes?: number
  private readonly maxClassAllocations: number
  private status: ProofOperationMemoryStatus = 'active'
  private totalPeakBytes = 0
  private readonly classes: Record<ProofMemoryBufferClass, MutableBufferClassCounter> = {
    artifact: emptyClassCounter(),
    witness: emptyClassCounter(),
    proof: emptyClassCounter(),
    publicInput: emptyClassCounter(),
    secret: emptyClassCounter(),
  }

  constructor(
    operationId: string,
    operation: string,
    options?: ProofOperationMemoryOptions,
  ) {
    if (typeof operationId !== 'string' || operationId.trim().length === 0) {
      throw new CircuitInputError('invalid_input')
    }
    if (typeof operation !== 'string' || operation.trim().length === 0) {
      throw new CircuitInputError('invalid_input')
    }

    const maxAlloc = options?.maxClassAllocations ?? PROOF_MEMORY_ACCOUNTING_LIMITS.maxClassAllocations
    if (
      !Number.isSafeInteger(maxAlloc) ||
      maxAlloc <= 0 ||
      maxAlloc > PROOF_MEMORY_ACCOUNTING_LIMITS.maxClassAllocations
    ) {
      failMemoryLimit()
    }

    this.operationId = operationId
    this.operation = operation
    this.publicInputLimitBytes = options?.publicInputLimitBytes
    this.maxClassAllocations = maxAlloc
  }

  allocate(bufferClass: ProofMemoryBufferClass, bytes: number): void {
    if (!isProofMemoryBufferClass(bufferClass)) {
      throw new CircuitInputError('invalid_input')
    }
    if (!Number.isSafeInteger(bytes) || bytes < 0) {
      failMemoryLimit()
    }

    const counter = this.classes[bufferClass]
    if (counter.allocatedCount + 1 > this.maxClassAllocations) {
      failMemoryLimit()
    }

    const nextActive = counter.activeBytes + bytes
    if (!Number.isSafeInteger(nextActive)) {
      failMemoryLimit()
    }

    const usage: ProofWorkerMemoryUsage = {
      artifactBytes: this.classes.artifact.activeBytes,
      witnessBytes: this.classes.witness.activeBytes,
      proofBytes: this.classes.proof.activeBytes,
      publicInputBytes: this.classes.publicInput.activeBytes,
      secretBytes: this.classes.secret.activeBytes,
      ...(this.publicInputLimitBytes !== undefined
        ? { publicInputLimitBytes: this.publicInputLimitBytes }
        : {}),
    }

    switch (bufferClass) {
      case 'artifact':
        usage.artifactBytes = nextActive
        break
      case 'witness':
        usage.witnessBytes = nextActive
        break
      case 'proof':
        usage.proofBytes = nextActive
        break
      case 'publicInput':
        usage.publicInputBytes = nextActive
        break
      case 'secret':
        usage.secretBytes = nextActive
        break
    }

    assertProofWorkerMemoryBudget(usage)

    counter.allocatedCount += 1
    counter.allocatedBytes += bytes
    counter.activeBytes = nextActive
    if (counter.activeBytes > counter.peakBytes) {
      counter.peakBytes = counter.activeBytes
    }

    const currentTotalActive = this.activeTotalBytes()
    if (currentTotalActive > this.totalPeakBytes) {
      this.totalPeakBytes = currentTotalActive
    }
  }

  release(bufferClass: ProofMemoryBufferClass, bytes: number): void {
    if (!isProofMemoryBufferClass(bufferClass)) {
      throw new CircuitInputError('invalid_input')
    }
    if (!Number.isSafeInteger(bytes) || bytes < 0) {
      failMemoryLimit()
    }

    const counter = this.classes[bufferClass]
    if (counter.releasedCount + 1 > counter.allocatedCount || bytes > counter.activeBytes) {
      failMemoryLimit()
    }

    counter.releasedCount += 1
    counter.releasedBytes += bytes
    counter.activeBytes -= bytes
  }

  releaseAll(status?: Exclude<ProofOperationMemoryStatus, 'active'>): void {
    for (const bufferClass of PROOF_MEMORY_BUFFER_CLASSES) {
      const counter = this.classes[bufferClass]
      const unreleasedCount = counter.allocatedCount - counter.releasedCount
      if (unreleasedCount > 0) {
        counter.releasedCount += unreleasedCount
      }
      if (counter.activeBytes > 0) {
        counter.releasedBytes += counter.activeBytes
        counter.activeBytes = 0
      }
    }
    if (status !== undefined) {
      this.status = status
    }
  }

  setStatus(status: ProofOperationMemoryStatus): void {
    this.status = status
  }

  snapshot(): ProofOperationMemoryReport {
    let allocatedCount = 0
    let releasedCount = 0
    let allocatedBytes = 0
    let releasedBytes = 0
    let activeBytes = 0

    const frozenClasses = {} as Record<ProofMemoryBufferClass, ProofBufferClassCounter>
    for (const bufferClass of PROOF_MEMORY_BUFFER_CLASSES) {
      const counter = this.classes[bufferClass]
      allocatedCount += counter.allocatedCount
      releasedCount += counter.releasedCount
      allocatedBytes += counter.allocatedBytes
      releasedBytes += counter.releasedBytes
      activeBytes += counter.activeBytes
      frozenClasses[bufferClass] = Object.freeze({ ...counter })
    }

    return Object.freeze({
      operationId: this.operationId,
      operation: this.operation,
      status: this.status,
      precision: 'operation-buffer-estimate',
      browserWidePrecision: false,
      classes: Object.freeze(frozenClasses),
      totals: Object.freeze({
        allocatedCount,
        releasedCount,
        allocatedBytes,
        releasedBytes,
        activeBytes,
        peakBytes: this.totalPeakBytes,
      }),
    })
  }

  private activeTotalBytes(): number {
    return (
      this.classes.artifact.activeBytes +
      this.classes.witness.activeBytes +
      this.classes.proof.activeBytes +
      this.classes.publicInput.activeBytes +
      this.classes.secret.activeBytes
    )
  }
}

export function createProofOperationMemoryAccountant(
  operationId: string,
  operation: string,
  options?: ProofOperationMemoryOptions,
): ProofOperationMemoryAccountant {
  return new ProofOperationMemoryAccountant(operationId, operation, options)
}
