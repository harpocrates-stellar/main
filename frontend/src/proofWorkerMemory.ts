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

export const PROOF_BUFFER_CLASSES = Object.freeze([
  'artifact',
  'witness',
  'proof',
  'public_input',
  'transfer',
] as const)

export type ProofBufferClass = (typeof PROOF_BUFFER_CLASSES)[number]

export type ProofBufferClassCounters = {
  readonly allocatedBytes: number
  readonly releasedBytes: number
  readonly activeBytes: number
  readonly peakBytes: number
  readonly allocationCount: number
  readonly releaseCount: number
}

export const PROOF_MEMORY_PRECISION_NOTE =
  'Counts explicit proof-worker buffer allocations and releases only; does not measure total browser or WASM linear-memory heap usage.' as const

export type ProofOperationMemoryReport = {
  readonly operationId: string
  readonly status: 'active' | 'completed'
  readonly measurementScope: 'tracked-operation-buffers'
  readonly browserHeapPrecise: false
  readonly precisionNote: typeof PROOF_MEMORY_PRECISION_NOTE
  readonly budgetLimitBytes: number
  readonly totals: ProofBufferClassCounters
  readonly classes: Readonly<Record<ProofBufferClass, ProofBufferClassCounters>>
}

export type ProofOperationMemoryTrackerOptions = {
  budgetLimitBytes?: number
  classLimits?: Partial<Record<ProofBufferClass, number>>
  maxTrackedOperations?: number
  maxAllocationEventsPerOperation?: number
  counterCeilingBytes?: number
}

type MutableCounters = {
  allocatedBytes: number
  releasedBytes: number
  activeBytes: number
  peakBytes: number
  allocationCount: number
  releaseCount: number
}

type MutableOperationEntry = {
  operationId: string
  status: 'active' | 'completed'
  budgetLimitBytes: number
  totals: MutableCounters
  classes: Record<ProofBufferClass, MutableCounters>
}

const DEFAULT_MAX_TRACKED_OPERATIONS = 64
const DEFAULT_MAX_ALLOCATION_EVENTS = 4_096
const SAFE_OPERATION_ID = /^[A-Za-z0-9._:-]{1,128}$/

const DEFAULT_CLASS_LIMITS: Readonly<Record<ProofBufferClass, number>> = Object.freeze({
  artifact: PROOF_WORKER_MEMORY_LIMITS.maxArtifactBytes,
  witness: PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes,
  proof: PROOF_WORKER_MEMORY_LIMITS.maxProofBytes,
  public_input: PROOF_WORKER_MEMORY_LIMITS.maxPublicInputBytes,
  transfer: PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes,
})

function emptyCounters(): MutableCounters {
  return {
    allocatedBytes: 0,
    releasedBytes: 0,
    activeBytes: 0,
    peakBytes: 0,
    allocationCount: 0,
    releaseCount: 0,
  }
}

function freezeCounters(counters: MutableCounters): ProofBufferClassCounters {
  return Object.freeze({
    allocatedBytes: counters.allocatedBytes,
    releasedBytes: counters.releasedBytes,
    activeBytes: counters.activeBytes,
    peakBytes: counters.peakBytes,
    allocationCount: counters.allocationCount,
    releaseCount: counters.releaseCount,
  })
}

function assertOperationId(operationId: string): string {
  if (typeof operationId !== 'string' || !SAFE_OPERATION_ID.test(operationId)) {
    throw new CircuitInputError('invalid_input')
  }
  return operationId
}

function isProofBufferClass(value: string): value is ProofBufferClass {
  return (PROOF_BUFFER_CLASSES as readonly string[]).includes(value)
}

function assertPositiveCap(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new CircuitInputError('invalid_input')
  }
  return value
}

/**
 * Per-operation buffer memory accountant with bounded counters.
 *
 * Accepts byte counts only (never raw witness/secret buffers) and explicitly
 * marks reports as tracked-buffer estimates rather than browser heap totals.
 */
export class ProofOperationMemoryTracker {
  private readonly operations: Map<string, MutableOperationEntry> = new Map()
  private readonly defaultBudgetLimitBytes: number
  private readonly classLimits: Readonly<Record<ProofBufferClass, number>>
  private readonly maxTrackedOperations: number
  private readonly maxAllocationEvents: number
  private readonly counterCeilingBytes: number

  constructor(options: ProofOperationMemoryTrackerOptions = {}) {
    this.defaultBudgetLimitBytes = assertPositiveCap(
      options.budgetLimitBytes,
      PROOF_WORKER_MEMORY_LIMITS.maxRuntimeBytes,
    )
    this.maxTrackedOperations = assertPositiveCap(
      options.maxTrackedOperations,
      DEFAULT_MAX_TRACKED_OPERATIONS,
    )
    this.maxAllocationEvents = assertPositiveCap(
      options.maxAllocationEventsPerOperation,
      DEFAULT_MAX_ALLOCATION_EVENTS,
    )
    this.counterCeilingBytes = assertPositiveCap(
      options.counterCeilingBytes,
      Math.min(Number.MAX_SAFE_INTEGER, this.defaultBudgetLimitBytes * 8),
    )

    const resolvedLimits: Record<ProofBufferClass, number> = {
      artifact: DEFAULT_CLASS_LIMITS.artifact,
      witness: DEFAULT_CLASS_LIMITS.witness,
      proof: DEFAULT_CLASS_LIMITS.proof,
      public_input: DEFAULT_CLASS_LIMITS.public_input,
      transfer: DEFAULT_CLASS_LIMITS.transfer,
    }
    if (options.classLimits) {
      for (const bufferClass of PROOF_BUFFER_CLASSES) {
        const custom = options.classLimits[bufferClass]
        if (custom !== undefined) {
          resolvedLimits[bufferClass] = assertPositiveCap(custom, DEFAULT_CLASS_LIMITS[bufferClass])
        }
      }
    }
    this.classLimits = Object.freeze(resolvedLimits)
  }

  startOperation(operationId: string, budgetLimitBytes?: number): ProofOperationMemoryReport {
    const id = assertOperationId(operationId)
    if (this.operations.has(id)) {
      throw new CircuitInputError('invalid_input')
    }
    const resolvedBudget = assertPositiveCap(budgetLimitBytes, this.defaultBudgetLimitBytes)
    if (resolvedBudget > this.counterCeilingBytes) {
      failMemoryLimit()
    }
    this.evictIfNeeded()
    const entry: MutableOperationEntry = {
      operationId: id,
      status: 'active',
      budgetLimitBytes: resolvedBudget,
      totals: emptyCounters(),
      classes: {
        artifact: emptyCounters(),
        witness: emptyCounters(),
        proof: emptyCounters(),
        public_input: emptyCounters(),
        transfer: emptyCounters(),
      },
    }
    this.operations.set(id, entry)
    return this.snapshot(entry)
  }

  recordAllocation(
    operationId: string,
    bufferClass: ProofBufferClass,
    byteLength: number,
  ): ProofOperationMemoryReport {
    const id = assertOperationId(operationId)
    if (!isProofBufferClass(bufferClass)) {
      throw new CircuitInputError('invalid_input')
    }
    if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
      throw new CircuitInputError('invalid_input')
    }

    let entry = this.operations.get(id)
    if (!entry) {
      this.startOperation(id)
      entry = this.operations.get(id)!
    }
    if (entry.status !== 'active') {
      throw new CircuitInputError('invalid_input')
    }

    const classCounters = entry.classes[bufferClass]
    const nextClassActive = classCounters.activeBytes + byteLength
    const nextTotalActive = entry.totals.activeBytes + byteLength
    const nextClassAllocated = classCounters.allocatedBytes + byteLength
    const nextTotalAllocated = entry.totals.allocatedBytes + byteLength
    const nextTotalEvents = entry.totals.allocationCount + 1

    if (
      nextClassActive > this.classLimits[bufferClass] ||
      nextTotalActive > entry.budgetLimitBytes ||
      nextClassAllocated > this.counterCeilingBytes ||
      nextTotalAllocated > this.counterCeilingBytes ||
      nextTotalEvents > this.maxAllocationEvents
    ) {
      failMemoryLimit()
    }

    classCounters.allocatedBytes = nextClassAllocated
    classCounters.activeBytes = nextClassActive
    if (nextClassActive > classCounters.peakBytes) {
      classCounters.peakBytes = nextClassActive
    }
    classCounters.allocationCount += 1

    entry.totals.allocatedBytes = nextTotalAllocated
    entry.totals.activeBytes = nextTotalActive
    if (nextTotalActive > entry.totals.peakBytes) {
      entry.totals.peakBytes = nextTotalActive
    }
    entry.totals.allocationCount = nextTotalEvents

    return this.snapshot(entry)
  }

  recordRelease(
    operationId: string,
    bufferClass: ProofBufferClass,
    byteLength: number,
  ): ProofOperationMemoryReport {
    const id = assertOperationId(operationId)
    if (!isProofBufferClass(bufferClass)) {
      throw new CircuitInputError('invalid_input')
    }
    if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
      throw new CircuitInputError('invalid_input')
    }

    const entry = this.operations.get(id)
    if (!entry || entry.status !== 'active') {
      throw new CircuitInputError('invalid_input')
    }

    const classCounters = entry.classes[bufferClass]
    if (byteLength > classCounters.activeBytes || byteLength > entry.totals.activeBytes) {
      throw new CircuitInputError('invalid_input')
    }

    classCounters.activeBytes -= byteLength
    classCounters.releasedBytes += byteLength
    classCounters.releaseCount += 1

    entry.totals.activeBytes -= byteLength
    entry.totals.releasedBytes += byteLength
    entry.totals.releaseCount += 1

    return this.snapshot(entry)
  }

  completeOperation(operationId: string): ProofOperationMemoryReport {
    const id = assertOperationId(operationId)
    const entry = this.operations.get(id)
    if (!entry) {
      throw new CircuitInputError('invalid_input')
    }
    entry.status = 'completed'
    return this.snapshot(entry)
  }

  getReport(operationId: string): ProofOperationMemoryReport | null {
    const id = assertOperationId(operationId)
    const entry = this.operations.get(id)
    return entry ? this.snapshot(entry) : null
  }

  clear(): void {
    this.operations.clear()
  }

  private evictIfNeeded(): void {
    if (this.operations.size < this.maxTrackedOperations) return
    for (const [key, item] of this.operations.entries()) {
      if (item.status === 'completed') {
        this.operations.delete(key)
        if (this.operations.size < this.maxTrackedOperations) return
      }
    }
    failMemoryLimit()
  }

  private snapshot(entry: MutableOperationEntry): ProofOperationMemoryReport {
    return Object.freeze({
      operationId: entry.operationId,
      status: entry.status,
      measurementScope: 'tracked-operation-buffers' as const,
      browserHeapPrecise: false as const,
      precisionNote: PROOF_MEMORY_PRECISION_NOTE,
      budgetLimitBytes: entry.budgetLimitBytes,
      totals: freezeCounters(entry.totals),
      classes: Object.freeze({
        artifact: freezeCounters(entry.classes.artifact),
        witness: freezeCounters(entry.classes.witness),
        proof: freezeCounters(entry.classes.proof),
        public_input: freezeCounters(entry.classes.public_input),
        transfer: freezeCounters(entry.classes.transfer),
      }),
    })
  }
}
