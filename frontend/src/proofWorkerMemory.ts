import benchLock from '../../zk/bench/bench.lock.json'
import browserArtifactManifest from '../../zk/browser.artifacts.manifest.json'
import { CircuitInputError } from './circuitInputSchema'

type BrowserArtifactEntry = {
  path: string
  raw_bytes?: number
  normalized_bytes?: number
  role?: string
  kind?: string
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

export type ProofWorkerExecutionMode =
  | 'multithreaded'
  | 'single-threaded-fallback'
  | 'rejected'

export type ProofWorkerAdmissionReasonCode =
  | 'admitted'
  | 'fallback_single_thread_not_isolated'
  | 'fallback_single_thread_low_concurrency'
  | 'fallback_single_thread_memory_constrained'
  | 'memory_budget_exceeded'
  | 'concurrency_limit_reached'

export type ProofWorkerResourceAdmissionInput = {
  usage?: ProofWorkerMemoryUsage
  /** Optional CSP / manager memory cap in megabytes. */
  maxMemoryMB?: number
  /** Optional browser device-memory hint in gigabytes (e.g. navigator.deviceMemory). */
  deviceMemoryGB?: number | null
  /** Whether SharedArrayBuffer multithreading is permitted (crossOriginIsolated). */
  crossOriginIsolated?: boolean
  /** Reported logical CPU count (e.g. navigator.hardwareConcurrency). */
  hardwareConcurrency?: number | null
  /** Number of currently active proving/verification tasks. */
  activeTasks?: number
  /** Maximum concurrent tasks permitted (defaults to 1). */
  maxConcurrentTasks?: number
}

export type ProofWorkerResourceAdmissionDecision = {
  readonly admitted: boolean
  readonly mode: ProofWorkerExecutionMode
  readonly fallbackApplied: boolean
  readonly reasonCodes: readonly ProofWorkerAdmissionReasonCode[]
  /** Privacy-safe human-readable summary of memory, thread, and concurrency restrictions. */
  readonly summary: string
  readonly memory: {
    readonly admitted: boolean
    readonly estimatedBytes: number
    readonly runtimeLimitBytes: number
    readonly maxMemoryBytes: number | null
    readonly deviceMemoryGB: number | null
    readonly constrained: boolean
    readonly detail: string
  }
  readonly threads: {
    readonly requested: number
    readonly admitted: number
    readonly crossOriginIsolated: boolean
    readonly fallbackSingleThread: boolean
    readonly detail: string
  }
  readonly concurrency: {
    readonly admitted: boolean
    readonly activeTasks: number
    readonly maxConcurrentTasks: number
    readonly availableSlots: number
    readonly detail: string
  }
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
  maxDiagnosticBytes: 4096,
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

export type BrowserArtifactManifestLike = {
  format?: string
  version?: number
  artifacts?: readonly BrowserArtifactEntry[]
  skipped?: readonly string[]
  toolchain?: {
    barretenberg?: string
    nargo?: string
    oracle_hash?: string
    proving_scheme?: string
  }
}

export type ProofWorkerArtifactEntryMetadata = {
  readonly path: string
  readonly role?: string
  readonly kind?: string
  readonly rawBytes: number
  readonly normalizedBytes?: number
  readonly withinArtifactLimit: boolean
}

export type ProofWorkerArtifactMetadataReport = {
  readonly format: string
  readonly version: number
  readonly toolchain: {
    readonly barretenberg?: string
    readonly nargo?: string
    readonly oracleHash?: string
    readonly provingScheme?: string
  }
  readonly publishedArtifactCount: number
  readonly skippedArtifactCount: number
  readonly totalPublishedArtifactBytes: number
  readonly allArtifactsWithinLimit: boolean
  readonly artifacts: readonly ProofWorkerArtifactEntryMetadata[]
  readonly memoryLimits: typeof PROOF_WORKER_MEMORY_LIMITS
}

/**
 * Inspect configured browser proving artifact metadata offline.
 * Uses only static manifest metadata and memory ceilings — never fetches or loads artifacts.
 */
export function inspectProofWorkerArtifactMetadata(
  manifest: BrowserArtifactManifestLike = browserArtifactManifest,
): ProofWorkerArtifactMetadataReport {
  const entries = (manifest.artifacts ?? []).map((entry) => {
    const rawBytes = safeBytes(entry.raw_bytes)
    const normalizedBytes =
      entry.normalized_bytes !== undefined ? safeBytes(entry.normalized_bytes) : undefined
    return Object.freeze({
      path: entry.path,
      ...(entry.role !== undefined ? { role: entry.role } : {}),
      ...(entry.kind !== undefined ? { kind: entry.kind } : {}),
      rawBytes,
      ...(normalizedBytes !== undefined ? { normalizedBytes } : {}),
      withinArtifactLimit:
        rawBytes > 0 && rawBytes <= PROOF_WORKER_MEMORY_LIMITS.maxArtifactBytes,
    })
  })

  const totalPublishedArtifactBytes = entries.reduce((total, entry) => total + entry.rawBytes, 0)
  const allArtifactsWithinLimit = entries.every((entry) => entry.withinArtifactLimit)

  return Object.freeze({
    format: manifest.format ?? 'unknown',
    version: Number.isSafeInteger(manifest.version) ? Number(manifest.version) : 0,
    toolchain: Object.freeze({
      ...(manifest.toolchain?.barretenberg !== undefined
        ? { barretenberg: manifest.toolchain.barretenberg }
        : {}),
      ...(manifest.toolchain?.nargo !== undefined ? { nargo: manifest.toolchain.nargo } : {}),
      ...(manifest.toolchain?.oracle_hash !== undefined
        ? { oracleHash: manifest.toolchain.oracle_hash }
        : {}),
      ...(manifest.toolchain?.proving_scheme !== undefined
        ? { provingScheme: manifest.toolchain.proving_scheme }
        : {}),
    }),
    publishedArtifactCount: entries.length,
    skippedArtifactCount: (manifest.skipped ?? []).length,
    totalPublishedArtifactBytes,
    allArtifactsWithinLimit,
    artifacts: Object.freeze(entries),
    memoryLimits: PROOF_WORKER_MEMORY_LIMITS,
  })
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

const MAX_WASM_THREADS = 8
const LOW_DEVICE_MEMORY_GB_THRESHOLD = 2
const BYTES_PER_MIB = 1024 * 1024

function isByteCountWithin(value: number | null | undefined, limit: number): boolean {
  if (value === null || value === undefined) return true
  return Number.isSafeInteger(value) && value >= 0 && value <= limit
}

function normalizeNonNegativeInt(value: number | null | undefined, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback
  return Math.max(0, Math.floor(value))
}

/**
 * Evaluate proof-worker resource admission before proving starts.
 *
 * Explains memory, thread, and concurrency restrictions in a privacy-safe
 * structured decision while preserving a safe single-threaded fallback for
 * constrained or non-cross-origin-isolated browsers.
 */
export function evaluateProofWorkerResourceAdmission(
  input: ProofWorkerResourceAdmissionInput = {},
): ProofWorkerResourceAdmissionDecision {
  const usage = input.usage ?? {}
  const artifactBytes = safeBytes(usage.artifactBytes)
  const witnessBytes = safeBytes(usage.witnessBytes)
  const proofBytes = safeBytes(usage.proofBytes)
  const publicInputLimitBytes =
    usage.publicInputLimitBytes !== undefined && usage.publicInputLimitBytes !== null
      ? safeBytes(usage.publicInputLimitBytes)
      : PROOF_WORKER_MEMORY_LIMITS.maxPublicInputBytes
  const publicInputBytes = safeBytes(usage.publicInputBytes)
  const secretBytes = safeBytes(usage.secretBytes)

  const estimatedBytes =
    artifactBytes + witnessBytes + proofBytes + publicInputBytes + secretBytes
  const runtimeLimitBytes =
    PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes +
    PROOF_WORKER_MEMORY_LIMITS.maxProofBytes +
    publicInputLimitBytes +
    Math.max(artifactBytes, publishedArtifactBytes)

  const maxMemoryBytes =
    typeof input.maxMemoryMB === 'number' && Number.isFinite(input.maxMemoryMB) && input.maxMemoryMB > 0
      ? Math.floor(input.maxMemoryMB * BYTES_PER_MIB)
      : null

  const deviceMemoryGB =
    typeof input.deviceMemoryGB === 'number' && Number.isFinite(input.deviceMemoryGB) && input.deviceMemoryGB > 0
      ? input.deviceMemoryGB
      : null
  const memoryConstrained =
    deviceMemoryGB !== null && deviceMemoryGB <= LOW_DEVICE_MEMORY_GB_THRESHOLD

  const memoryFieldsValid =
    isByteCountWithin(usage.artifactBytes, PROOF_WORKER_MEMORY_LIMITS.maxArtifactBytes) &&
    isByteCountWithin(usage.witnessBytes, PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes) &&
    isByteCountWithin(usage.proofBytes, PROOF_WORKER_MEMORY_LIMITS.maxProofBytes) &&
    isByteCountWithin(usage.publicInputLimitBytes, PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes) &&
    isByteCountWithin(usage.publicInputBytes, publicInputLimitBytes) &&
    isByteCountWithin(usage.secretBytes, PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes)

  const withinRuntimeLimit = estimatedBytes <= runtimeLimitBytes
  const withinMaxMemoryCap = maxMemoryBytes === null || estimatedBytes <= maxMemoryBytes
  const memoryAdmitted = memoryFieldsValid && withinRuntimeLimit && withinMaxMemoryCap

  const memoryDetail = !memoryAdmitted
    ? `Memory budget exceeded (${estimatedBytes} B estimated against ${
        maxMemoryBytes !== null ? Math.min(runtimeLimitBytes, maxMemoryBytes) : runtimeLimitBytes
      } B limit).`
    : memoryConstrained
      ? `Device memory is constrained (${deviceMemoryGB} GB); using single-threaded fallback within ${runtimeLimitBytes} B runtime budget.`
      : `Memory within budget (${estimatedBytes} B / ${runtimeLimitBytes} B runtime limit).`

  const crossOriginIsolated = Boolean(input.crossOriginIsolated)
  const rawHardwareConcurrency =
    typeof input.hardwareConcurrency === 'number' &&
    Number.isFinite(input.hardwareConcurrency) &&
    input.hardwareConcurrency > 0
      ? Math.floor(input.hardwareConcurrency)
      : 1
  const requestedThreads = Math.max(1, Math.min(rawHardwareConcurrency, MAX_WASM_THREADS))

  const activeTasks = normalizeNonNegativeInt(input.activeTasks, 0)
  const maxConcurrentTasks =
    typeof input.maxConcurrentTasks === 'number' && Number.isFinite(input.maxConcurrentTasks)
      ? Math.max(0, Math.floor(input.maxConcurrentTasks))
      : 1
  const availableSlots = Math.max(0, maxConcurrentTasks - activeTasks)
  const concurrencyAdmitted = maxConcurrentTasks > 0 && activeTasks < maxConcurrentTasks
  const concurrencyDetail = concurrencyAdmitted
    ? `Concurrency slot available (${activeTasks}/${maxConcurrentTasks} active).`
    : `Concurrency limit reached (${activeTasks}/${maxConcurrentTasks} active tasks).`

  const reasonCodes: ProofWorkerAdmissionReasonCode[] = []
  if (!memoryAdmitted) reasonCodes.push('memory_budget_exceeded')
  if (!concurrencyAdmitted) reasonCodes.push('concurrency_limit_reached')

  const admitted = memoryAdmitted && concurrencyAdmitted

  let admittedThreads: number
  let fallbackSingleThread = false
  let threadsDetail: string

  if (!admitted) {
    admittedThreads = 0
    threadsDetail = 'Thread allocation skipped because admission was rejected.'
  } else if (!crossOriginIsolated) {
    admittedThreads = 1
    fallbackSingleThread = true
    reasonCodes.push('fallback_single_thread_not_isolated')
    threadsDetail =
      'Cross-origin isolation unavailable; falling back to 1 thread (SharedArrayBuffer disabled).'
  } else if (memoryConstrained) {
    admittedThreads = 1
    fallbackSingleThread = true
    reasonCodes.push('fallback_single_thread_memory_constrained')
    threadsDetail = `Constrained device memory (${deviceMemoryGB} GB); falling back to 1 thread.`
  } else if (requestedThreads <= 1) {
    admittedThreads = 1
    fallbackSingleThread = true
    reasonCodes.push('fallback_single_thread_low_concurrency')
    threadsDetail = 'Single logical core detected; running in single-threaded fallback mode.'
  } else {
    admittedThreads = requestedThreads
    fallbackSingleThread = false
    reasonCodes.push('admitted')
    threadsDetail = `Multithreaded WASM proving admitted with ${admittedThreads} threads.`
  }

  const mode: ProofWorkerExecutionMode = !admitted
    ? 'rejected'
    : fallbackSingleThread
      ? 'single-threaded-fallback'
      : 'multithreaded'

  const summary = `${memoryDetail} ${threadsDetail} ${concurrencyDetail}`

  return Object.freeze({
    admitted,
    mode,
    fallbackApplied: admitted && fallbackSingleThread,
    reasonCodes: Object.freeze(reasonCodes),
    summary,
    memory: Object.freeze({
      admitted: memoryAdmitted,
      estimatedBytes,
      runtimeLimitBytes,
      maxMemoryBytes,
      deviceMemoryGB,
      constrained: memoryConstrained,
      detail: memoryDetail,
    }),
    threads: Object.freeze({
      requested: requestedThreads,
      admitted: admittedThreads,
      crossOriginIsolated,
      fallbackSingleThread,
      detail: threadsDetail,
    }),
    concurrency: Object.freeze({
      admitted: concurrencyAdmitted,
      activeTasks,
      maxConcurrentTasks,
      availableSlots,
      detail: concurrencyDetail,
    }),
  })
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

/**
 * Zeroes a byte buffer in place so completed private witness / proof material
 * does not linger in memory once its operation has finished.
 */
export function wipeProofBuffer(buffer: ArrayBuffer | ArrayBufferView | null | undefined): void {
  if (!buffer) return
  if (buffer instanceof ArrayBuffer) {
    new Uint8Array(buffer).fill(0)
    return
  }
  new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).fill(0)
}

/**
 * Tracks transient proof buffers for an operation and releases them (zeroing
 * contents and dropping references) once the operation completes or the
 * session is reused, so a later operation cannot observe earlier witness data.
 */
export class ProofBufferLedger {
  private buffers = new Set<ArrayBuffer | ArrayBufferView>()

  track<T extends ArrayBuffer | ArrayBufferView>(buffer: T): T {
    this.buffers.add(buffer)
    return buffer
  }

  /** Releases a buffer after it has been transferred or exported. */
  release(buffer: ArrayBuffer | ArrayBufferView): void {
    if (this.buffers.delete(buffer)) wipeProofBuffer(buffer)
  }

  get size(): number {
    return this.buffers.size
  }

  /** Wipes and forgets every tracked buffer. Safe to call repeatedly. */
  clear(): void {
    for (const buffer of this.buffers) wipeProofBuffer(buffer)
    this.buffers.clear()
  }
}
