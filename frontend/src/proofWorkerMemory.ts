import benchLock from '../../zk/bench/bench.lock.json'
import browserArtifactManifest from '../../zk/browser.artifacts.manifest.json'
import { CircuitInputError } from './circuitInputSchema'
import {
  detectWorkerCapabilities,
  expectationFor,
} from './workers/multiBrowserWorkerSupport'

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

export type ResourceRestrictionCategory =
  | 'memory'
  | 'threads'
  | 'concurrency'
  | 'environment'

export type ResourceRestrictionCode =
  | 'ESTIMATED_MEMORY_EXCEEDS_BUDGET'
  | 'LOW_DEVICE_MEMORY_CONSTRAINED'
  | 'BEST_EFFORT_SURFACE_MEMORY_CONSTRAINED'
  | 'CROSS_ORIGIN_ISOLATION_UNAVAILABLE'
  | 'SHARED_ARRAY_BUFFER_UNAVAILABLE'
  | 'SINGLE_CORE_HARDWARE_CONCURRENCY'
  | 'THREAD_CAP_CLAMPED'
  | 'MAX_CONCURRENT_OPERATIONS_REACHED'
  | 'WORKER_CAPABILITY_MISSING'
  | 'MAIN_THREAD_FALLBACK_REQUIRED'

export type ResourceAdmissionRestriction = {
  readonly category: ResourceRestrictionCategory
  readonly code: ResourceRestrictionCode
  readonly severity: 'advisory' | 'fallback' | 'blocking'
  readonly explanation: string
}

export type ProofWorkerExecutionMode =
  | 'multithreaded-worker'
  | 'single-threaded-worker'
  | 'bounded-main-thread-fallback'
  | 'rejected'

export type ProofWorkerAdmissionOutcome =
  | 'admit_optimal'
  | 'admit_constrained'
  | 'reject'

export type ProofWorkerAdmissionInput = {
  globalObj?: typeof globalThis
  browser?: string
  platform?: string
  activeOperations?: number
  maxConcurrentOperations?: number
  memoryBudgetBytes?: number
  estimatedUsage?: ProofWorkerMemoryUsage
  requestedThreads?: number
  allowBoundedMainThreadFallback?: boolean
  maxFallbackSecretBytes?: number
}

export type ProofWorkerAdmissionDecision = {
  readonly admitted: boolean
  readonly outcome: ProofWorkerAdmissionOutcome
  readonly executionMode: ProofWorkerExecutionMode
  readonly grantedThreads: number
  readonly maxConcurrentOperations: number
  readonly activeOperations: number
  readonly memoryBudgetBytes: number
  readonly estimatedOperationBytes: number
  readonly restrictions: readonly ResourceAdmissionRestriction[]
  readonly summary: string
}

const DEFAULT_MAX_CONCURRENT_OPERATIONS = 1
const DEFAULT_MAX_FALLBACK_SECRET_BYTES = 256
const MAX_WORKER_THREADS = 8

function nonNegativeIntOrThrow(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new CircuitInputError('invalid_input')
  }
  return value
}

function positiveIntOrThrow(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new CircuitInputError('invalid_input')
  }
  return value
}

/**
 * Evaluate memory, thread, concurrency, and capability restrictions before
 * proving starts, preserving a safe bounded fallback for constrained browsers
 * without exposing witness material.
 */
export function evaluateProofWorkerResourceAdmission(
  input: ProofWorkerAdmissionInput = {},
): ProofWorkerAdmissionDecision {
  const globalObj = input.globalObj ?? globalThis
  const activeOperations = nonNegativeIntOrThrow(input.activeOperations, 0)
  const maxConcurrentOperations = positiveIntOrThrow(
    input.maxConcurrentOperations,
    DEFAULT_MAX_CONCURRENT_OPERATIONS,
  )
  const memoryBudgetBytes = positiveIntOrThrow(
    input.memoryBudgetBytes,
    PROOF_WORKER_MEMORY_LIMITS.maxRuntimeBytes,
  )
  const maxFallbackSecretBytes = positiveIntOrThrow(
    input.maxFallbackSecretBytes,
    DEFAULT_MAX_FALLBACK_SECRET_BYTES,
  )
  const allowFallback = input.allowBoundedMainThreadFallback ?? true

  const restrictions: ResourceAdmissionRestriction[] = []
  const capabilities = detectWorkerCapabilities(globalObj)

  // 1. Core cryptographic prerequisites (fail closed; never downgrade privacy)
  const coreMissing: string[] = []
  if (!capabilities.WebAssembly) coreMissing.push('WebAssembly')
  if (!capabilities.SubtleCrypto) coreMissing.push('SubtleCrypto')
  if (!capabilities.BigInt) coreMissing.push('BigInt')
  if (!capabilities.ArrayBuffer) coreMissing.push('ArrayBuffer')
  if (coreMissing.length > 0) {
    restrictions.push(
      Object.freeze({
        category: 'environment',
        code: 'WORKER_CAPABILITY_MISSING',
        severity: 'blocking',
        explanation: `Required browser cryptographic primitives are unavailable: ${coreMissing.join(', ')}.`,
      }),
    )
  }

  // 2. Concurrency slot check
  if (activeOperations >= maxConcurrentOperations) {
    restrictions.push(
      Object.freeze({
        category: 'concurrency',
        code: 'MAX_CONCURRENT_OPERATIONS_REACHED',
        severity: 'blocking',
        explanation: `Active proof operations (${activeOperations}) reached concurrency limit (${maxConcurrentOperations}).`,
      }),
    )
  }

  // 3. Memory budget & device surface constraints
  const usage = input.estimatedUsage ?? {}
  let estimatedOperationBytes = 0
  let memoryExceeded = false
  for (const field of [
    usage.artifactBytes,
    usage.witnessBytes,
    usage.proofBytes,
    usage.publicInputBytes,
    usage.secretBytes,
  ]) {
    if (field !== undefined && field !== null) {
      if (!Number.isSafeInteger(field) || field < 0) {
        memoryExceeded = true
      } else {
        estimatedOperationBytes += field
      }
    }
  }
  try {
    assertProofWorkerMemoryBudget(usage)
  } catch {
    memoryExceeded = true
  }
  if (estimatedOperationBytes > memoryBudgetBytes) {
    memoryExceeded = true
  }
  if (memoryExceeded) {
    restrictions.push(
      Object.freeze({
        category: 'memory',
        code: 'ESTIMATED_MEMORY_EXCEEDS_BUDGET',
        severity: 'blocking',
        explanation: `Estimated proof buffer footprint exceeds configured memory budget (${memoryBudgetBytes} bytes).`,
      }),
    )
  }

  const nav = (
    globalObj as {
      navigator?: { hardwareConcurrency?: unknown; deviceMemory?: unknown }
    }
  ).navigator
  const deviceMemoryGb =
    nav && typeof nav.deviceMemory === 'number' && Number.isFinite(nav.deviceMemory)
      ? nav.deviceMemory
      : undefined
  let forceSingleThreadForMemory = false
  if (deviceMemoryGb !== undefined && deviceMemoryGb <= 2) {
    forceSingleThreadForMemory = true
    restrictions.push(
      Object.freeze({
        category: 'memory',
        code: 'LOW_DEVICE_MEMORY_CONSTRAINED',
        severity: 'fallback',
        explanation:
          'Reported device memory is 2 GB or lower; restricting proving to a single worker thread.',
      }),
    )
  }

  if (input.browser && input.platform) {
    const surface = expectationFor(input.browser, input.platform)
    if (surface?.memoryConstrained) {
      forceSingleThreadForMemory = true
      restrictions.push(
        Object.freeze({
          category: 'memory',
          code: 'BEST_EFFORT_SURFACE_MEMORY_CONSTRAINED',
          severity: 'fallback',
          explanation: `${surface.browser} on ${surface.platform} is memory-constrained; restricting proving to a single worker thread.`,
        }),
      )
    }
  }

  // 4. Worker vs bounded main-thread fallback evaluation
  const workerSupported = capabilities.Worker && capabilities.moduleWorkerType
  let useBoundedMainFallback = false
  if (!workerSupported && coreMissing.length === 0) {
    const secretBytes = safeBytes(usage.secretBytes)
    if (allowFallback && secretBytes <= maxFallbackSecretBytes) {
      useBoundedMainFallback = true
      restrictions.push(
        Object.freeze({
          category: 'environment',
          code: 'MAIN_THREAD_FALLBACK_REQUIRED',
          severity: 'fallback',
          explanation:
            'Module Web Worker API is unavailable; admitting operation via bounded single-threaded fallback.',
        }),
      )
    } else {
      restrictions.push(
        Object.freeze({
          category: 'environment',
          code: 'WORKER_CAPABILITY_MISSING',
          severity: 'blocking',
          explanation:
            'Module Web Worker API is unavailable and bounded fallback is disabled or exceeded.',
        }),
      )
    }
  }

  // 5. Threading restrictions
  const crossOriginIsolated =
    (globalObj as { crossOriginIsolated?: unknown }).crossOriginIsolated === true
  const sharedArrayBufferAvailable =
    typeof (globalObj as { SharedArrayBuffer?: unknown }).SharedArrayBuffer === 'function'
  const rawHardwareThreads =
    nav && typeof nav.hardwareConcurrency === 'number' && Number.isFinite(nav.hardwareConcurrency)
      ? Math.max(1, Math.floor(nav.hardwareConcurrency))
      : 1
  const requestedThreads =
    input.requestedThreads !== undefined
      ? positiveIntOrThrow(input.requestedThreads, rawHardwareThreads)
      : rawHardwareThreads

  const canMultithreadWorker =
    !useBoundedMainFallback &&
    workerSupported &&
    crossOriginIsolated &&
    sharedArrayBufferAvailable &&
    !forceSingleThreadForMemory

  if (!useBoundedMainFallback && workerSupported) {
    if (!crossOriginIsolated) {
      restrictions.push(
        Object.freeze({
          category: 'threads',
          code: 'CROSS_ORIGIN_ISOLATION_UNAVAILABLE',
          severity: 'fallback',
          explanation:
            'Cross-origin isolation (COOP/COEP) is inactive; falling back safely to single-threaded worker proving.',
        }),
      )
    } else if (!sharedArrayBufferAvailable) {
      restrictions.push(
        Object.freeze({
          category: 'threads',
          code: 'SHARED_ARRAY_BUFFER_UNAVAILABLE',
          severity: 'fallback',
          explanation:
            'SharedArrayBuffer is unavailable; falling back safely to single-threaded worker proving.',
        }),
      )
    } else if (canMultithreadWorker) {
      if (requestedThreads > MAX_WORKER_THREADS) {
        restrictions.push(
          Object.freeze({
            category: 'threads',
            code: 'THREAD_CAP_CLAMPED',
            severity: 'advisory',
            explanation: `Requested thread count (${requestedThreads}) clamped to proof-worker maximum (${MAX_WORKER_THREADS}).`,
          }),
        )
      }
      if (Math.max(1, Math.min(requestedThreads, MAX_WORKER_THREADS)) === 1) {
        restrictions.push(
          Object.freeze({
            category: 'threads',
            code: 'SINGLE_CORE_HARDWARE_CONCURRENCY',
            severity: 'advisory',
            explanation: 'Browser reports single-thread concurrency; running 1 worker thread.',
          }),
        )
      }
    }
  }

  const hasBlocking = restrictions.some((r) => r.severity === 'blocking')
  if (hasBlocking) {
    const blockingCodes = restrictions
      .filter((r) => r.severity === 'blocking')
      .map((r) => r.code)
      .join(', ')
    return Object.freeze({
      admitted: false,
      outcome: 'reject' as const,
      executionMode: 'rejected' as const,
      grantedThreads: 0,
      maxConcurrentOperations,
      activeOperations,
      memoryBudgetBytes,
      estimatedOperationBytes,
      restrictions: Object.freeze(restrictions),
      summary: `Proving rejected before start (${blockingCodes}).`,
    })
  }

  const grantedThreads = canMultithreadWorker
    ? Math.max(1, Math.min(requestedThreads, MAX_WORKER_THREADS))
    : 1

  const hasFallbackRestriction =
    useBoundedMainFallback || restrictions.some((r) => r.severity === 'fallback')
  const executionMode: ProofWorkerExecutionMode = useBoundedMainFallback
    ? 'bounded-main-thread-fallback'
    : grantedThreads > 1
      ? 'multithreaded-worker'
      : 'single-threaded-worker'
  const outcome: ProofWorkerAdmissionOutcome = hasFallbackRestriction
    ? 'admit_constrained'
    : 'admit_optimal'

  return Object.freeze({
    admitted: true,
    outcome,
    executionMode,
    grantedThreads,
    maxConcurrentOperations,
    activeOperations,
    memoryBudgetBytes,
    estimatedOperationBytes,
    restrictions: Object.freeze(restrictions),
    summary:
      outcome === 'admit_optimal'
        ? `Admitted in ${executionMode} mode with ${grantedThreads} thread(s).`
        : `Admitted with constrained fallback (${executionMode}, ${grantedThreads} thread).`,
  })
}
