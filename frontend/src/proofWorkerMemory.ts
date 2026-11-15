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

export const DEFAULT_WORKER_TEARDOWN_TIMEOUT_MS = 250
export const MIN_WORKER_TEARDOWN_TIMEOUT_MS = 10
export const MAX_WORKER_TEARDOWN_TIMEOUT_MS = 5_000

export type WorkerTeardownOutcome = 'acknowledged' | 'forced_termination' | 'no_active_worker'

export type WorkerTeardownResult = {
  readonly teardownId: string
  readonly outcome: WorkerTeardownOutcome
  readonly cleanupConfirmed: boolean
  readonly forcedTermination: boolean
  readonly terminated: boolean
  readonly timeoutMs: number
  readonly elapsedMs: number
}

export type BoundedTeardownWorkerLike = {
  postMessage: (message: unknown) => void
  terminate: () => void
  addEventListener?: (type: string, listener: EventListener) => void
  removeEventListener?: (type: string, listener: EventListener) => void
  onmessage?: ((event: MessageEvent) => void) | null
}

function defaultTeardownAckMatcher(payload: unknown, teardownId: string): boolean {
  if (!payload || typeof payload !== 'object') return false
  const record = payload as Record<string, unknown>
  if (record.type === 'teardown_ack' && record.id === teardownId) {
    const data = record.data as { resourcesCleaned?: unknown } | undefined
    return data?.resourcesCleaned === true
  }
  if (record.type === 'TEARDOWN_ACK' && record.teardownId === teardownId) {
    return record.resourcesCleaned === true
  }
  return false
}

export function validateTeardownTimeoutMs(timeoutMs?: number): number {
  const resolved = timeoutMs ?? DEFAULT_WORKER_TEARDOWN_TIMEOUT_MS
  if (
    !Number.isSafeInteger(resolved) ||
    resolved < MIN_WORKER_TEARDOWN_TIMEOUT_MS ||
    resolved > MAX_WORKER_TEARDOWN_TIMEOUT_MS
  ) {
    throw new CircuitInputError('invalid_input')
  }
  return resolved
}

/**
 * Send a teardown handshake to a proof worker, wait a strictly bounded
 * interval for an explicit cleanup acknowledgement, and terminate the worker
 * while distinguishing confirmed cleanup from forced timeout termination.
 */
export function coordinateBoundedWorkerTeardown(
  worker: BoundedTeardownWorkerLike | null,
  options?: {
    teardownId?: string
    timeoutMs?: number
    buildRequest?: (teardownId: string) => unknown
    isMatchingAck?: (payload: unknown, teardownId: string) => boolean
  },
): Promise<WorkerTeardownResult> {
  const timeoutMs = validateTeardownTimeoutMs(options?.timeoutMs)
  const teardownId = options?.teardownId ?? `teardown_${Date.now()}`

  if (!worker) {
    return Promise.resolve(
      Object.freeze({
        teardownId,
        outcome: 'no_active_worker' as const,
        cleanupConfirmed: true,
        forcedTermination: false,
        terminated: true,
        timeoutMs,
        elapsedMs: 0,
      }),
    )
  }

  const startedAt = Date.now()
  const matchAck = options?.isMatchingAck ?? defaultTeardownAckMatcher
  const requestPayload = options?.buildRequest
    ? options.buildRequest(teardownId)
    : { type: 'teardown', id: teardownId }

  return new Promise<WorkerTeardownResult>((resolve) => {
    let settled = false
    const previousOnMessage = worker.onmessage ?? null
    const useEventTarget =
      typeof worker.addEventListener === 'function' &&
      typeof worker.removeEventListener === 'function'

    const finish = (cleanupConfirmed: boolean) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (useEventTarget) {
        worker.removeEventListener!('message', eventListener)
      } else if (worker.onmessage === chainedOnMessage) {
        worker.onmessage = previousOnMessage
      }
      try {
        worker.terminate()
      } catch {
        // ignore termination error on dead worker
      }
      const elapsedMs = Math.max(0, Date.now() - startedAt)
      resolve(
        Object.freeze({
          teardownId,
          outcome: cleanupConfirmed ? ('acknowledged' as const) : ('forced_termination' as const),
          cleanupConfirmed,
          forcedTermination: !cleanupConfirmed,
          terminated: true,
          timeoutMs,
          elapsedMs,
        }),
      )
    }

    const inspectEvent = (event: MessageEvent) => {
      if (matchAck(event.data, teardownId)) {
        finish(true)
      }
    }

    const eventListener: EventListener = (evt: Event) => {
      inspectEvent(evt as MessageEvent)
    }

    const chainedOnMessage = (evt: MessageEvent) => {
      inspectEvent(evt)
      if (!settled && previousOnMessage) {
        previousOnMessage(evt)
      }
    }

    if (useEventTarget) {
      worker.addEventListener!('message', eventListener)
    } else {
      worker.onmessage = chainedOnMessage
    }

    const timer = setTimeout(() => {
      finish(false)
    }, timeoutMs)

    try {
      worker.postMessage(requestPayload)
    } catch {
      finish(false)
    }
  })
}
