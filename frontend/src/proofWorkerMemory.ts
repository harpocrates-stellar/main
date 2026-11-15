import benchLock from '../../zk/bench/bench.lock.json'
import browserArtifactManifest from '../../zk/browser.artifacts.manifest.json'
import { CircuitInputError } from './circuitInputSchema'
import { PROOF_STAGES } from './proofStage'
import { scrubTelemetryFields } from './telemetry/scrubTelemetryFields'

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

export const DEFAULT_DIAGNOSTIC_MAX_BYTES = 512
export const MIN_DIAGNOSTIC_MAX_BYTES = 192
export const MAX_DIAGNOSTIC_MAX_BYTES = 4_096

export const STABLE_DIAGNOSTIC_STAGES = Object.freeze([
  ...PROOF_STAGES,
  'initializing',
  'verifying',
  'cancelling',
  'teardown',
  'idle',
  'unknown_stage',
] as const)

export type DiagnosticStageId = (typeof STABLE_DIAGNOSTIC_STAGES)[number]

export const STABLE_DIAGNOSTIC_ERROR_CODES = Object.freeze([
  'NONE',
  'BUSY',
  'CANCELLED',
  'CRASHED',
  'INVALID_INPUT',
  'UNSUPPORTED_INPUT_SCHEMA',
  'ARTIFACT_MISMATCH',
  'INVALID_PROOF_OUTPUT',
  'UNSUPPORTED_ENVIRONMENT',
  'CIRCUIT_LOAD_FAILED',
  'MEMORY_LIMIT_EXCEEDED',
  'PROOF_GENERATION_FAILED',
  'TIMEOUT',
  'WORKER_UNAVAILABLE',
  'FALLBACK_LIMIT_EXCEEDED',
  'PROOF_ERROR',
  'UNKNOWN_ERROR',
  'UNKNOWN_MESSAGE_TYPE',
  'VERIFICATION_TIMEOUT',
  'ORIGIN_NOT_ALLOWED',
  'invalid_input',
  'unsupported_input_schema',
  'artifact_mismatch',
  'invalid_proof_output',
  'circuit_load_failed',
  'proof_worker_memory_exceeded',
  'proof_generation_failed',
  'UNCLASSIFIED_WORKER_ERROR',
] as const)

export type DiagnosticErrorCode = (typeof STABLE_DIAGNOSTIC_ERROR_CODES)[number]

export type ProofWorkerDiagnosticInput = {
  stage?: unknown
  errorCode?: unknown
  level?: 'debug' | 'info' | 'warn' | 'error'
  message?: unknown
  context?: Record<string, unknown>
}

export type BoundedProofWorkerDiagnosticPayload = {
  readonly stage: DiagnosticStageId
  readonly errorCode: DiagnosticErrorCode
  readonly level: 'debug' | 'info' | 'warn' | 'error'
  readonly message: string
  readonly truncated: boolean
  readonly redactionsApplied: number
  readonly context?: Record<string, unknown>
}

export type BoundedProofWorkerDiagnostic = {
  readonly payload: BoundedProofWorkerDiagnosticPayload
  readonly serialized: string
  readonly payloadBytes: number
  readonly maxBytes: number
}

const STAGE_SET: ReadonlySet<string> = new Set(STABLE_DIAGNOSTIC_STAGES)
const ERROR_CODE_SET: ReadonlySet<string> = new Set(STABLE_DIAGNOSTIC_ERROR_CODES)

const INLINE_SENSITIVE_KV =
  /\b(?:credential[_-]?secret|nullifier[_-]?secret|private[_-]?input|witness(?:[_-]?[a-z0-9]+)?|nullifier|credential|secret|seed|proof)\s*[:=]\s*[^\s,;)}\]"']+/gi
const INLINE_HEX_FIELD = /\b0x[0-9a-fA-F]{8,}\b/g
const INLINE_BARE_HEX = /\b[0-9a-fA-F]{32,}\b/g
const INLINE_DECIMAL_FIELD = /\b[0-9]{16,}\b/g
const INLINE_BASE64_BLOB = /\b(?=[A-Za-z0-9+/_-]*[0-9+/=])[A-Za-z0-9+/_-]{40,}={0,2}\b/g

export function redactWitnessShapedDiagnosticText(raw: string): {
  text: string
  redactions: number
} {
  let redactions = 0
  const replaceWithMarker = (input: string, pattern: RegExp): string =>
    input.replace(pattern, () => {
      redactions += 1
      return '[REDACTED:witness]'
    })

  let out = raw
  out = replaceWithMarker(out, INLINE_SENSITIVE_KV)
  out = replaceWithMarker(out, INLINE_HEX_FIELD)
  out = replaceWithMarker(out, INLINE_BARE_HEX)
  out = replaceWithMarker(out, INLINE_DECIMAL_FIELD)
  out = replaceWithMarker(out, INLINE_BASE64_BLOB)
  return { text: out, redactions }
}

function normalizeDiagnosticStage(stage: unknown): DiagnosticStageId {
  if (typeof stage === 'string' && STAGE_SET.has(stage)) {
    return stage as DiagnosticStageId
  }
  return 'unknown_stage'
}

function normalizeDiagnosticErrorCode(errorCode: unknown): DiagnosticErrorCode {
  if (errorCode === undefined || errorCode === null || errorCode === '') {
    return 'NONE'
  }
  if (typeof errorCode === 'string' && ERROR_CODE_SET.has(errorCode)) {
    return errorCode as DiagnosticErrorCode
  }
  return 'UNCLASSIFIED_WORKER_ERROR'
}

function scrubNestedStrings(value: unknown): { value: unknown; redactions: number } {
  if (typeof value === 'string') {
    const res = redactWitnessShapedDiagnosticText(value)
    return { value: res.text, redactions: res.redactions }
  }
  if (Array.isArray(value)) {
    let redactions = 0
    const next = value.map((item) => {
      const sub = scrubNestedStrings(item)
      redactions += sub.redactions
      return sub.value
    })
    return { value: next, redactions }
  }
  if (value && typeof value === 'object') {
    let redactions = 0
    const next: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const sub = scrubNestedStrings(v)
      redactions += sub.redactions
      next[k] = sub.value
    }
    return { value: next, redactions }
  }
  return { value, redactions: 0 }
}

function utf8Bytes(text: string): number {
  return textEncoder.encode(text).byteLength
}

function sliceCodePoints(text: string, count: number): string {
  return Array.from(text).slice(0, count).join('')
}

/**
 * Redact witness-shaped values and cap UTF-8 byte size before forwarding any
 * proof-worker diagnostic to telemetry, while retaining stable `stage` and
 * `errorCode` identifiers intact.
 */
export function boundProofWorkerDiagnostic(
  input: ProofWorkerDiagnosticInput,
  options?: { maxBytes?: number },
): BoundedProofWorkerDiagnostic {
  const requestedMax = options?.maxBytes ?? DEFAULT_DIAGNOSTIC_MAX_BYTES
  if (
    !Number.isSafeInteger(requestedMax) ||
    requestedMax < MIN_DIAGNOSTIC_MAX_BYTES ||
    requestedMax > MAX_DIAGNOSTIC_MAX_BYTES
  ) {
    throw new CircuitInputError('invalid_input')
  }
  const maxBytes = requestedMax

  const stage = normalizeDiagnosticStage(input.stage)
  const errorCode = normalizeDiagnosticErrorCode(input.errorCode)
  const level =
    input.level === 'debug' ||
    input.level === 'info' ||
    input.level === 'warn' ||
    input.level === 'error'
      ? input.level
      : 'info'

  const rawMessage = typeof input.message === 'string' ? input.message : ''
  const msgRedacted = redactWitnessShapedDiagnosticText(rawMessage)
  let totalRedactions = msgRedacted.redactions
  let truncated = false

  let safeContext: Record<string, unknown> | undefined
  if (input.context && typeof input.context === 'object' && !Array.isArray(input.context)) {
    const scrubbed = scrubTelemetryFields(input.context, {
      maxDepth: 4,
      maxNodes: 64,
      capChars: 128,
    })
    totalRedactions += scrubbed.redactionsApplied
    if (scrubbed.truncationsApplied > 0 || scrubbed.stopped) {
      truncated = true
    }
    if (scrubbed.data && typeof scrubbed.data === 'object' && !Array.isArray(scrubbed.data)) {
      const deep = scrubNestedStrings(scrubbed.data)
      totalRedactions += deep.redactions
      const candidate = deep.value as Record<string, unknown>
      if (Object.keys(candidate).length > 0) {
        safeContext = candidate
      }
    }
  }

  const buildPayload = (
    message: string,
    isTruncated: boolean,
    ctx: Record<string, unknown> | undefined,
  ): BoundedProofWorkerDiagnosticPayload => {
    const base: BoundedProofWorkerDiagnosticPayload = ctx
      ? {
          stage,
          errorCode,
          level,
          message,
          truncated: isTruncated,
          redactionsApplied: totalRedactions,
          context: ctx,
        }
      : {
          stage,
          errorCode,
          level,
          message,
          truncated: isTruncated,
          redactionsApplied: totalRedactions,
        }
    return Object.freeze(base)
  }

  let candidate = buildPayload(msgRedacted.text, truncated, safeContext)
  let serialized = JSON.stringify(candidate)
  let payloadBytes = utf8Bytes(serialized)

  if (payloadBytes > maxBytes && safeContext !== undefined) {
    candidate = buildPayload(msgRedacted.text, true, undefined)
    serialized = JSON.stringify(candidate)
    payloadBytes = utf8Bytes(serialized)
  }

  if (payloadBytes > maxBytes) {
    const suffix = '…[truncated]'
    const codePoints = Array.from(msgRedacted.text)
    let low = 0
    let high = codePoints.length
    let bestPayload = buildPayload('', true, undefined)
    let bestSerialized = JSON.stringify(bestPayload)

    while (low <= high) {
      const mid = Math.floor((low + high) / 2)
      const trimmedMsg = `${sliceCodePoints(msgRedacted.text, mid)}${suffix}`
      const trial = buildPayload(trimmedMsg, true, undefined)
      const trialJson = JSON.stringify(trial)
      if (utf8Bytes(trialJson) <= maxBytes) {
        bestPayload = trial
        bestSerialized = trialJson
        low = mid + 1
      } else {
        high = mid - 1
      }
    }

    candidate = bestPayload
    serialized = bestSerialized
    payloadBytes = utf8Bytes(serialized)
  }

  return Object.freeze({
    payload: candidate,
    serialized,
    payloadBytes,
    maxBytes,
  })
}
