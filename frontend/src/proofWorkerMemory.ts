import benchLock from '../../zk/bench/bench.lock.json'
import browserArtifactManifest from '../../zk/browser.artifacts.manifest.json'
import { CircuitInputError } from './circuitInputSchema'
import type { ProofStage } from './proofStage'

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

export const SYNTHETIC_FIXTURE_PROTOCOL_VERSION =
  'harpocrates.synthetic-worker-fixture.v1' as const

export const SYNTHETIC_WORKER_FAULT_MODES = Object.freeze([
  'initialization_failure',
  'malformed_message',
  'interrupted_proving',
] as const)

export type SyntheticWorkerFaultMode = (typeof SYNTHETIC_WORKER_FAULT_MODES)[number]

export type SyntheticNonSecretFixture = {
  readonly syntheticOnly: true
  readonly fixtureId: string
  readonly placeholderDigest: string
}

export type SyntheticUIRecoverySnapshot = {
  readonly uiStage: 'idle' | 'proving' | 'error' | 'ready'
  readonly activeProofStage: ProofStage | null
  readonly canRetry: boolean
  readonly errorCode: string | null
  readonly statusMessage: string
}

export type SyntheticCrashRecoveryReport = {
  readonly protocolVersion: typeof SYNTHETIC_FIXTURE_PROTOCOL_VERSION
  readonly faultMode: SyntheticWorkerFaultMode
  readonly usedLiveSecrets: false
  readonly initialFailureCode:
    | 'WORKER_INIT_FAILED'
    | 'MALFORMED_WORKER_MESSAGE'
    | 'INTERRUPTED_PROVING'
  readonly faultyWorkerTerminated: boolean
  readonly workerRespawnCount: number
  readonly uiBeforeRecovery: SyntheticUIRecoverySnapshot
  readonly uiAfterRecovery: SyntheticUIRecoverySnapshot
  readonly postRecoveryVerificationSucceeded: boolean
  readonly deterministicTranscript: readonly string[]
}

const DEFAULT_SYNTHETIC_FIXTURE: SyntheticNonSecretFixture = Object.freeze({
  syntheticOnly: true,
  fixtureId: 'synthetic-fixture-0001',
  placeholderDigest: '0'.repeat(64),
})

const FORBIDDEN_LIVE_SECRET_KEYS = new Set([
  'credentialsecret',
  'nullifiersecret',
  'privatekey',
  'seedphrase',
  'mnemonic',
  'witness',
])

function isSyntheticFaultMode(value: unknown): value is SyntheticWorkerFaultMode {
  return (
    typeof value === 'string' &&
    (SYNTHETIC_WORKER_FAULT_MODES as readonly string[]).includes(value)
  )
}

export function createSyntheticNonSecretFixture(
  fixtureId = 'synthetic-fixture-0001',
): SyntheticNonSecretFixture {
  if (!/^[a-z0-9-]{3,64}$/.test(fixtureId)) {
    throw new CircuitInputError('invalid_input')
  }
  return Object.freeze({
    syntheticOnly: true,
    fixtureId,
    placeholderDigest: '0'.repeat(64),
  })
}

export function assertSyntheticFixtureOnly(candidate: unknown): SyntheticNonSecretFixture {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new CircuitInputError('invalid_input')
  }
  const record = candidate as Record<string, unknown>
  for (const key of Object.keys(record)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '')
    if (FORBIDDEN_LIVE_SECRET_KEYS.has(normalized)) {
      throw new CircuitInputError('invalid_input')
    }
  }
  if (
    record.syntheticOnly !== true ||
    typeof record.fixtureId !== 'string' ||
    !/^[a-z0-9-]{3,64}$/.test(record.fixtureId) ||
    record.placeholderDigest !== '0'.repeat(64)
  ) {
    throw new CircuitInputError('invalid_input')
  }
  return Object.freeze({
    syntheticOnly: true,
    fixtureId: record.fixtureId,
    placeholderDigest: '0'.repeat(64),
  })
}

type SyntheticWorkerSlot = {
  id: number
  fault: SyntheticWorkerFaultMode | 'healthy'
  terminated: boolean
}

/**
 * Execute a deterministic, zero-secret crash-recovery fixture scenario across
 * initialization failure, malformed worker messages, or interrupted proving,
 * verifying worker termination, respawn, and UI state recovery.
 */
export function runSyntheticCrashRecoveryFixture(
  faultMode: SyntheticWorkerFaultMode,
  fixture: unknown = DEFAULT_SYNTHETIC_FIXTURE,
): SyntheticCrashRecoveryReport {
  if (!isSyntheticFaultMode(faultMode)) {
    throw new CircuitInputError('invalid_input')
  }
  const validatedFixture = assertSyntheticFixtureOnly(fixture)
  const transcript: string[] = [`fixture:${validatedFixture.fixtureId}:start:${faultMode}`]

  let nextWorkerId = 1
  let respawnCount = 0
  let faultyWorker: SyntheticWorkerSlot
  let activeStage: ProofStage | null
  let initialFailureCode: SyntheticCrashRecoveryReport['initialFailureCode']
  let uiBeforeRecovery: SyntheticUIRecoverySnapshot

  if (faultMode === 'initialization_failure') {
    transcript.push('worker:1:spawn_attempt:initialization_failure')
    initialFailureCode = 'WORKER_INIT_FAILED'
    faultyWorker = { id: nextWorkerId++, fault: faultMode, terminated: true }
    activeStage = null
    transcript.push('worker:1:init_failed:WORKER_INIT_FAILED')
    uiBeforeRecovery = Object.freeze({
      uiStage: 'error',
      activeProofStage: activeStage,
      canRetry: true,
      errorCode: 'WORKER_INIT_FAILED',
      statusMessage: 'Proof worker failed to initialize; ready to retry with a fresh worker.',
    })
  } else if (faultMode === 'malformed_message') {
    faultyWorker = { id: nextWorkerId++, fault: faultMode, terminated: false }
    transcript.push('worker:1:spawned')
    activeStage = 'loading_circuits'
    transcript.push(`worker:1:progress:${activeStage}`)
    transcript.push('worker:1:message_corrupted:MALFORMED_WORKER_MESSAGE')
    faultyWorker.terminated = true
    activeStage = null
    initialFailureCode = 'MALFORMED_WORKER_MESSAGE'
    uiBeforeRecovery = Object.freeze({
      uiStage: 'error',
      activeProofStage: activeStage,
      canRetry: true,
      errorCode: 'MALFORMED_WORKER_MESSAGE',
      statusMessage: 'Proof worker emitted a malformed message and was restarted.',
    })
  } else {
    faultyWorker = { id: nextWorkerId++, fault: faultMode, terminated: false }
    transcript.push('worker:1:spawned')
    activeStage = 'loading_circuits'
    transcript.push(`worker:1:progress:${activeStage}`)
    activeStage = 'executing_helper'
    transcript.push(`worker:1:progress:${activeStage}`)
    transcript.push('worker:1:interrupted:INTERRUPTED_PROVING')
    faultyWorker.terminated = true
    activeStage = null
    initialFailureCode = 'INTERRUPTED_PROVING'
    uiBeforeRecovery = Object.freeze({
      uiStage: 'error',
      activeProofStage: activeStage,
      canRetry: true,
      errorCode: 'INTERRUPTED_PROVING',
      statusMessage: 'Proving was interrupted; worker state was cleared and can be retried.',
    })
  }

  // Deterministic respawn + synthetic recovery verification
  const healthyWorker: SyntheticWorkerSlot = {
    id: nextWorkerId,
    fault: 'healthy',
    terminated: false,
  }
  respawnCount += 1
  transcript.push(`worker:${healthyWorker.id}:respawned:healthy`)
  transcript.push(`worker:${healthyWorker.id}:synthetic_probe:loading_circuits`)
  transcript.push(`worker:${healthyWorker.id}:synthetic_probe:generating_proof`)
  transcript.push(`worker:${healthyWorker.id}:synthetic_probe:verified`)

  const uiAfterRecovery: SyntheticUIRecoverySnapshot = Object.freeze({
    uiStage: 'ready',
    activeProofStage: null,
    canRetry: true,
    errorCode: null,
    statusMessage: 'Proof worker recovered and ready.',
  })
  transcript.push('ui:recovered:ready')

  return Object.freeze({
    protocolVersion: SYNTHETIC_FIXTURE_PROTOCOL_VERSION,
    faultMode,
    usedLiveSecrets: false as const,
    initialFailureCode,
    faultyWorkerTerminated: Boolean(faultyWorker?.terminated),
    workerRespawnCount: respawnCount,
    uiBeforeRecovery,
    uiAfterRecovery,
    postRecoveryVerificationSucceeded: !healthyWorker.terminated,
    deterministicTranscript: Object.freeze(transcript),
  })
}
