import benchLock from '../../zk/bench/bench.lock.json'
import browserArtifactManifest from '../../zk/browser.artifacts.manifest.json'
import {
  CIRCUIT_INPUT_SCHEMA_VERSION,
  CircuitInputError,
  PUBLIC_FRAMES,
} from './circuitInputSchema'
import {
  assessWorkerSupport,
  detectWorkerCapabilities,
  type WorkerCapabilityId,
  type WorkerCapabilitySnapshot,
  type WorkerSupportTier,
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

export type ConfiguredArtifactSummary = {
  readonly path: string
  readonly role: string
  readonly rawBytes: number
  readonly normalizedBytes: number
  readonly rawSha256: string
  readonly normalizedSha256: string
  readonly withinMemoryLimit: boolean
}

export type OfflineWorkerCapabilityReport = {
  readonly reportVersion: 1
  readonly inspectionMode: 'offline-static'
  readonly networkContacted: false
  readonly artifactsLoaded: false
  readonly readyForWorkerProving: boolean
  readonly browserSupport: {
    readonly ok: boolean
    readonly tier: WorkerSupportTier
    readonly capabilities: WorkerCapabilitySnapshot
    readonly missing: readonly WorkerCapabilityId[]
    readonly reason: string
    readonly crossOriginIsolated: boolean
    readonly sharedArrayBufferAvailable: boolean
    readonly maxRecommendedThreads: number
  }
  readonly configuredArtifacts: {
    readonly manifestFormat: string
    readonly manifestVersion: number
    readonly toolchain: {
      readonly nargo: string
      readonly barretenberg: string
      readonly provingScheme: string
      readonly oracleHash: string
    }
    readonly inputSchemaVersion: number
    readonly supportedPublicFrames: readonly string[]
    readonly totalPublishedRawBytes: number
    readonly artifacts: readonly ConfiguredArtifactSummary[]
    readonly metadataValid: boolean
    readonly metadataIssues: readonly string[]
  }
  readonly memoryBudgets: typeof PROOF_WORKER_MEMORY_LIMITS
}

const EXPECTED_MANIFEST_FORMAT = 'harpocrates.zk-browser-artifact-manifest'
const SHA256_HEX = /^[0-9a-f]{64}$/

type RawManifestArtifact = {
  path?: unknown
  role?: unknown
  raw_bytes?: unknown
  normalized_bytes?: unknown
  raw_sha256?: unknown
  normalized_sha256?: unknown
}

type RawManifestShape = {
  format?: unknown
  version?: unknown
  toolchain?: {
    nargo?: unknown
    barretenberg?: unknown
    proving_scheme?: unknown
    oracle_hash?: unknown
  }
  artifacts?: unknown
}

/**
 * Synchronously inspect browser proof-worker prerequisites and configured
 * artifact metadata without loading compiled circuit artifacts, spawning a
 * worker, or contacting any network endpoint.
 */
export function buildOfflineWorkerCapabilityReport(options?: {
  globalObj?: typeof globalThis
  manifestOverride?: unknown
}): OfflineWorkerCapabilityReport {
  const globalObj = options?.globalObj ?? globalThis
  const capabilities = detectWorkerCapabilities(globalObj)
  const support = assessWorkerSupport(globalObj)

  const crossOriginIsolated = Boolean(
    (globalObj as { crossOriginIsolated?: unknown }).crossOriginIsolated === true,
  )
  const sharedArrayBufferAvailable =
    typeof (globalObj as { SharedArrayBuffer?: unknown }).SharedArrayBuffer === 'function'
  const nav = (globalObj as { navigator?: { hardwareConcurrency?: unknown } }).navigator
  const rawConcurrency =
    nav && typeof nav.hardwareConcurrency === 'number' && Number.isFinite(nav.hardwareConcurrency)
      ? Math.floor(nav.hardwareConcurrency)
      : 1
  const maxRecommendedThreads =
    crossOriginIsolated && sharedArrayBufferAvailable
      ? Math.max(1, Math.min(rawConcurrency || 1, 8))
      : 1

  const rawManifest = (options?.manifestOverride ?? browserArtifactManifest) as RawManifestShape
  const issues: string[] = []

  const manifestFormat = typeof rawManifest?.format === 'string' ? rawManifest.format : ''
  const manifestVersion =
    typeof rawManifest?.version === 'number' && Number.isSafeInteger(rawManifest.version)
      ? rawManifest.version
      : -1
  if (manifestFormat !== EXPECTED_MANIFEST_FORMAT) {
    issues.push('invalid_manifest_format')
  }
  if (manifestVersion !== 1) {
    issues.push('unsupported_manifest_version')
  }

  const tc = rawManifest?.toolchain
  const nargo = typeof tc?.nargo === 'string' ? tc.nargo : ''
  const barretenberg = typeof tc?.barretenberg === 'string' ? tc.barretenberg : ''
  const provingScheme = typeof tc?.proving_scheme === 'string' ? tc.proving_scheme : ''
  const oracleHash = typeof tc?.oracle_hash === 'string' ? tc.oracle_hash : ''
  if (!nargo || !barretenberg || !provingScheme || !oracleHash) {
    issues.push('incomplete_toolchain_metadata')
  }

  const rawList = Array.isArray(rawManifest?.artifacts)
    ? (rawManifest.artifacts as RawManifestArtifact[])
    : []
  if (rawList.length === 0) {
    issues.push('missing_published_artifacts')
  }

  const summaries: ConfiguredArtifactSummary[] = []
  let totalPublishedRawBytes = 0

  for (const item of rawList) {
    const path = typeof item?.path === 'string' ? item.path : ''
    const role = typeof item?.role === 'string' ? item.role : ''
    const rawBytes = safeBytes(item?.raw_bytes)
    const normalizedBytes = safeBytes(item?.normalized_bytes)
    const rawSha256 = typeof item?.raw_sha256 === 'string' ? item.raw_sha256 : ''
    const normalizedSha256 =
      typeof item?.normalized_sha256 === 'string' ? item.normalized_sha256 : ''

    const withinMemoryLimit =
      rawBytes > 0 && rawBytes <= PROOF_WORKER_MEMORY_LIMITS.maxArtifactBytes
    if (!path || !role) {
      issues.push('invalid_artifact_entry')
    } else {
      if (!SHA256_HEX.test(rawSha256) || !SHA256_HEX.test(normalizedSha256)) {
        issues.push(`invalid_artifact_digest:${path}`)
      }
      if (!withinMemoryLimit) {
        issues.push(`artifact_exceeds_memory_limit:${path}`)
      }
    }

    totalPublishedRawBytes += rawBytes
    summaries.push(
      Object.freeze({
        path,
        role,
        rawBytes,
        normalizedBytes,
        rawSha256,
        normalizedSha256,
        withinMemoryLimit,
      }),
    )
  }

  if (totalPublishedRawBytes > PROOF_WORKER_MEMORY_LIMITS.maxRuntimeBytes) {
    issues.push('published_artifacts_exceed_runtime_budget')
  }

  const metadataValid = issues.length === 0
  const supportedPublicFrames = Object.freeze(Object.keys(PUBLIC_FRAMES))

  return Object.freeze({
    reportVersion: 1 as const,
    inspectionMode: 'offline-static' as const,
    networkContacted: false as const,
    artifactsLoaded: false as const,
    readyForWorkerProving: support.ok && metadataValid,
    browserSupport: Object.freeze({
      ok: support.ok,
      tier: support.tier,
      capabilities,
      missing: support.missing,
      reason: support.reason,
      crossOriginIsolated,
      sharedArrayBufferAvailable,
      maxRecommendedThreads,
    }),
    configuredArtifacts: Object.freeze({
      manifestFormat,
      manifestVersion,
      toolchain: Object.freeze({
        nargo,
        barretenberg,
        provingScheme,
        oracleHash,
      }),
      inputSchemaVersion: CIRCUIT_INPUT_SCHEMA_VERSION,
      supportedPublicFrames,
      totalPublishedRawBytes,
      artifacts: Object.freeze(summaries),
      metadataValid,
      metadataIssues: Object.freeze(issues),
    }),
    memoryBudgets: PROOF_WORKER_MEMORY_LIMITS,
  })
}
