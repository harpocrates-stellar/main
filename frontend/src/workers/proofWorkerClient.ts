import type {
  FallbackReason,
  ProofErrorCode,
  RuntimeMode,
  SilentWitnessProof,
  WorkerRequest,
  WorkerResponse,
} from './proofWorker.types'

export const PROOF_TIMEOUT_MS = 60_000
export const MAX_SECRET_BYTES = 256
export const HEX64 = /^[0-9a-fA-F]{64}$/

export type GenerateSilentWitnessInput = {
  videoHash: string
  credentialSecret: string
  nullifierSecret: string
}

export type FallbackLimits = {
  timeoutMs: number
  maxSecretBytes: number
}

export const DEFAULT_FALLBACK_LIMITS: Readonly<FallbackLimits> = {
  timeoutMs: PROOF_TIMEOUT_MS,
  maxSecretBytes: MAX_SECRET_BYTES,
}

export type FallbackProver = (input: GenerateSilentWitnessInput) => Promise<SilentWitnessProof>

export type ProofWorkerClientOptions = {
  /** 'auto' prefers the worker and falls back; 'worker' never falls back; 'main' always proves on the main thread. */
  runtime?: 'auto' | 'worker' | 'main'
  /** Allow falling back to main-thread proving. No effect when runtime is 'main'. Default true. */
  enableFallback?: boolean
  /** Per-request timeout for the worker and fallback paths. Default PROOF_TIMEOUT_MS. */
  timeoutMs?: number
  /** Explicit bound on secret byte length for the fallback path. Default MAX_SECRET_BYTES. */
  maxSecretBytes?: number
  /** Override the main-thread prover (tests only). Defaults to noirClient.generateSilentWitnessProof. */
  prover?: FallbackProver
  /** Override the Web Worker factory (tests only). A null/yielding factory disables the worker. */
  workerFactory?: () => Worker | null
}

function validateInput(input: GenerateSilentWitnessInput): ProofWorkerError | null {
  if (!HEX64.test(input.videoHash)) {
    return new ProofWorkerError('INVALID_INPUT', 'videoHash must be a 64-character hex string.')
  }
  if (!input.credentialSecret || !input.nullifierSecret) {
    return new ProofWorkerError('INVALID_INPUT', 'credentialSecret and nullifierSecret are required.')
  }
  const credBytes = new TextEncoder().encode(input.credentialSecret).length
  const nullBytes = new TextEncoder().encode(input.nullifierSecret).length
  if (credBytes > MAX_SECRET_BYTES || nullBytes > MAX_SECRET_BYTES) {
    return new ProofWorkerError('INVALID_INPUT', 'Secret input exceeds maximum allowed size.')
  }
  return null
}

/**
 * Classify a fallback (main-thread) failure into a stable error code.
 * The raw error is used only for classification and is never surfaced, so
 * secret or witness data embedded in an exception can never leak to the UI.
 */
function toFallbackError(error: unknown): ProofWorkerError {
  const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error)
  if (/CIRCUIT|ACIR|artifact|fetch|network|noir|wasm|panicked/i.test(message)) {
    return new ProofWorkerError('CIRCUIT_LOAD_FAILED', 'Failed to load or execute a Noir circuit on the main thread.')
  }
  if (/timed out|timeout/i.test(message)) {
    return new ProofWorkerError('TIMEOUT', 'Proof generation timed out on the main thread.')
  }
  return new ProofWorkerError('PROOF_GENERATION_FAILED', 'Proof generation failed on the main thread. Please retry.')
}

export class ProofWorkerError extends Error {
  code: ProofErrorCode
  constructor(code: ProofErrorCode, message: string) {
    super(message)
    this.code = code
  }
}

type PendingJob = {
  resolve: (proof: SilentWitnessProof) => void
  reject: (err: ProofWorkerError) => void
  onProgress?: (stage: string) => void
}

type FallbackPendingJob = {
  requestId: string
  reject: (err: ProofWorkerError) => void
}

export type ProofWorkerClientResult = {
  requestId: string
  result: Promise<SilentWitnessProof>
  /** Runtime that handled this request: the Web Worker or the non-worker fallback. */
  mode: RuntimeMode
  /** Why the main thread is used; null when the worker handled it. */
  fallbackReason: FallbackReason | null
}

export class ProofWorkerClient {
  private worker: Worker | null = null
  private pending: Map<string, PendingJob> = new Map()
  private fallbackPending: FallbackPendingJob | null = null
  private fallbackActive = false
  private readonly allowFallback: boolean
  private readonly fallbackLimits: FallbackLimits
  private readonly prover: FallbackProver
  private readonly workerFactory: () => Worker | null
  private runtimeMode: RuntimeMode | 'unavailable'
  private reason: FallbackReason | null = null

  constructor(options: ProofWorkerClientOptions = {}) {
    const runtime = options.runtime ?? 'auto'
    this.allowFallback = options.enableFallback ?? true
    this.fallbackLimits = {
      timeoutMs: options.timeoutMs ?? DEFAULT_FALLBACK_LIMITS.timeoutMs,
      maxSecretBytes: options.maxSecretBytes ?? DEFAULT_FALLBACK_LIMITS.maxSecretBytes,
    }
    this.prover =
      options.prover ??
      (async (input) => {
        const { generateSilentWitnessProof } = await import('../noirClient')
        return generateSilentWitnessProof(input)
      })
    this.workerFactory =
      options.workerFactory ??
      (() => new Worker(new URL('./proofWorker.ts', import.meta.url), { type: 'module' }))

    if (runtime === 'main') {
      this.runtimeMode = 'main-thread'
      this.reason = 'runtime_forced_main'
      return
    }
    const worker = this.spawnWorker()
    if (worker) {
      this.worker = worker
      this.runtimeMode = 'worker'
      this.reason = null
      return
    }
    if (this.allowFallback) {
      this.runtimeMode = 'main-thread'
      this.reason = runtime === 'auto' ? 'worker_spawn_failed' : 'worker_api_unavailable'
      return
    }
    this.runtimeMode = 'unavailable'
  }

  /** 'worker' | 'main-thread' when proof generation is possible, 'unavailable' otherwise. */
  get mode(): RuntimeMode | 'unavailable' {
    return this.runtimeMode
  }

  /** Why the main thread is being used, or null when not in the fallback. */
  get fallbackReason(): FallbackReason | null {
    return this.reason
  }

  get isFallbackEnabled(): boolean {
    return this.allowFallback
  }

  get limits(): Readonly<FallbackLimits> {
    return this.fallbackLimits
  }

  private spawnWorker(): Worker | null {
    if (typeof Worker === 'undefined') return null
    try {
      const worker = this.workerFactory()
      if (!worker) return null
      worker.onmessage = (event: MessageEvent<WorkerResponse>) => this.handleMessage(event.data)
      worker.onerror = () => this.handleCrash()
      worker.onmessageerror = () => this.handleCrash()
      return worker
    } catch {
      return null
    }
  }

  private handleMessage(msg: WorkerResponse) {
    if (msg.type === 'READY') return
    const job = this.pending.get('requestId' in msg ? msg.requestId : '')
    if (!job) return
    if (msg.type === 'PROGRESS') {
      job.onProgress?.(msg.stage)
    } else if (msg.type === 'RESULT') {
      this.pending.delete(msg.requestId)
      job.resolve(msg.proof)
    } else if (msg.type === 'ERROR') {
      this.pending.delete(msg.requestId)
      job.reject(new ProofWorkerError(msg.code, msg.message))
    } else if (msg.type === 'CANCELLED') {
      this.pending.delete(msg.requestId)
      job.reject(new ProofWorkerError('CANCELLED', 'Proof generation was cancelled.'))
    }
  }

  private handleCrash() {
    for (const [, job] of this.pending) {
      job.reject(new ProofWorkerError('CRASHED', 'The proof worker crashed unexpectedly.'))
    }
    this.pending.clear()
    this.worker?.terminate()
    this.worker = null
    const replacement = this.spawnWorker()
    if (replacement) {
      this.worker = replacement
      return
    }
    this.failOverToMainThread('worker_crashed')
  }

  private failOverToMainThread(reason: FallbackReason) {
    if (!this.allowFallback) {
      this.runtimeMode = 'unavailable'
      this.reason = null
      return
    }
    this.runtimeMode = 'main-thread'
    this.reason = reason
  }

  private respawnOrFailOver() {
    const replacement = this.spawnWorker()
    if (replacement) {
      this.worker = replacement
      return
    }
    this.failOverToMainThread('worker_crashed')
  }

  private timeoutJob(requestId: string) {
    const job = this.pending.get(requestId)
    if (!job) return
    this.pending.delete(requestId)
    job.reject(new ProofWorkerError('TIMEOUT', 'Proof generation timed out.'))
    this.worker?.terminate()
    this.worker = null
    this.respawnOrFailOver()
  }

  generate(
    input: GenerateSilentWitnessInput,
    onProgress?: (stage: string) => void,
  ): ProofWorkerClientResult {
    const validationError = validateInput(input)
    if (validationError) {
      return this.requestResult('', Promise.reject(validationError))
    }
    if (this.runtimeMode === 'main-thread') {
      return this.generateViaFallback(input, onProgress)
    }
    if (this.runtimeMode === 'unavailable') {
      return this.requestResult(
        '',
        Promise.reject(
          new ProofWorkerError('WORKER_UNAVAILABLE', 'Web Worker proving is unavailable and the fallback is disabled.'),
        ),
      )
    }
    const requestId = crypto.randomUUID()
    const credentialSecret = new TextEncoder().encode(input.credentialSecret).buffer
    const nullifierSecret = new TextEncoder().encode(input.nullifierSecret).buffer

    const result = new Promise<SilentWitnessProof>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.timeoutJob(requestId)
      }, this.fallbackLimits.timeoutMs)

      this.pending.set(requestId, {
        resolve: (proof) => {
          clearTimeout(timeoutId)
          resolve(proof)
        },
        reject: (err) => {
          clearTimeout(timeoutId)
          reject(err)
        },
        onProgress,
      })

      const msg: WorkerRequest = {
        type: 'GENERATE_PROOF',
        requestId,
        input: { videoHash: input.videoHash, credentialSecret, nullifierSecret },
      }
      this.worker!.postMessage(msg, [credentialSecret, nullifierSecret])
    })

    return this.requestResult(requestId, result)
  }

  private generateViaFallback(
    input: GenerateSilentWitnessInput,
    onProgress?: (stage: string) => void,
  ): ProofWorkerClientResult {
    const requestId = crypto.randomUUID()

    if (this.fallbackActive) {
      return this.requestResult(
        '',
        Promise.reject(new ProofWorkerError('BUSY', 'A proof is already being generated in the main thread.')),
      )
    }

    if (!this.withinFallbackLimits(input)) {
      return this.requestResult(
        '',
        Promise.reject(
          new ProofWorkerError('FALLBACK_LIMIT_EXCEEDED', 'Input exceeds the explicit main-thread fallback limits.'),
        ),
      )
    }

    this.fallbackActive = true
    let rejectJob: (err: ProofWorkerError) => void = () => {}

    const result = new Promise<SilentWitnessProof>((resolve, reject) => {
      rejectJob = reject
      onProgress?.('loading_circuits')
      onProgress?.('executing_helper')
      const timeoutId = setTimeout(() => {
        if (this.fallbackPending?.requestId !== requestId) return
        this.fallbackPending = null
        reject(new ProofWorkerError('TIMEOUT', 'Proof generation timed out in the main-thread fallback.'))
      }, this.fallbackLimits.timeoutMs)
      this.prover(input)
        .then(resolve)
        .catch((err) => reject(toFallbackError(err)))
        .finally(() => {
          this.fallbackActive = false
          clearTimeout(timeoutId)
          if (this.fallbackPending?.requestId === requestId) this.fallbackPending = null
        })
    })

    this.fallbackPending = { requestId, reject: rejectJob }
    return this.requestResult(requestId, result)
  }

  private withinFallbackLimits(input: GenerateSilentWitnessInput): boolean {
    const credBytes = new TextEncoder().encode(input.credentialSecret).length
    const nullBytes = new TextEncoder().encode(input.nullifierSecret).length
    return (
      credBytes <= this.fallbackLimits.maxSecretBytes && nullBytes <= this.fallbackLimits.maxSecretBytes
    )
  }

  private requestResult(requestId: string, result: Promise<SilentWitnessProof>): ProofWorkerClientResult {
    const mode: RuntimeMode = this.runtimeMode === 'main-thread' ? 'main-thread' : 'worker'
    return { requestId, result, mode, fallbackReason: mode === 'main-thread' ? this.reason : null }
  }

  cancel(requestId: string) {
    if (this.runtimeMode !== 'main-thread') {
      const job = this.pending.get(requestId)
      if (!job) return
      this.pending.delete(requestId)
      job.reject(new ProofWorkerError('CANCELLED', 'Proof generation was cancelled.'))
      this.worker?.terminate()
      this.worker = null
      this.respawnOrFailOver()
      return
    }
    if (this.fallbackPending && this.fallbackPending.requestId === requestId) {
      const job = this.fallbackPending
      this.fallbackPending = null
      job.reject(new ProofWorkerError('CANCELLED', 'Proof generation was cancelled.'))
    }
  }

  destroy() {
    this.worker?.terminate()
    this.worker = null
    this.pending.clear()
    this.fallbackPending = null
  }
}