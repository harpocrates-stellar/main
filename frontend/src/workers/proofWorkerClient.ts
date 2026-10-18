import type {
  FallbackReason,
  ProofErrorCode,
  RuntimeMode,
  SilentWitnessProof,
  WorkerRequest,
  WorkerResponse,
} from './proofWorker.types'
import { assessWorkerSupport } from './multiBrowserWorkerSupport'

const PROOF_TIMEOUT_MS = 60_000
const HEX64 = /^[0-9a-fA-F]{64}$/
const MAX_SECRET_BYTES = 256

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

export type GenerateSilentWitnessInput = {
  videoHash: string
  credentialSecret: string
  nullifierSecret: string
  inputSchemaVersion?: number
  verifierScope?: string
  epoch?: number
}

export class ProofWorkerError extends Error {
  code: ProofErrorCode
  constructor(code: ProofErrorCode, message: string) {
    super(message)
    this.name = 'ProofWorkerError'
    this.code = code
  }
}

type PendingJob = {
  resolve: (proof: SilentWitnessProof) => void
  reject: (err: ProofWorkerError) => void
  onProgress?: (stage: string) => void
  timeoutId: ReturnType<typeof setTimeout>
  generation: number
}

/**
 * Main-thread client for cancellable Silent Witness proving.
 *
 * Cancel / timeout / crash all terminate the worker and respawn a fresh one so
 * in-flight UltraHonk work cannot continue holding witness material. Secrets
 * are transferred (detached) into the worker and never logged.
 */
export class ProofWorkerClient {
  private worker: Worker
  private pending: Map<string, PendingJob> = new Map()
  /** Monotonic generation so messages from a terminated worker are ignored. */
  private generation = 0
  private destroyed = false

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

  private spawn(): Worker {
    const worker = new Worker(new URL('./proofWorker.ts', import.meta.url), { type: 'module' })
    const generation = this.generation
    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      if (generation !== this.generation) return
      this.handleMessage(event.data)
    }
    worker.onerror = () => {
      if (generation !== this.generation) return
      this.handleCrash()
    }
    worker.onmessageerror = () => {
      if (generation !== this.generation) return
      this.handleCrash()
    }
    return worker
  }

  private handleMessage(msg: WorkerResponse) {
    if (msg.type === 'READY') return
    const job = this.pending.get('requestId' in msg ? msg.requestId : '')
    if (!job) return
    if (msg.type === 'PROGRESS') {
      job.onProgress?.(msg.stage)
    } else if (msg.type === 'RESULT') {
      this.settle(msg.requestId, (j) => j.resolve(msg.proof))
    } else if (msg.type === 'ERROR') {
      this.settle(msg.requestId, (j) => j.reject(new ProofWorkerError(msg.code, msg.message)))
    } else if (msg.type === 'CANCELLED') {
      this.settle(msg.requestId, (j) =>
        j.reject(new ProofWorkerError('CANCELLED', 'Proof generation was cancelled.')),
      )
    }
  }

  private settle(requestId: string, apply: (job: PendingJob) => void) {
    const job = this.pending.get(requestId)
    if (!job) return
    this.pending.delete(requestId)
    clearTimeout(job.timeoutId)
    apply(job)
  }

  private rejectAll(code: ProofErrorCode, message: string) {
    const jobs = [...this.pending.entries()]
    this.pending.clear()
    for (const [, job] of jobs) {
      clearTimeout(job.timeoutId)
      job.reject(new ProofWorkerError(code, message))
    }
  }

  private respawnWorker() {
    this.generation += 1
    try {
      this.worker.terminate()
    } catch {
      // ignore
    }
    if (!this.destroyed) {
      this.worker = this.spawn()
    }
  }

  private handleCrash() {
    this.rejectAll('CRASHED', 'The proof worker crashed unexpectedly.')
    this.respawnWorker()
  }

  private timeoutJob(requestId: string) {
    const job = this.pending.get(requestId)
    if (!job) return
    this.pending.delete(requestId)
    clearTimeout(job.timeoutId)
    job.reject(new ProofWorkerError('TIMEOUT', 'Proof generation timed out.'))
    this.respawnWorker()
  }

  /**
   * Start proof generation. At most one in-flight request per client.
   * Concurrent calls reject with BUSY without posting to the worker.
   */
  generate(
    input: GenerateSilentWitnessInput,
    onProgress?: (stage: string) => void,
    signal?: AbortSignal,
  ): { requestId: string; result: Promise<SilentWitnessProof> } {
    if (this.destroyed) {
      return {
        requestId: '',
        result: Promise.reject(new ProofWorkerError('CANCELLED', 'Proof worker has been destroyed.')),
      }
    }

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

    // Fail closed before any secret crosses the worker boundary when the
    // multi-browser capability floor is not met.
    const support = assessWorkerSupport()
    if (!support.ok) {
      return {
        requestId: '',
        result: Promise.reject(
          new ProofWorkerError('UNSUPPORTED_ENVIRONMENT', support.reason),
        ),
      }
    }

    // Reject concurrent work on the client without posting another message
    // (matches the documented BUSY contract).
    if (this.pending.size > 0) {
      return {
        requestId: '',
        result: Promise.reject(
          new ProofWorkerError('BUSY', 'A proof is already being generated.'),
        ),
      }
    }

    if (signal?.aborted) {
      return {
        requestId: '',
        result: Promise.reject(new ProofWorkerError('CANCELLED', 'Proof generation was cancelled.')),
      }
    }

    const requestId = crypto.randomUUID()
    const credentialSecret = new TextEncoder().encode(input.credentialSecret).buffer
    const nullifierSecret = new TextEncoder().encode(input.nullifierSecret).buffer
    const generation = this.generation

    const result = new Promise<SilentWitnessProof>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.timeoutJob(requestId)
      }, this.fallbackLimits.timeoutMs)

      const onAbort = () => {
        this.cancel(requestId)
      }
      if (signal) {
        signal.addEventListener('abort', onAbort, { once: true })
      }

      this.pending.set(requestId, {
        resolve: (proof) => {
          if (signal) signal.removeEventListener('abort', onAbort)
          resolve(proof)
        },
        reject: (err) => {
          if (signal) signal.removeEventListener('abort', onAbort)
          reject(err)
        },
        onProgress,
        timeoutId,
        generation,
      })

      const msg: WorkerRequest = {
        type: 'GENERATE_PROOF',
        requestId,
        input: {
          videoHash: input.videoHash,
          credentialSecret,
          nullifierSecret,
          inputSchemaVersion: input.inputSchemaVersion,
          verifierScope: input.verifierScope,
          epoch: input.epoch,
        },
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

  /**
   * Cancel an in-flight proof safely:
   * 1. Post CANCEL so the worker can mark cooperative cancel + zero buffers
   * 2. Reject the pending promise with a stable CANCELLED code (no secrets)
   * 3. Terminate + respawn so UltraHonk cannot keep running with witness data
   */
  cancel(requestId: string) {
    const job = this.pending.get(requestId)
    if (!job) return

    try {
      const msg: WorkerRequest = { type: 'CANCEL', requestId }
      this.worker.postMessage(msg)
    } catch {
      // Worker may already be dead; terminate path below still settles.
    }

    this.pending.delete(requestId)
    clearTimeout(job.timeoutId)
    job.reject(new ProofWorkerError('CANCELLED', 'Proof generation was cancelled.'))
    this.respawnWorker()
  }

  /** Tear down the worker and reject any in-flight job as CANCELLED. */
  destroy() {
    if (this.destroyed) return
    this.destroyed = true
    this.rejectAll('CANCELLED', 'Proof generation was cancelled.')
    this.generation += 1
    try {
      this.worker.terminate()
    } catch {
      // ignore
    }
  }
}
