import { ProofWorkerManager } from './proof-worker-manager'
import type {
  CSPPolicyConfig,
  ProofWorkerMessage,
  ProofWorkerResponse,
} from './proof.worker.types'
import {
  assertProofWorkerMemoryBudget,
  PROOF_WORKER_MEMORY_LIMITS,
  type ProofWorkerMemoryUsage,
} from '../proofWorkerMemory'

/**
 * Failure modes modelled by the synthetic worker crash-recovery fixture protocol.
 */
export type CrashRecoveryScenario =
  | 'init_failure'
  | 'malformed_message'
  | 'interrupted_proving'

/**
 * Deterministic UI recovery phases observed across worker lifecycle and recovery.
 */
export type RecoveryPhase =
  | 'idle'
  | 'initializing'
  | 'ready'
  | 'proving'
  | 'failed'
  | 'recovering'
  | 'recovered'

/**
 * Privacy-safe error codes emitted by the crash-recovery protocol.
 * Never includes witness material, live cryptographic secrets, or raw evidence.
 */
export type CrashRecoveryErrorCode =
  | 'INIT_FAILED'
  | 'ORIGIN_REJECTED'
  | 'MALFORMED_WORKER_MESSAGE'
  | 'PROVING_INTERRUPTED'
  | 'MEMORY_LIMIT_EXCEEDED'
  | 'WORKER_CRASHED'
  | 'TIMEOUT'
  | 'NOT_READY'

/**
 * Non-secret synthetic fixture input used to drive deterministic proving and
 * crash-recovery tests without live cryptographic secrets or real media.
 */
export interface SyntheticProofFixture {
  readonly fixtureId: string
  readonly syntheticEvidenceTag: string
  readonly syntheticProofTag: string
  readonly contract: string
  readonly memoryUsage?: ProofWorkerMemoryUsage
}

/**
 * A single scripted step for `SyntheticCrashRecoveryWorker`.
 */
export type SyntheticWorkerScriptStep =
  | { kind: 'init_failure'; reason?: string }
  | { kind: 'malformed_message'; rawPayload: unknown }
  | { kind: 'message_error' }
  | { kind: 'interrupted_proving'; mode: 'crash' | 'terminate' | 'memory_exceeded' }
  | { kind: 'success'; valid: boolean; message?: string }

/**
 * Deterministic UI state snapshot emitted at every transition.
 */
export interface RecoveryUIState {
  readonly phase: RecoveryPhase
  readonly generation: number
  readonly retryCount: number
  readonly canRetry: boolean
  readonly isBusy: boolean
  readonly lastScenario: CrashRecoveryScenario | null
  readonly lastErrorCode: CrashRecoveryErrorCode | null
  readonly lastErrorMessage: string | null
  readonly lastVerified: boolean | null
}

/**
 * Structured transition log entry for deterministic assertions.
 */
export interface RecoveryTransition {
  readonly seq: number
  readonly generation: number
  readonly from: RecoveryPhase
  readonly to: RecoveryPhase
  readonly reason: string
  readonly errorCode?: CrashRecoveryErrorCode
}

/**
 * Result of running a single synthetic proving attempt.
 */
export interface SyntheticProveResult {
  readonly ok: boolean
  readonly generation: number
  readonly response?: ProofWorkerResponse
  readonly errorCode?: CrashRecoveryErrorCode
  readonly errorMessage?: string
  readonly uiState: RecoveryUIState
}

/**
 * Canonical non-secret fixture factory. Never contains real media or secrets.
 */
export function createSyntheticProofFixture(
  overrides: Partial<SyntheticProofFixture> = {},
): SyntheticProofFixture {
  return {
    fixtureId: overrides.fixtureId ?? 'fixture-synthetic-001',
    syntheticEvidenceTag: overrides.syntheticEvidenceTag ?? 'synthetic-evidence-placeholder',
    syntheticProofTag: overrides.syntheticProofTag ?? 'synthetic-proof-placeholder',
    contract: overrides.contract ?? 'C'.repeat(56),
    memoryUsage: overrides.memoryUsage ?? {
      artifactBytes: 1024,
      witnessBytes: 512,
      proofBytes: 256,
      publicInputBytes: 128,
      secretBytes: 0,
    },
  }
}

/**
 * Fail-closed validator for messages crossing the worker -> main-thread boundary.
 * Rejects malformed, untyped, or mismatched-id frames before they can influence UI state.
 */
export function isValidWorkerResponse(
  raw: unknown,
  expectedId: string,
): raw is ProofWorkerResponse {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return false
  }
  const candidate = raw as Record<string, unknown>
  if (
    candidate.type !== 'success' &&
    candidate.type !== 'error' &&
    candidate.type !== 'status'
  ) {
    return false
  }
  if (typeof candidate.id !== 'string' || candidate.id !== expectedId) {
    return false
  }

  if (candidate.type === 'success') {
    if (candidate.data === null || typeof candidate.data !== 'object' || Array.isArray(candidate.data)) {
      return false
    }
    const data = candidate.data as Record<string, unknown>
    if (typeof data.valid !== 'boolean') {
      return false
    }
    return true
  }

  if (candidate.type === 'error') {
    if (candidate.error === null || typeof candidate.error !== 'object' || Array.isArray(candidate.error)) {
      return false
    }
    const err = candidate.error as Record<string, unknown>
    return (
      typeof err.code === 'string' &&
      typeof err.message === 'string' &&
      typeof err.privacySafe === 'boolean'
    )
  }

  return true
}

/**
 * Deterministic fake worker transport that executes scripted crash-recovery steps.
 * Supports late/stale message injection to test generation-fenced UI isolation.
 */
export class SyntheticCrashRecoveryWorker {
  readonly generation: number
  terminated = false
  readonly postedMessages: ProofWorkerMessage[] = []
  onmessage: ((data: unknown) => void) | null = null
  onerror: ((reason: string) => void) | null = null
  onmessageerror: (() => void) | null = null

  private readonly step: SyntheticWorkerScriptStep

  constructor(generation: number, step: SyntheticWorkerScriptStep) {
    this.generation = generation
    this.step = step
  }

  postMessage(message: ProofWorkerMessage): void {
    if (this.terminated) {
      return
    }
    this.postedMessages.push(message)

    if (message.type !== 'verify') {
      return
    }

    const requestId = message.id ?? ''
    switch (this.step.kind) {
      case 'malformed_message':
        this.onmessage?.(this.step.rawPayload)
        break
      case 'message_error':
        this.onmessageerror?.()
        break
      case 'interrupted_proving':
        if (this.step.mode === 'crash') {
          this.onerror?.('synthetic_worker_crash')
        } else if (this.step.mode === 'terminate') {
          this.terminate()
          this.onerror?.('synthetic_worker_terminated')
        } else if (this.step.mode === 'memory_exceeded') {
          this.onmessage?.({
            type: 'error',
            id: requestId,
            error: {
              code: 'MEMORY_LIMIT_EXCEEDED',
              message: 'proof_worker_memory_exceeded',
              privacySafe: true,
            },
          } satisfies ProofWorkerResponse)
        }
        break
      case 'success':
        this.onmessage?.({
          type: 'success',
          id: requestId,
          data: {
            valid: this.step.valid,
            message: this.step.message ?? 'synthetic_verified',
          },
        } satisfies ProofWorkerResponse)
        break
      case 'init_failure':
        this.onerror?.(this.step.reason ?? 'synthetic_init_failure')
        break
    }
  }

  /**
   * Injects a late or unsolicited message (e.g. from a terminated generation)
   * to verify that stale worker frames cannot corrupt recovered UI state.
   */
  emitStaleMessage(rawPayload: unknown): void {
    this.onmessage?.(rawPayload)
  }

  terminate(): void {
    this.terminated = true
  }
}

export interface CrashRecoveryProtocolOptions {
  readonly cspConfig?: Partial<CSPPolicyConfig>
  readonly origin?: string
  readonly script: readonly SyntheticWorkerScriptStep[]
}

/**
 * Deterministic crash-recovery protocol harness built on top of `ProofWorkerManager`
 * and `proofWorkerMemory` budget enforcement.
 *
 * Models:
 * 1. Initialization failure (`init_failure`)
 * 2. Malformed worker messages (`malformed_message` / `message_error`)
 * 3. Interrupted proving (`interrupted_proving`: crash, termination, memory cap)
 *
 * Guarantees fail-closed verification, generation-fenced isolation of stale workers,
 * privacy-safe error reporting, and deterministic UI recovery.
 */
export class CrashRecoveryFixtureProtocol {
  private readonly cspConfig?: Partial<CSPPolicyConfig>
  private readonly origin?: string
  private readonly script: SyntheticWorkerScriptStep[]
  private scriptCursor = 0
  private manager: ProofWorkerManager
  private worker: SyntheticCrashRecoveryWorker | null = null
  private generation = 0
  private retryCount = 0
  private seq = 0
  private requestCounter = 0
  private phase: RecoveryPhase = 'idle'
  private lastScenario: CrashRecoveryScenario | null = null
  private lastErrorCode: CrashRecoveryErrorCode | null = null
  private lastErrorMessage: string | null = null
  private lastVerified: boolean | null = null
  private readonly transitions: RecoveryTransition[] = []
  private readonly spawnedWorkers: SyntheticCrashRecoveryWorker[] = []

  constructor(options: CrashRecoveryProtocolOptions) {
    this.cspConfig = options.cspConfig
    this.origin = options.origin
    this.script = [...options.script]
    this.manager = new ProofWorkerManager(this.cspConfig)
  }

  getUIState(): RecoveryUIState {
    return {
      phase: this.phase,
      generation: this.generation,
      retryCount: this.retryCount,
      canRetry: this.phase === 'failed' || this.phase === 'ready' || this.phase === 'recovered',
      isBusy: this.phase === 'initializing' || this.phase === 'proving' || this.phase === 'recovering',
      lastScenario: this.lastScenario,
      lastErrorCode: this.lastErrorCode,
      lastErrorMessage: this.lastErrorMessage,
      lastVerified: this.lastVerified,
    }
  }

  getTransitions(): readonly RecoveryTransition[] {
    return [...this.transitions]
  }

  getSpawnedWorkers(): readonly SyntheticCrashRecoveryWorker[] {
    return [...this.spawnedWorkers]
  }

  private transition(to: RecoveryPhase, reason: string, errorCode?: CrashRecoveryErrorCode): void {
    const from = this.phase
    this.phase = to
    this.seq += 1
    this.transitions.push({
      seq: this.seq,
      generation: this.generation,
      from,
      to,
      reason,
      ...(errorCode ? { errorCode } : {}),
    })
  }

  private nextStep(): SyntheticWorkerScriptStep {
    if (this.scriptCursor < this.script.length) {
      const step = this.script[this.scriptCursor]
      this.scriptCursor += 1
      return step
    }
    return { kind: 'success', valid: true, message: 'synthetic_default_recovered' }
  }

  private terminateCurrentWorker(): void {
    if (this.worker) {
      this.worker.terminate()
      this.worker = null
    }
  }

  /**
   * Initializes the underlying `ProofWorkerManager` and spawns a synthetic worker
   * for the current generation. Fails closed on origin rejection or scripted init failure.
   */
  async init(): Promise<RecoveryUIState> {
    this.transition('initializing', 'init_started')
    this.generation += 1
    this.lastErrorCode = null
    this.lastErrorMessage = null
    this.lastVerified = null

    try {
      await this.manager.init(this.origin)
    } catch {
      this.lastScenario = 'init_failure'
      this.lastErrorCode = 'ORIGIN_REJECTED'
      this.lastErrorMessage = 'Worker initialization rejected by origin policy.'
      this.transition('failed', 'init_origin_rejected', 'ORIGIN_REJECTED')
      return this.getUIState()
    }

    const step = this.nextStep()
    if (step.kind === 'init_failure') {
      this.manager.destroy()
      this.lastScenario = 'init_failure'
      this.lastErrorCode = 'INIT_FAILED'
      this.lastErrorMessage = 'Synthetic worker initialization failed.'
      this.transition('failed', 'init_worker_failed', 'INIT_FAILED')
      return this.getUIState()
    }

    const worker = new SyntheticCrashRecoveryWorker(this.generation, step)
    this.worker = worker
    this.spawnedWorkers.push(worker)
    this.transition('ready', 'init_succeeded')
    return this.getUIState()
  }

  /**
   * Runs a deterministic synthetic proof verification attempt.
   * Enforces `proofWorkerMemory` budgets before dispatching to the worker,
   * validates worker responses fail-closed, and transitions UI state deterministically.
   */
  async prove(fixture: SyntheticProofFixture): Promise<SyntheticProveResult> {
    if ((this.phase !== 'ready' && this.phase !== 'recovered') || !this.worker) {
      this.lastErrorCode = 'NOT_READY'
      this.lastErrorMessage = 'Worker is not ready for proving.'
      return {
        ok: false,
        generation: this.generation,
        errorCode: 'NOT_READY',
        errorMessage: this.lastErrorMessage,
        uiState: this.getUIState(),
      }
    }

    this.transition('proving', 'prove_started')
    this.lastErrorCode = null
    this.lastErrorMessage = null
    this.lastVerified = null

    if (fixture.memoryUsage) {
      try {
        assertProofWorkerMemoryBudget(fixture.memoryUsage)
      } catch {
        this.terminateCurrentWorker()
        this.lastScenario = 'interrupted_proving'
        this.lastErrorCode = 'MEMORY_LIMIT_EXCEEDED'
        this.lastErrorMessage = 'proof_worker_memory_exceeded'
        this.transition('failed', 'prove_memory_budget_exceeded', 'MEMORY_LIMIT_EXCEEDED')
        return {
          ok: false,
          generation: this.generation,
          errorCode: 'MEMORY_LIMIT_EXCEEDED',
          errorMessage: this.lastErrorMessage,
          uiState: this.getUIState(),
        }
      }
    }

    const activeGeneration = this.generation
    const activeWorker = this.worker
    this.requestCounter += 1
    const requestId = `synthetic_req_${activeGeneration}_${this.requestCounter}`

    return new Promise<SyntheticProveResult>((resolve) => {
      let settled = false

      const finishFailure = (
        scenario: CrashRecoveryScenario,
        code: CrashRecoveryErrorCode,
        message: string,
        reason: string,
      ) => {
        if (settled || activeGeneration !== this.generation) return
        settled = true
        this.terminateCurrentWorker()
        this.lastScenario = scenario
        this.lastErrorCode = code
        this.lastErrorMessage = message
        this.lastVerified = false
        this.transition('failed', reason, code)
        resolve({
          ok: false,
          generation: activeGeneration,
          errorCode: code,
          errorMessage: message,
          uiState: this.getUIState(),
        })
      }

      activeWorker.onmessage = (raw: unknown) => {
        if (settled || activeGeneration !== this.generation) {
          // Generation-fenced: late/stale frames from prior workers are ignored.
          return
        }

        if (!isValidWorkerResponse(raw, requestId)) {
          finishFailure(
            'malformed_message',
            'MALFORMED_WORKER_MESSAGE',
            'Worker emitted a malformed or mismatched response frame.',
            'prove_malformed_message',
          )
          return
        }

        if (raw.type === 'error') {
          const code: CrashRecoveryErrorCode =
            raw.error?.code === 'MEMORY_LIMIT_EXCEEDED'
              ? 'MEMORY_LIMIT_EXCEEDED'
              : 'PROVING_INTERRUPTED'
          finishFailure(
            'interrupted_proving',
            code,
            raw.error?.privacySafe ? raw.error.message : 'Worker reported a proving error.',
            'prove_worker_error_response',
          )
          return
        }

        settled = true
        this.lastVerified = Boolean(raw.data?.valid)
        this.lastErrorCode = null
        this.lastErrorMessage = null
        this.transition('ready', 'prove_succeeded')
        resolve({
          ok: true,
          generation: activeGeneration,
          response: raw,
          uiState: this.getUIState(),
        })
      }

      activeWorker.onmessageerror = () => {
        finishFailure(
          'malformed_message',
          'MALFORMED_WORKER_MESSAGE',
          'Worker message deserialization failed.',
          'prove_message_error',
        )
      }

      activeWorker.onerror = () => {
        finishFailure(
          'interrupted_proving',
          'WORKER_CRASHED',
          'Proof worker crashed during proving.',
          'prove_worker_crashed',
        )
      }

      const message: ProofWorkerMessage = {
        type: 'verify',
        id: requestId,
        payload: {
          evidence: fixture.syntheticEvidenceTag,
          proof: fixture.syntheticProofTag,
          contract: fixture.contract,
        },
      }
      activeWorker.postMessage(message)
    })
  }

  /**
   * Deterministically recovers the UI and worker subsystem from a failure state:
   * terminates any lingering worker, resets `ProofWorkerManager`, increments
   * generation, spawns a fresh worker, and transitions `failed -> recovering -> recovered`.
   */
  async recover(): Promise<RecoveryUIState> {
    this.transition('recovering', 'recovery_started')
    this.terminateCurrentWorker()
    this.manager.destroy()
    this.manager = new ProofWorkerManager(this.cspConfig)
    this.retryCount += 1
    this.generation += 1

    try {
      await this.manager.init(this.origin)
    } catch {
      this.lastScenario = 'init_failure'
      this.lastErrorCode = 'ORIGIN_REJECTED'
      this.lastErrorMessage = 'Recovery failed: origin rejected by CSP policy.'
      this.transition('failed', 'recovery_origin_rejected', 'ORIGIN_REJECTED')
      return this.getUIState()
    }

    const step = this.nextStep()
    if (step.kind === 'init_failure') {
      this.manager.destroy()
      this.lastScenario = 'init_failure'
      this.lastErrorCode = 'INIT_FAILED'
      this.lastErrorMessage = 'Recovery failed: synthetic worker initialization failed.'
      this.transition('failed', 'recovery_init_failed', 'INIT_FAILED')
      return this.getUIState()
    }

    const freshWorker = new SyntheticCrashRecoveryWorker(this.generation, step)
    this.worker = freshWorker
    this.spawnedWorkers.push(freshWorker)
    this.lastErrorCode = null
    this.lastErrorMessage = null
    this.transition('recovered', 'recovery_succeeded')
    return this.getUIState()
  }

  destroy(): void {
    this.terminateCurrentWorker()
    this.manager.destroy()
  }
}

export const CRASH_RECOVERY_MEMORY_CEILINGS = PROOF_WORKER_MEMORY_LIMITS
