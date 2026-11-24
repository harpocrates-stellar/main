import type {
  ProofWorkerMessage,
  ProofWorkerResponse,
  WorkerMessageDispatchResult,
  WorkerOwnershipToken,
  WorkerStatus,
  WorkerTeardownOptions,
  WorkerTeardownResult,
} from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import {
  PROOF_MEMORY_ACCOUNTING_LIMITS,
  PROOF_MEMORY_BUFFER_CLASSES,
  ProofOperationMemoryAccountant,
  byteLengthOfProofWorkerValue,
  createProofOperationMemoryAccountant,
  type ProofBufferClassCounter,
  type ProofMemoryBufferClass,
  type ProofOperationMemoryReport,
  type ProofOperationMemoryStatus,
} from '../proofWorkerMemory';

export {
  PROOF_WORKER_PROTOCOL_VERSION,
  PROOF_MEMORY_ACCOUNTING_LIMITS,
  PROOF_MEMORY_BUFFER_CLASSES,
};
export type {
  WorkerProtocolVersionCheckResult,
  ProofBufferClassCounter,
  ProofMemoryBufferClass,
  ProofOperationMemoryReport,
  ProofOperationMemoryStatus,
};

const logger = new ProofWorkerLogger({ enabled: true });
const textEncoder = new TextEncoder();

/** Default bounded wait (ms) for an explicit worker `teardown_ack` after cancellation. */
export const DEFAULT_TEARDOWN_TIMEOUT_MS = 2000;

/**
 * Coordinates browser proof worker lifecycle, CSP validation, single-owner
 * operation generation tracking, and bounded teardown acknowledgement.
 *
 * Single ownership protocol:
 * - At most one active operation may hold ownership via `acquireOwnership()`.
 * - Each ownership acquisition, cancellation, or worker replacement/restart
 *   advances the monotonic `generation` counter.
 * - Incoming `progress` and proof (`success`/`error`) messages are dispatched
 *   through `handleWorkerMessage()`, which fails closed and rejects any message
 *   belonging to a cancelled, replaced, or unowned generation.
 *
 * Explicit teardown acknowledgement protocol:
 * - `cancelAndTeardown()` cancels the active generation, posts a `cancel`
 *   message to the worker, and waits up to a bounded `timeoutMs` interval for
 *   a matching `teardown_ack` response (via `handleWorkerMessage()` or
 *   `acknowledgeTeardown()`).
 * - If acknowledged in time, teardown resolves with `status: 'confirmed'`.
 * - If the bounded interval expires without acknowledgement, the worker is
 *   forcibly terminated and teardown resolves with `status: 'forced'`.
 */
export class ProofWorkerManager {
  // Preserve the currently active proof result to avoid losing state on unexpected messages
  private activeProofResult: ProofWorkerResponse | null = null;

  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private progressHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private operationGenerations: Map<string, number> = new Map();
  private cancelledGenerations: Set<number> = new Set();
  private pendingTeardowns: Map<
    string,
    { generation: number; settle: (confirmed: boolean) => void }
  > = new Map();
  private lastTeardownResult: WorkerTeardownResult | null = null;
  private generation = 0;
  private activeOwner: WorkerOwnershipToken | null = null;
  private isInitialized = false;
  private readonly protocolVersion = PROOF_WORKER_PROTOCOL_VERSION;

  constructor(config?: Partial<ReturnType<typeof validateCSPPolicy>>) {
    this.cspConfig = validateCSPPolicy(config || {});
  }

  private trackOperationMemory(
    operationId: string,
    accountant: ProofOperationMemoryAccountant
  ): void {
    if (this.operationMemory.size >= PROOF_MEMORY_ACCOUNTING_LIMITS.maxTrackedOperations) {
      let evictKey: string | undefined;
      for (const [key, entry] of this.operationMemory.entries()) {
        if (entry.snapshot().status !== 'active') {
          evictKey = key;
          break;
        }
      }
      if (evictKey === undefined) {
        evictKey = this.operationMemory.keys().next().value;
      }
      if (evictKey !== undefined) {
        this.operationMemory.delete(evictKey);
      }
    }
    this.operationMemory.set(operationId, accountant);
  }

  async init(origin?: string): Promise<void> {

  }
    if (this.isInitialized) {
      logger.warn('Worker already initialized');
      return;
    }

    if (origin && !isOriginAllowed(origin, this.cspConfig)) {
      throw new Error(`Origin not allowed: ${origin}`);
    }

    try {
      this.isInitialized = true;
      logger.info('Worker manager initialized', { cspConfig: this.cspConfig });
    } catch (error) {
      logger.error('Failed to initialize worker manager', { error });
      throw error;
    }
  }

  /** Returns the current monotonic operation generation. */
  getGeneration(): number {
    return this.generation;
  }

  /** Returns a copy of the currently active ownership token, or null if idle. */
  getActiveOwner(): WorkerOwnershipToken | null {
    return this.activeOwner ? { ...this.activeOwner } : null;
  }

  /**
   * Acquires exclusive single-owner control of the worker for a proving or
   * verification operation. Advances the operation generation so messages from
   * any prior worker or operation cannot collide with the new owner.
   */
  acquireOwnership(operationId?: string): WorkerOwnershipToken {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    if (this.activeOwner !== null) {
      throw new Error('Worker ownership already held by an active operation');
    }

    const id = operationId ?? `op_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
    this.generation += 1;
    this.activeOwner = { generation: this.generation, operationId: id };
    this.operationGenerations.set(id, this.generation);
    return { ...this.activeOwner };
  }

  /**
   * Releases ownership if and only if the supplied token matches the active
   * owner's generation and operationId.
   */
  releaseOwnership(token: WorkerOwnershipToken): boolean {
    if (
      this.activeOwner === null ||
      this.activeOwner.generation !== token.generation ||
      this.activeOwner.operationId !== token.operationId
    ) {
      return false;
    }
    this.activeOwner = null;
    return true;
  }

  /**
   * Replaces the underlying worker instance, invalidating any active owner and
   * advancing the operation generation so stale messages from the replaced
   * worker are rejected.
   */
  replaceWorker(nextWorker: Worker | null = null): number {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }

    if (this.activeOwner !== null) {
      this.cancelledGenerations.add(this.activeOwner.generation);
      this.activeOwner = null;
    } else if (this.generation > 0) {
      this.cancelledGenerations.add(this.generation);
    }

    this.generation += 1;
    this.worker = nextWorker;
    logger.info('Worker replaced', { generation: this.generation });
    return this.generation;
  }

  /**
   * Restarts the worker by replacing it and advancing the operation generation.
   */
  restartWorker(nextWorker: Worker | null = null): number {
    return this.replaceWorker(nextWorker);
  }

  /**
   * Validates and dispatches an incoming worker response against the single
   * ownership protocol. Rejects stale progress and proof messages from
   * cancelled, replaced, or unowned generations.
   */
  handleWorkerMessage(response: ProofWorkerResponse): WorkerMessageDispatchResult {
    if (!this.isInitialized) {
      return {
        accepted: false,
        reason: 'not_initialized',
        expectedGeneration: this.generation,
        receivedGeneration: response.generation,
      };
    }

    const receivedGeneration = response.generation;

    if (response.type === 'teardown_ack') {
      const cancelId = response.id;
      const pending = cancelId ? this.pendingTeardowns.get(cancelId) : undefined;
      if (!cancelId || !pending) {
        return {
          accepted: false,
          reason: 'unowned_operation',
          expectedGeneration: this.generation,
          receivedGeneration,
        };
      }
      if (receivedGeneration !== undefined && receivedGeneration !== pending.generation) {
        return {
          accepted: false,
          reason: 'stale_generation',
          expectedGeneration: pending.generation,
          receivedGeneration,
        };
      }
      this.acknowledgeTeardown(cancelId, receivedGeneration);
      return { accepted: true, generation: pending.generation, operationId: cancelId };
    }

    if (receivedGeneration !== undefined && this.cancelledGenerations.has(receivedGeneration)) {
      return {
        accepted: false,
        reason: 'cancelled',
        expectedGeneration: this.generation,
        receivedGeneration,
      };
    }

    if (this.activeOwner !== null) {
      if (receivedGeneration === undefined || receivedGeneration !== this.activeOwner.generation) {
        return {
          accepted: false,
          reason: 'stale_generation',
          expectedGeneration: this.activeOwner.generation,
          receivedGeneration,
        };
      }

      if (!response.id || response.id !== this.activeOwner.operationId) {
        return {
          accepted: false,
          reason: 'unowned_operation',
          expectedGeneration: this.activeOwner.generation,
          receivedGeneration,
        };
      }
    } else {
      if (receivedGeneration !== undefined && receivedGeneration !== this.generation) {
        return {
          accepted: false,
          reason: 'stale_generation',
          expectedGeneration: this.generation,
          receivedGeneration,
        };
      }

      const recordedGeneration = response.id ? this.operationGenerations.get(response.id) : undefined;
      if (recordedGeneration === undefined) {
        return {
          accepted: false,
          reason: 'unowned_operation',
          expectedGeneration: this.generation,
          receivedGeneration,
        };
      }

      if (this.cancelledGenerations.has(recordedGeneration)) {
        return {
          accepted: false,
          reason: 'cancelled',
          expectedGeneration: this.generation,
          receivedGeneration,
        };
      }

      if (recordedGeneration !== this.generation) {
        return {
          accepted: false,
          reason: 'stale_generation',
          expectedGeneration: this.generation,
          receivedGeneration,
        };
      }
    }

    const operationId = response.id ?? '';
    if (response.type === 'progress') {
      const progressHandler = this.progressHandlers.get(operationId);
      if (progressHandler) {
        progressHandler(response);
      }
      return { accepted: true, generation: this.generation, operationId };
    }

    if (response.type === 'success' || response.type === 'error') {
      const handler = this.messageHandlers.get(operationId);
      if (handler) {
        handler(response);
      }
      this.progressHandlers.delete(operationId);
      this.operationGenerations.delete(operationId);
      if (this.activeOwner && this.activeOwner.operationId === operationId) {
        this.activeOwner = null;
      }
      return { accepted: true, generation: this.generation, operationId };
    }

    return { accepted: true, generation: this.generation, operationId };
  }

  async verifyProof(
    evidence: string,
    proof: string,
    contract: string,
    timeout?: number,
    onProgress?: (response: ProofWorkerResponse) => void
  ): Promise<ProofWorkerResponse> {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const operationGeneration = this.generation;
    this.operationGenerations.set(messageId, operationGeneration);

    if (onProgress) {
      this.progressHandlers.set(messageId, onProgress);
    }

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.messageHandlers.delete(messageId);
        this.progressHandlers.delete(messageId);
        this.operationGenerations.delete(messageId);
        reject(new Error('Verification timed out'));
      }, timeout || this.cspConfig.maxExecutionTimeMs);

      this.messageHandlers.set(messageId, (response) => {
        clearTimeout(timeoutId);
        this.messageHandlers.delete(messageId);
        this.progressHandlers.delete(messageId);
        this.operationGenerations.delete(messageId);
        resolve(response);
      });

      const message: ProofWorkerMessage = {
        protocolVersion: this.protocolVersion,
        type: 'verify',
        payload: {
          evidence,
          proof,
          contract,
          timeout,
        },
        id: messageId,
        generation: operationGeneration,
      };

      logger.info('Sending verify message', { id: messageId });
      this.worker?.postMessage(message);
    });
  }

  /** Registers a transient buffer so it is wiped when the session completes or is reused. */
  trackBuffer<T extends ArrayBuffer | ArrayBufferView>(buffer: T): T {
    return this.bufferLedger.track(buffer);
  }

  /** Releases a buffer once it has been transferred or exported. */
  releaseBuffer(buffer: ArrayBuffer | ArrayBufferView): void {
    this.bufferLedger.release(buffer);
  }

  async cancelProof(): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    const messageId = `cancel_${Date.now()}`;

    if (this.activeOwner !== null) {
      this.cancelledGenerations.add(this.activeOwner.generation);
      this.activeOwner = null;
      this.generation += 1;
    } else if (this.operationGenerations.size > 0 || this.generation > 0) {
      this.cancelledGenerations.add(this.generation);
      this.generation += 1;
    }

    const message: ProofWorkerMessage = {
      protocolVersion: this.protocolVersion,
      type: 'cancel',
      id: messageId,
      generation: this.generation,
    };

    logger.info('Sending cancel message', { id: messageId });
    this.worker?.postMessage(message);
  }

  getProtocolVersion(): number {
    return this.protocolVersion;
  }

  /**
   * Validate an incoming worker message's protocol version before accepting any
   * transferred buffers or parsing payload fields. Returns a clear reload-required
   * error response on mismatch and settles any matching pending request.
   */
  handleWorkerMessage(
    rawMessage: unknown,
    acceptBuffers?: () => readonly ArrayBuffer[]
  ): ProofWorkerResponse {
    const candidate = isRecord(rawMessage) ? rawMessage : null;
    const id = candidate && typeof candidate.id === 'string' ? candidate.id : undefined;
    const check = validateWorkerProtocolVersion(
      candidate ? candidate.protocolVersion : undefined,
      this.protocolVersion
    );

    if (!check.compatible) {
      logger.warn('Rejected incompatible worker protocol version', {
        expectedVersion: check.expectedVersion,
        receivedVersion: check.receivedVersion,
        reloadRequired: true,
      });
      const mismatchResponse = createProtocolMismatchResponse(check, id);
      if (id !== undefined) {
        const handler = this.messageHandlers.get(id);
        handler?.(mismatchResponse);
      }
      return mismatchResponse;
    }

    // Protocol version verified: safe to accept transferred buffers and dispatch.
    acceptBuffers?.();
    const response = candidate as unknown as ProofWorkerResponse;
    if (id !== undefined) {
      const handler = this.messageHandlers.get(id);
      handler?.(response);
    }
    return response;
  }

  getProtocolVersion(): number {
    return this.protocolVersion;
  }

  /**
   * Validate an incoming worker message's protocol version before accepting any
   * transferred buffers or parsing payload fields. Returns a clear reload-required
   * error response on mismatch and settles any matching pending request.
   */
  handleWorkerMessage(
    rawMessage: unknown,
    acceptBuffers?: () => readonly ArrayBuffer[]
  ): ProofWorkerResponse {
    const candidate = isRecord(rawMessage) ? rawMessage : null;
    const id = candidate && typeof candidate.id === 'string' ? candidate.id : undefined;
    const check = validateWorkerProtocolVersion(
      candidate ? candidate.protocolVersion : undefined,
      this.protocolVersion
    );

    if (!check.compatible) {
      logger.warn('Rejected incompatible worker protocol version', {
        expectedVersion: check.expectedVersion,
        receivedVersion: check.receivedVersion,
        reloadRequired: true,
      });
      const mismatchResponse = createProtocolMismatchResponse(check, id);
      if (id !== undefined) {
        const handler = this.messageHandlers.get(id);
        handler?.(mismatchResponse);
      }
      return mismatchResponse;
    }

    // Protocol version verified: safe to accept transferred buffers and dispatch.
    const acceptedBuffers = acceptBuffers?.() ?? [];
    if (id !== undefined && acceptedBuffers.length > 0) {
      const accountant = this.operationMemory.get(id);
      if (accountant) {
        const transferredBytes = acceptedBuffers.reduce(
          (total, buffer) => total + buffer.byteLength,
          0
        );
        accountant.allocate('proof', transferredBytes);
      }
    }
    const response = candidate as unknown as ProofWorkerResponse;
    if (id !== undefined) {
      const handler = this.messageHandlers.get(id);
      handler?.(response);
    }
    return response;
  }

  /**
   * Returns a frozen, privacy-safe per-operation buffer accounting snapshot.
   * Counters reflect tracked operation buffer classes only and do not claim
   * browser-wide heap or OS-level memory precision.
   */
  getOperationMemoryReport(operationId: string): ProofOperationMemoryReport | undefined {
    return this.operationMemory.get(operationId)?.snapshot();
  }

  /**
   * Returns a bounded snapshot of tracked per-operation memory reports.
   */
  getMemoryAccountingSnapshot(): readonly ProofOperationMemoryReport[] {
    return Object.freeze(
      Array.from(this.operationMemory.values(), (accountant) => accountant.snapshot())
    );
  }

  /**
   * Returns a copy of the most recent teardown result, or null if no
   * `cancelAndTeardown()` has completed yet.
   */
  getLastTeardownResult(): WorkerTeardownResult | null {
    return this.lastTeardownResult ? { ...this.lastTeardownResult } : null;
  }

  /**
   * Records an explicit worker teardown acknowledgement for a pending
   * `cancelAndTeardown()` request. Fails closed if `cancelId` is unknown or if
   * `generation` does not match the pending teardown generation.
   */
  acknowledgeTeardown(cancelId: string, generation?: number): boolean {
    const pending = this.pendingTeardowns.get(cancelId);
    if (!pending) {
      return false;
    }
    if (generation !== undefined && generation !== pending.generation) {
      return false;
    }
    this.pendingTeardowns.delete(cancelId);
    pending.settle(true);
    return true;
  }

  /**
   * Cancels the active operation, posts a `cancel` message to the worker, and
   * waits up to a bounded interval (`timeoutMs`) for an explicit `teardown_ack`.
   *
   * - If acknowledged before the interval elapses, resolves with
   *   `status: 'confirmed'` (`confirmed: true, forced: false`).
   * - If the bounded interval elapses without acknowledgement, forcibly
   *   terminates the worker and resolves with `status: 'forced'`
   *   (`confirmed: false, forced: true`).
   */
  async cancelAndTeardown(options?: WorkerTeardownOptions): Promise<WorkerTeardownResult> {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    const timeoutMs = options?.timeoutMs ?? DEFAULT_TEARDOWN_TIMEOUT_MS;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new Error('Invalid teardown timeoutMs: must be a positive finite number');
    }

    const cancelId = `cancel_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;

    if (this.activeOwner !== null) {
      this.cancelledGenerations.add(this.activeOwner.generation);
      this.activeOwner = null;
      this.generation += 1;
    } else if (this.operationGenerations.size > 0 || this.generation > 0) {
      this.cancelledGenerations.add(this.generation);
      this.generation += 1;
    }

    const teardownGeneration = this.generation;
    const message: ProofWorkerMessage = {
      type: 'cancel',
      id: cancelId,
      generation: teardownGeneration,
    };

    logger.info('Sending cancel message and awaiting teardown ack', {
      id: cancelId,
      generation: teardownGeneration,
      timeoutMs,
    });
    this.worker?.postMessage(message);

    const confirmed = await new Promise<boolean>((resolve) => {
      let settled = false;
      const settle = (wasConfirmed: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.pendingTeardowns.delete(cancelId);
        resolve(wasConfirmed);
      };

      const timer = setTimeout(() => {
        settle(false);
      }, timeoutMs);

      this.pendingTeardowns.set(cancelId, {
        generation: teardownGeneration,
        settle,
      });
    });

    if (!confirmed && this.worker) {
      this.worker.terminate();
      this.worker = null;
    }

    const result: WorkerTeardownResult = {
      status: confirmed ? 'confirmed' : 'forced',
      confirmed,
      forced: !confirmed,
      generation: teardownGeneration,
      cancelId,
      timeoutMs,
    };
    this.lastTeardownResult = result;

    if (confirmed) {
      logger.info('Worker teardown confirmed', {
        id: cancelId,
        generation: teardownGeneration,
        status: result.status,
      });
    } else {
      logger.warn('Worker teardown timed out; forced termination', {
        id: cancelId,
        generation: teardownGeneration,
        status: result.status,
        timeoutMs,
      });
    }

    return { ...result };
  }

  getStatus(): WorkerStatus {
    return {
      isRunning: false,
      currentTaskId: undefined,
      memoryUsage: undefined,
    };
  }

  getResourceAdmissionDecision(
    options: Partial<ProofWorkerResourceAdmissionInput> = {}
  ): ProofWorkerResourceAdmissionDecision {
    const nav =
      typeof navigator !== 'undefined'
        ? (navigator as Navigator & { deviceMemory?: number })
        : undefined;
    const crossOriginIsolated =
      options.crossOriginIsolated ??
      (typeof globalThis.crossOriginIsolated === 'boolean'
        ? globalThis.crossOriginIsolated
        : false);
    const hardwareConcurrency =
      options.hardwareConcurrency !== undefined
        ? options.hardwareConcurrency
        : nav?.hardwareConcurrency ?? 1;
    const deviceMemoryGB =
      options.deviceMemoryGB !== undefined
        ? options.deviceMemoryGB
        : typeof nav?.deviceMemory === 'number'
          ? nav.deviceMemory
          : null;

    return evaluateProofWorkerResourceAdmission({
      usage: options.usage,
      maxMemoryMB: options.maxMemoryMB ?? this.cspConfig.maxMemoryMB,
      deviceMemoryGB,
      crossOriginIsolated,
      hardwareConcurrency,
      activeTasks: options.activeTasks ?? this.messageHandlers.size,
      maxConcurrentTasks: options.maxConcurrentTasks ?? 1,
    });
  }

  getCSPHeaders(): Record<string, string> {
    return createCSPHeaders(this.cspConfig);
  }

  forwardDiagnosticToTelemetry(
    diagnostic: ProofWorkerDiagnosticInput,
    options?: { maxBytes?: number; emit?: typeof emitScrubbedTelemetry },
  ): BoundedProofWorkerDiagnostic {
    const bounded = boundProofWorkerDiagnostic(diagnostic, { maxBytes: options?.maxBytes });
    const sink = options?.emit ?? emitScrubbedTelemetry;
    sink(bounded.level, 'proof_worker.diagnostic', { ...bounded });
    return bounded;
  }

  destroy(): void {
    for (const pending of this.pendingTeardowns.values()) {
      pending.settle(false);
    }
    this.pendingTeardowns.clear();
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    if (this.activeOwner !== null) {
      this.cancelledGenerations.add(this.activeOwner.generation);
      this.activeOwner = null;
    }
    this.generation += 1;
    this.messageHandlers.clear();
    this.progressHandlers.clear();
    this.operationGenerations.clear();
    this.isInitialized = false;
    logger.info('Worker manager destroyed');
  }
}
