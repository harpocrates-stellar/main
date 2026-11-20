import type {
  ProofWorkerMessage,
  ProofWorkerResponse,
  WorkerMessageDispatchResult,
  WorkerOwnershipToken,
  WorkerStatus,
} from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';

const logger = new ProofWorkerLogger({ enabled: true });

/**
 * Coordinates browser proof worker lifecycle, CSP validation, and single-owner
 * operation generation tracking.
 *
 * Single ownership protocol:
 * - At most one active operation may hold ownership via `acquireOwnership()`.
 * - Each ownership acquisition, cancellation, or worker replacement/restart
 *   advances the monotonic `generation` counter.
 * - Incoming `progress` and proof (`success`/`error`) messages are dispatched
 *   through `handleWorkerMessage()`, which fails closed and rejects any message
 *   belonging to a cancelled, replaced, or unowned generation.
 */
export class ProofWorkerManager {
  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private progressHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private operationGenerations: Map<string, number> = new Map();
  private cancelledGenerations: Set<number> = new Set();
  private generation = 0;
  private activeOwner: WorkerOwnershipToken | null = null;
  private isInitialized = false;

  constructor(config?: Partial<ReturnType<typeof validateCSPPolicy>>) {
    this.cspConfig = validateCSPPolicy(config || {});
  }

  async init(origin?: string): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Worker already initialized');
      return;
    }

    if (origin && !isOriginAllowed(origin, this.cspConfig)) {
      throw new Error(`Origin not allowed: ${origin}`);
    }

    try {
      // In a real implementation, this would load the worker from a URL
      // For now, we simulate the initialization
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
      // In a real implementation, this would post to the actual worker
      // this.worker?.postMessage(message);
    });
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
      type: 'cancel',
      id: messageId,
      generation: this.generation,
    };

    logger.info('Sending cancel message', { id: messageId });
    // In a real implementation, this would post to the actual worker
    // this.worker?.postMessage(message);
  }

  getStatus(): WorkerStatus {
    return {
      isRunning: false, // In a real implementation, this would check the actual worker state
      currentTaskId: undefined,
      memoryUsage: undefined,
    };
  }

  getCSPHeaders(): Record<string, string> {
    return createCSPHeaders(this.cspConfig);
  }

  destroy(): void {
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
