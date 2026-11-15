import type { ProofWorkerMessage, ProofWorkerResponse, WorkerStatus } from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import {
  DEFAULT_WORKER_TEARDOWN_TIMEOUT_MS,
  MAX_WORKER_TEARDOWN_TIMEOUT_MS,
  MIN_WORKER_TEARDOWN_TIMEOUT_MS,
  coordinateBoundedWorkerTeardown,
  validateTeardownTimeoutMs,
  type BoundedTeardownWorkerLike,
  type WorkerTeardownOutcome,
  type WorkerTeardownResult,
} from '../proofWorkerMemory';

export {
  DEFAULT_WORKER_TEARDOWN_TIMEOUT_MS,
  MAX_WORKER_TEARDOWN_TIMEOUT_MS,
  MIN_WORKER_TEARDOWN_TIMEOUT_MS,
  coordinateBoundedWorkerTeardown,
  validateTeardownTimeoutMs,
  type BoundedTeardownWorkerLike,
  type WorkerTeardownOutcome,
  type WorkerTeardownResult,
};

const logger = new ProofWorkerLogger({ enabled: true });

export class ProofWorkerManager {
  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
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

  async verifyProof(
    evidence: string,
    proof: string,
    contract: string,
    timeout?: number
  ): Promise<ProofWorkerResponse> {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.messageHandlers.delete(messageId);
        reject(new Error('Verification timed out'));
      }, timeout || this.cspConfig.maxExecutionTimeMs);

      this.messageHandlers.set(messageId, (response) => {
        clearTimeout(timeoutId);
        this.messageHandlers.delete(messageId);
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
      };

      logger.info('Sending verify message', { id: messageId });
      void message;
    });
  }

  async cancelProof(): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    const messageId = `cancel_${Date.now()}`;

    const message: ProofWorkerMessage = {
      type: 'cancel',
      id: messageId,
    };

    logger.info('Sending cancel message', { id: messageId });
    void message;
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

  async cancelAndTeardown(options?: {
    timeoutMs?: number;
    teardownId?: string;
  }): Promise<WorkerTeardownResult> {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }
    const timeoutMs = validateTeardownTimeoutMs(options?.timeoutMs);
    const activeWorker = this.worker;
    this.worker = null;
    this.messageHandlers.clear();

    const result = await coordinateBoundedWorkerTeardown(activeWorker, {
      timeoutMs,
      teardownId: options?.teardownId,
    });
    logger.info('Worker teardown completed', {
      outcome: result.outcome,
      cleanupConfirmed: result.cleanupConfirmed,
      forcedTermination: result.forcedTermination,
    });
    return result;
  }

  destroy(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.messageHandlers.clear();
    this.isInitialized = false;
    logger.info('Worker manager destroyed');
  }
}