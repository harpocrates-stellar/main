import type { ProofWorkerMessage, ProofWorkerResponse, WorkerStatus } from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import {
  PROOF_WORKER_MEMORY_LIMITS,
  ProofOperationMemoryTracker,
  type ProofBufferClass,
  type ProofBufferClassCounters,
  type ProofOperationMemoryReport,
} from '../proofWorkerMemory';

export {
  ProofOperationMemoryTracker,
  type ProofBufferClass,
  type ProofBufferClassCounters,
  type ProofOperationMemoryReport,
};

const logger = new ProofWorkerLogger({ enabled: true });

export class ProofWorkerManager {
  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private isInitialized = false;
  private memoryTracker: ProofOperationMemoryTracker;

  constructor(config?: Partial<ReturnType<typeof validateCSPPolicy>>) {
    this.cspConfig = validateCSPPolicy(config || {});
    const cspBudgetBytes = this.cspConfig.maxMemoryMB * 1024 * 1024;
    this.memoryTracker = new ProofOperationMemoryTracker({
      budgetLimitBytes: Math.min(cspBudgetBytes, PROOF_WORKER_MEMORY_LIMITS.maxRuntimeBytes),
    });
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

  startOperationMemory(operationId: string, budgetLimitBytes?: number): ProofOperationMemoryReport {
    return this.memoryTracker.startOperation(operationId, budgetLimitBytes);
  }

  recordOperationAllocation(
    operationId: string,
    bufferClass: ProofBufferClass,
    byteLength: number
  ): ProofOperationMemoryReport {
    return this.memoryTracker.recordAllocation(operationId, bufferClass, byteLength);
  }

  recordOperationRelease(
    operationId: string,
    bufferClass: ProofBufferClass,
    byteLength: number
  ): ProofOperationMemoryReport {
    return this.memoryTracker.recordRelease(operationId, bufferClass, byteLength);
  }

  completeOperationMemory(operationId: string): ProofOperationMemoryReport {
    return this.memoryTracker.completeOperation(operationId);
  }

  getOperationMemoryReport(operationId: string): ProofOperationMemoryReport | null {
    return this.memoryTracker.getReport(operationId);
  }

  destroy(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.messageHandlers.clear();
    this.memoryTracker.clear();
    this.isInitialized = false;
    logger.info('Worker manager destroyed');
  }
}