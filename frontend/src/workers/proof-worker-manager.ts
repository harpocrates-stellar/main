import type { ProofWorkerMessage, ProofWorkerResponse, WorkerStatus } from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import {
  ProofWorkerOwnershipError,
  ProofWorkerOwnershipProtocol,
  type OwnedOperationStamp,
  type WorkerEnvelopeOwnershipVerdict,
  type WorkerEnvelopeStampInput,
  type WorkerOwnershipLease,
  type WorkerOwnershipSnapshot,
  type WorkerReplacementReason,
} from '../proofWorkerMemory';

export {
  ProofWorkerOwnershipError,
  ProofWorkerOwnershipProtocol,
  type OwnedOperationStamp,
  type WorkerEnvelopeOwnershipVerdict,
  type WorkerEnvelopeStampInput,
  type WorkerOwnershipLease,
  type WorkerOwnershipSnapshot,
  type WorkerReplacementReason,
};

export type OwnedWorkerDispatchInput = WorkerEnvelopeStampInput & {
  readonly stage?: string;
  readonly onProgress?: (stage: string) => void;
  readonly response?: ProofWorkerResponse;
};

const logger = new ProofWorkerLogger({ enabled: true });

export class ProofWorkerManager {
  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private isInitialized = false;
  private readonly ownership = new ProofWorkerOwnershipProtocol();

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

    this.ownership.invalidateForCancel();
    logger.info('Sending cancel message', { id: messageId });
    void message;
  }

  claimOwnership(ownerId: string): WorkerOwnershipLease {
    return this.ownership.claimOwnership(ownerId);
  }

  releaseOwnership(ownerId: string, leaseId?: string): void {
    this.ownership.releaseOwnership(ownerId, leaseId);
  }

  getOwnershipSnapshot(): WorkerOwnershipSnapshot {
    return this.ownership.getSnapshot();
  }

  beginOwnedOperation(
    params: { operationId?: string; ownerId?: string } = {},
  ): OwnedOperationStamp {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }
    const operationId =
      params.operationId ?? `msg_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
    return this.ownership.startOperation({
      operationId,
      ownerId: params.ownerId,
    });
  }

  cancelOwnedOperation(operationId?: string): {
    workerEpoch: number;
    operationGeneration: number;
  } {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }
    if (operationId !== undefined) {
      this.messageHandlers.delete(operationId);
    }
    return this.ownership.invalidateForCancel(operationId);
  }

  replaceWorker(
    nextWorker: Worker | null = null,
    reason: WorkerReplacementReason = 'manual_restart',
  ): { workerEpoch: number; operationGeneration: number } {
    if (this.worker) {
      this.worker.terminate();
    }
    this.worker = nextWorker;
    this.messageHandlers.clear();
    const state = this.ownership.recordWorkerReplacement(reason);
    logger.info('Worker replaced', {
      workerEpoch: state.workerEpoch,
      operationGeneration: state.operationGeneration,
      reason,
    });
    return state;
  }

  acceptOwnedWorkerMessage(input: OwnedWorkerDispatchInput): WorkerEnvelopeOwnershipVerdict {
    const verdict = this.ownership.validateIncomingMessage(input);
    if (!verdict.accepted) {
      return verdict;
    }

    if (input.kind === 'progress') {
      input.onProgress?.(input.stage ?? '');
      return verdict;
    }

    this.ownership.completeOperation(verdict.stamp.operationId);
    if (input.response) {
      const handler = this.messageHandlers.get(verdict.stamp.operationId);
      if (handler) {
        handler(input.response);
      }
    }
    return verdict;
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
    this.messageHandlers.clear();
    this.ownership.recordWorkerReplacement('destroy');
    this.isInitialized = false;
    logger.info('Worker manager destroyed');
  }
}