import type { ProofWorkerMessage, ProofWorkerResponse, WorkerStatus } from './proof.worker.types';
import type { ProofStage } from '../proofStage';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import {
  validateWorkerOperationEnvelope,
  type OperationEnvelopeRejectionReason,
  type OperationEnvelopeValidationResult,
} from '../proofWorkerMemory';

export {
  validateWorkerOperationEnvelope,
  type OperationEnvelopeRejectionReason,
  type OperationEnvelopeValidationResult,
};

export type ActiveOperationSnapshot = {
  readonly activeOperationId: string | null;
  readonly currentStage: ProofStage | null;
  readonly currentResult: ProofWorkerResponse | null;
  readonly rejectedEnvelopeCount: number;
};

const logger = new ProofWorkerLogger({ enabled: true });

export class ProofWorkerManager {
  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private isInitialized = false;
  private activeOperationId: string | null = null;
  private currentStage: ProofStage | null = null;
  private currentResult: ProofWorkerResponse | null = null;
  private rejectedEnvelopeCount = 0;

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
        const envelopeCheck = validateWorkerOperationEnvelope(response, messageId);
        if (!envelopeCheck.valid) {
          this.rejectedEnvelopeCount += 1;
          logger.warn('Rejected worker response with mismatched operation identity', {
            reason: envelopeCheck.reason,
            expectedId: messageId,
          });
          return;
        }
        clearTimeout(timeoutId);
        this.messageHandlers.delete(messageId);
        this.currentResult = response;
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

  beginActiveOperation(operationId: string, preservedResult?: ProofWorkerResponse | null): void {
    const check = validateWorkerOperationEnvelope({ id: operationId }, operationId);
    if (!check.valid) {
      throw new Error('Invalid operation identity');
    }
    this.activeOperationId = operationId;
    this.currentStage = null;
    if (preservedResult !== undefined) {
      this.currentResult = preservedResult;
    }
  }

  applyOperationEnvelope(
    rawEnvelope: unknown,
    onProgress?: (stage: ProofStage) => void
  ): OperationEnvelopeValidationResult {
    const check = validateWorkerOperationEnvelope(rawEnvelope, this.activeOperationId);
    if (!check.valid) {
      this.rejectedEnvelopeCount += 1;
      logger.warn('Rejected worker envelope before applying update', {
        reason: check.reason,
      });
      return check;
    }

    const record = rawEnvelope as Record<string, unknown>;
    if (check.stage) {
      this.currentStage = check.stage;
      onProgress?.(check.stage);
      return check;
    }

    if (record.type === 'success' || record.type === 'error' || record.type === 'status') {
      this.currentResult = rawEnvelope as ProofWorkerResponse;
      if (record.type === 'success' || record.type === 'error') {
        this.activeOperationId = null;
        this.currentStage = null;
      }
    }

    return check;
  }

  getActiveOperationState(): ActiveOperationSnapshot {
    return Object.freeze({
      activeOperationId: this.activeOperationId,
      currentStage: this.currentStage,
      currentResult: this.currentResult,
      rejectedEnvelopeCount: this.rejectedEnvelopeCount,
    });
  }

  destroy(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.messageHandlers.clear();
    this.activeOperationId = null;
    this.currentStage = null;
    this.currentResult = null;
    this.rejectedEnvelopeCount = 0;
    this.isInitialized = false;
    logger.info('Worker manager destroyed');
  }
}