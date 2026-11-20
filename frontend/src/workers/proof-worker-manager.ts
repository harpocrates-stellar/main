import type {
  ProofWorkerMessage,
  ProofWorkerResourceAdmissionDecision,
  ProofWorkerResourceAdmissionInput,
  ProofWorkerResponse,
  WorkerStatus,
} from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import { evaluateProofWorkerResourceAdmission } from '../proofWorkerMemory';

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
      // In a real implementation, this would post to the actual worker
      // this.worker?.postMessage(message);
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