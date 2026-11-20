import {
  PROOF_WORKER_PROTOCOL_VERSION,
  type ProofWorkerMessage,
  type ProofWorkerResponse,
  type WorkerProtocolVersionCheckResult,
  type WorkerStatus,
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Strictly validate a worker/main-thread protocol version without fallback parsing.
 * Rejects missing, non-integer, stringified, or mismatched versions fail-closed.
 */
export function validateWorkerProtocolVersion(
  receivedVersion: unknown,
  expectedVersion: number = PROOF_WORKER_PROTOCOL_VERSION
): WorkerProtocolVersionCheckResult {
  const isValidInteger =
    typeof receivedVersion === 'number' &&
    Number.isSafeInteger(receivedVersion) &&
    receivedVersion > 0;

  if (!isValidInteger) {
    return Object.freeze({
      compatible: false,
      code: 'PROTOCOL_VERSION_MISMATCH',
      expectedVersion,
      receivedVersion: null,
      reloadRequired: true,
      message: `Incompatible worker protocol version (expected ${expectedVersion}, received unknown). Reload required.`,
      privacySafe: true,
    });
  }

  if (receivedVersion !== expectedVersion) {
    return Object.freeze({
      compatible: false,
      code: 'PROTOCOL_VERSION_MISMATCH',
      expectedVersion,
      receivedVersion,
      reloadRequired: true,
      message: `Incompatible worker protocol version (expected ${expectedVersion}, received ${receivedVersion}). Reload required.`,
      privacySafe: true,
    });
  }

  return Object.freeze({
    compatible: true,
    protocolVersion: expectedVersion,
    reloadRequired: false,
  });
}

export function createProtocolMismatchResponse(
  check: Extract<WorkerProtocolVersionCheckResult, { compatible: false }>,
  id?: string
): ProofWorkerResponse {
  return {
    type: 'error',
    protocolVersion: check.expectedVersion,
    ...(id !== undefined ? { id } : {}),
    error: {
      code: check.code,
      message: check.message,
      privacySafe: true,
      reloadRequired: true,
    },
  };
}

export class ProofWorkerManager {
  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private operationMemory: Map<string, ProofOperationMemoryAccountant> = new Map();
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
    const accountant = createProofOperationMemoryAccountant(messageId, 'verify');
    accountant.allocate('witness', byteLengthOfProofWorkerValue(evidence));
    accountant.allocate('proof', byteLengthOfProofWorkerValue(proof));
    accountant.allocate('publicInput', byteLengthOfProofWorkerValue(contract));
    this.trackOperationMemory(messageId, accountant);

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.messageHandlers.delete(messageId);
        accountant.releaseAll('timed_out');
        reject(new Error('Verification timed out'));
      }, timeout || this.cspConfig.maxExecutionTimeMs);

      this.messageHandlers.set(messageId, (response) => {
        clearTimeout(timeoutId);
        this.messageHandlers.delete(messageId);
        accountant.releaseAll(response.type === 'error' ? 'failed' : 'completed');
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
      protocolVersion: this.protocolVersion,
      type: 'cancel',
      id: messageId,
    };

    logger.info('Sending cancel message', { id: messageId });
    // In a real implementation, this would post to the actual worker
    // this.worker?.postMessage(message);
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
    for (const accountant of this.operationMemory.values()) {
      if (accountant.snapshot().status === 'active') {
        accountant.releaseAll('cancelled');
      }
    }
    this.messageHandlers.clear();
    this.isInitialized = false;
    logger.info('Worker manager destroyed');
  }
}
