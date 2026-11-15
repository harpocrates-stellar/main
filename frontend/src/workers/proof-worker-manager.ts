import type { ProofWorkerMessage, ProofWorkerResponse, WorkerStatus } from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import {
  PROOF_WORKER_PROTOCOL_VERSION,
  RELOAD_REQUIRED_MESSAGE,
  checkWorkerProtocolCompatibility,
  guardTransferableBuffersForProtocol,
  type ProtocolCompatibilityResult,
} from '../proofWorkerMemory';

export {
  PROOF_WORKER_PROTOCOL_VERSION,
  RELOAD_REQUIRED_MESSAGE,
  checkWorkerProtocolCompatibility,
  guardTransferableBuffersForProtocol,
  type ProtocolCompatibilityResult,
};

const logger = new ProofWorkerLogger({ enabled: true });

export class ProofWorkerManager {
  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private isInitialized = false;
  private expectedProtocolVersion: string = PROOF_WORKER_PROTOCOL_VERSION;
  private negotiatedWorkerVersion: string | null = null;
  private protocolIncompatible = false;

  constructor(
    config?: Partial<ReturnType<typeof validateCSPPolicy>>,
    options?: { expectedProtocolVersion?: string }
  ) {
    this.cspConfig = validateCSPPolicy(config || {});
    if (options?.expectedProtocolVersion) {
      this.expectedProtocolVersion = options.expectedProtocolVersion;
    }
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

  negotiateProtocolVersion(reportedWorkerVersion: unknown): ProtocolCompatibilityResult {
    const check = checkWorkerProtocolCompatibility(
      reportedWorkerVersion,
      this.expectedProtocolVersion
    );
    if (!check.compatible) {
      this.protocolIncompatible = true;
      this.negotiatedWorkerVersion = null;
      logger.warn('Rejected incompatible worker protocol version', {
        expectedVersion: check.expectedVersion,
        actualVersion: check.actualVersion,
      });
      return check;
    }
    this.protocolIncompatible = false;
    this.negotiatedWorkerVersion = check.actualVersion;
    return check;
  }

  dispatchTransferableOperation(
    message: ProofWorkerMessage,
    transferBuffers: readonly ArrayBuffer[]
  ): ProofWorkerResponse {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    const messageVersion = message.protocolVersion ?? this.expectedProtocolVersion;
    const activeWorkerVersion = this.protocolIncompatible
      ? null
      : (this.negotiatedWorkerVersion ?? messageVersion);

    const senderGuard = guardTransferableBuffersForProtocol(
      messageVersion,
      transferBuffers,
      this.expectedProtocolVersion
    );
    if (!senderGuard.ok) {
      return this.buildProtocolMismatchResponse(message.id);
    }

    const workerGuard = guardTransferableBuffersForProtocol(
      activeWorkerVersion,
      transferBuffers,
      this.expectedProtocolVersion
    );
    if (!workerGuard.ok) {
      return this.buildProtocolMismatchResponse(message.id);
    }

    const stampedMessage: ProofWorkerMessage = {
      ...message,
      protocolVersion: this.expectedProtocolVersion,
    };
    this.worker?.postMessage(stampedMessage, workerGuard.transferList);

    return {
      type: 'status',
      protocolVersion: this.expectedProtocolVersion,
      reloadRequired: false,
      id: message.id,
      data: { message: 'Transfer dispatched' },
    };
  }

  receiveWorkerEnvelope(rawEnvelope: unknown): ProofWorkerResponse {
    if (!rawEnvelope || typeof rawEnvelope !== 'object' || Array.isArray(rawEnvelope)) {
      return this.buildProtocolMismatchResponse(undefined);
    }
    const candidate = rawEnvelope as Record<string, unknown>;
    const messageId = typeof candidate.id === 'string' ? candidate.id : undefined;
    const versionCheck = checkWorkerProtocolCompatibility(
      candidate.protocolVersion,
      this.expectedProtocolVersion
    );
    if (!versionCheck.compatible) {
      this.protocolIncompatible = true;
      return this.buildProtocolMismatchResponse(messageId);
    }
    const type = candidate.type;
    if (type !== 'success' && type !== 'error' && type !== 'status') {
      return this.buildProtocolMismatchResponse(messageId);
    }
    return {
      type,
      protocolVersion: versionCheck.actualVersion,
      reloadRequired: false,
      id: messageId,
      data:
        candidate.data && typeof candidate.data === 'object'
          ? (candidate.data as ProofWorkerResponse['data'])
          : undefined,
      error:
        candidate.error && typeof candidate.error === 'object'
          ? (candidate.error as ProofWorkerResponse['error'])
          : undefined,
    };
  }

  private buildProtocolMismatchResponse(id?: string): ProofWorkerResponse {
    return {
      type: 'error',
      protocolVersion: this.expectedProtocolVersion,
      reloadRequired: true,
      id,
      error: {
        code: 'PROTOCOL_VERSION_MISMATCH',
        message: RELOAD_REQUIRED_MESSAGE,
        privacySafe: true,
      },
    };
  }

  destroy(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.messageHandlers.clear();
    this.negotiatedWorkerVersion = null;
    this.protocolIncompatible = false;
    this.isInitialized = false;
    logger.info('Worker manager destroyed');
  }
}