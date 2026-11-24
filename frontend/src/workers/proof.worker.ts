/// <reference lib="webworker" />

import {
  PROOF_WORKER_PROTOCOL_VERSION,
  type ProofWorkerMessage,
  type ProofWorkerResponse,
} from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy } from './csp-policy';
import {
  createProtocolMismatchResponse,
  validateWorkerProtocolVersion,
} from './proof-worker-manager';

const logger = new ProofWorkerLogger({ enabled: true });

let cspConfig: ReturnType<typeof validateCSPPolicy> | null = null;
let isRunning = false;
let currentTaskId: string | null = null;

function sanitizeError(error: unknown): { code: string; message: string; privacySafe: boolean } {
  if (error instanceof Error) {
    return {
      code: 'PROOF_ERROR',
      message: error.message,
      privacySafe: true,
    };
  }
  return {
    code: 'UNKNOWN_ERROR',
    message: 'An unexpected error occurred',
    privacySafe: true,
  };
}

function validateInput(payload: ProofWorkerMessage['payload']): void {
  if (!payload) {
    throw new Error('Missing payload');
  }

  if (!payload.evidence && !payload.proof && !payload.contract) {
    throw new Error('Missing required fields: evidence, proof, or contract');
  }

  if (payload.evidence && typeof payload.evidence !== 'string') {
    throw new Error('Evidence must be a string');
  }

  if (payload.proof && typeof payload.proof !== 'string') {
    throw new Error('Proof must be a string');
  }

  if (payload.contract && typeof payload.contract !== 'string') {
    throw new Error('Contract must be a string');
  }

  if (payload.timeout && (typeof payload.timeout !== 'number' || payload.timeout <= 0)) {
    throw new Error('Timeout must be a positive number');
  }
}

async function verifyProof(payload: ProofWorkerMessage['payload']): Promise<ProofWorkerResponse> {
  validateInput(payload);

  const evidence = payload?.evidence ?? '';
  const proof = payload?.proof ?? '';
  const contract = payload?.contract ?? '';

  // Simulate proof verification logic
  // In a real implementation, this would call the actual proof verification library
  const isValid = evidence.length > 0 && proof.length > 0 && contract.length > 0;

  return {
    protocolVersion: PROOF_WORKER_PROTOCOL_VERSION,
    type: 'success',
    data: {
      valid: isValid,
      result: isValid ? { verified: true } : { verified: false },
    },
  };
}

self.onmessage = async (event: MessageEvent<ProofWorkerMessage>) => {
  const rawMessage: unknown = event.data;
  const candidate =
    typeof rawMessage === 'object' && rawMessage !== null && !Array.isArray(rawMessage)
      ? (rawMessage as Record<string, unknown>)
      : null;
  const messageId = candidate && typeof candidate.id === 'string' ? candidate.id : 'unknown';

  // Fail closed before accepting transferred buffers or parsing payload fields.
  const versionCheck = validateWorkerProtocolVersion(
    candidate ? candidate.protocolVersion : undefined
  );
  if (!versionCheck.compatible) {
    logger.warn('Rejected incompatible main-thread protocol version', {
      expectedVersion: versionCheck.expectedVersion,
      receivedVersion: versionCheck.receivedVersion,
      reloadRequired: true,
    });
    self.postMessage(createProtocolMismatchResponse(versionCheck, messageId));
    return;
  }

  const message = rawMessage as ProofWorkerMessage;

  try {
    switch (message.type) {
      case 'init': {
        if (message.payload?.metadata) {
          try {
            cspConfig = validateCSPPolicy(
              message.payload.metadata as Partial<ReturnType<typeof validateCSPPolicy>>
            );
            logger.info('CSP policy initialized', { config: cspConfig });
          } catch (error) {
            logger.error('Failed to initialize CSP policy', { error });
            throw error;
          }
        }
        break;
      }

      case 'verify': {
        if (!cspConfig) {
          throw new Error('CSP policy not initialized');
        }

        if (isRunning) {
          throw new Error('Worker is already running a task');
        }

        isRunning = true;
        currentTaskId = messageId;

        logger.info('Starting proof verification', { id: messageId });

        try {
          const response = await verifyProof(message.payload);
          logger.info('Proof verification completed', {
            id: messageId,
            valid: response.data?.valid,
          });
          self.postMessage({
            ...response,
            protocolVersion: PROOF_WORKER_PROTOCOL_VERSION,
            id: messageId,
          } as ProofWorkerResponse);
        } catch (error) {
          const sanitizedError = sanitizeError(error);
          logger.error('Proof verification failed', { id: messageId, error: sanitizedError });
          self.postMessage({
            protocolVersion: PROOF_WORKER_PROTOCOL_VERSION,
            type: 'error',
            id: messageId,
            error: sanitizedError,
          } as ProofWorkerResponse);
        } finally {
          isRunning = false;
          currentTaskId = null;
        }
        break;
      }

      case 'cancel': {
        if (isRunning) {
          logger.info('Cancellation requested', { id: messageId });
          // In a real implementation, this would cancel the ongoing task and release resources
          isRunning = false;
          currentTaskId = null;
          self.postMessage({
            protocolVersion: PROOF_WORKER_PROTOCOL_VERSION,
            type: 'status',
            id: messageId,
            generation: message.generation,
            data: { message: 'Task cancelled' },
          } as ProofWorkerResponse);
        }
        self.postMessage({
          type: 'teardown_ack',
          id: messageId,
          generation: message.generation,
          data: { message: 'Teardown acknowledged' },
        } as ProofWorkerResponse);
        break;
      }

      case 'status': {
        self.postMessage({
          protocolVersion: PROOF_WORKER_PROTOCOL_VERSION,
          type: 'status',
          id: messageId,
          data: {
            isRunning,
            currentTaskId,
          },
        } as ProofWorkerResponse);
        break;
      }

      default: {
        logger.warn('Unknown message type', { type: message.type });
        self.postMessage({
          protocolVersion: PROOF_WORKER_PROTOCOL_VERSION,
          type: 'error',
          id: messageId,
          error: {
            code: 'UNKNOWN_MESSAGE_TYPE',
            message: `Unknown message type: ${message.type}`,
            privacySafe: true,
          },
        } as ProofWorkerResponse);
      }
    }
  } catch (error) {
    const sanitizedError = sanitizeError(error);
    logger.error('Worker error', { id: messageId, error: sanitizedError });
    self.postMessage({
      protocolVersion: PROOF_WORKER_PROTOCOL_VERSION,
      type: 'error',
      id: messageId,
      error: sanitizedError,
    } as ProofWorkerResponse);
  }
};

self.onerror = (event: ErrorEvent) => {
  logger.error('Worker global error', {
    error: event.message,
    filename: event.filename,
    lineno: event.lineno,
  });
};
