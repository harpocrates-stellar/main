/// <reference lib="webworker" />

import type { ProofWorkerMessage, ProofWorkerResponse } from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';

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

  const timeout = payload?.timeout ?? cspConfig?.maxExecutionTimeMs ?? 30000;
  const evidence = payload?.evidence ?? '';
  const proof = payload?.proof ?? '';
  const contract = payload?.contract ?? '';

  // Simulate proof verification logic
  // In a real implementation, this would call the actual proof verification library
  const isValid = evidence.length > 0 && proof.length > 0 && contract.length > 0;

  return {
    type: 'success',
    data: {
      valid: isValid,
      result: isValid ? { verified: true } : { verified: false },
    },
  };
}

self.onmessage = async (event: MessageEvent<ProofWorkerMessage>) => {
  const message = event.data;
  const messageId = message.id ?? 'unknown';

  try {
    switch (message.type) {
      case 'init': {
        if (message.payload?.metadata) {
          try {
            cspConfig = validateCSPPolicy(message.payload.metadata as any);
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
          logger.info('Proof verification completed', { id: messageId, valid: response.data?.valid });
          self.postMessage({ ...response, id: messageId } as ProofWorkerResponse);
        } catch (error) {
          const sanitizedError = sanitizeError(error);
          logger.error('Proof verification failed', { id: messageId, error: sanitizedError });
          self.postMessage({
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
          // In a real implementation, this would cancel the ongoing task
          isRunning = false;
          currentTaskId = null;
          self.postMessage({
            type: 'status',
            id: messageId,
            data: { message: 'Task cancelled' },
          } as ProofWorkerResponse);
        }
        break;
      }

      case 'status': {
        self.postMessage({
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
      type: 'error',
      id: messageId,
      error: sanitizedError,
    } as ProofWorkerResponse);
  }
};

self.onerror = (event: ErrorEvent) => {
  logger.error('Worker global error', { error: event.message, filename: event.filename, lineno: event.lineno });
};