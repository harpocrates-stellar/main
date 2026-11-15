import type { ProofWorkerMessage, ProofWorkerResponse, WorkerStatus } from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import {
  SYNTHETIC_FIXTURE_PROTOCOL_VERSION,
  SYNTHETIC_WORKER_FAULT_MODES,
  assertSyntheticFixtureOnly,
  createSyntheticNonSecretFixture,
  runSyntheticCrashRecoveryFixture,
  type SyntheticCrashRecoveryReport,
  type SyntheticNonSecretFixture,
  type SyntheticUIRecoverySnapshot,
  type SyntheticWorkerFaultMode,
} from '../proofWorkerMemory';

export {
  SYNTHETIC_FIXTURE_PROTOCOL_VERSION,
  SYNTHETIC_WORKER_FAULT_MODES,
  assertSyntheticFixtureOnly,
  createSyntheticNonSecretFixture,
  runSyntheticCrashRecoveryFixture,
  type SyntheticCrashRecoveryReport,
  type SyntheticNonSecretFixture,
  type SyntheticUIRecoverySnapshot,
  type SyntheticWorkerFaultMode,
};

export type SyntheticFaultWorkerInstance = {
  onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  onmessageerror: ((event: MessageEvent) => void) | null;
  readonly terminated: boolean;
  postMessage(message: unknown, transfer?: Transferable[]): void;
  terminate(): void;
};

/**
 * Create a deterministic `workerFactory` that injects scripted fault scenarios
 * (`initialization_failure`, `malformed_message`, `interrupted_proving`) before
 * spawning a healthy synthetic worker that resolves without network or WASM.
 */
export function createSyntheticFaultWorkerFactory(
  scriptedFaults: readonly SyntheticWorkerFaultMode[]
): {
  workerFactory: () => Worker | null;
  spawnedWorkers: SyntheticFaultWorkerInstance[];
} {
  let cursor = 0;
  const spawnedWorkers: SyntheticFaultWorkerInstance[] = [];

  const workerFactory = (): Worker | null => {
    const mode: SyntheticWorkerFaultMode | 'healthy' =
      cursor < scriptedFaults.length ? scriptedFaults[cursor++] : 'healthy';
    if (mode === 'initialization_failure') {
      throw new Error('Synthetic worker initialization failure');
    }

    let isTerminated = false;
    const worker: SyntheticFaultWorkerInstance = {
      onmessage: null,
      onerror: null,
      onmessageerror: null,
      get terminated() {
        return isTerminated;
      },
      postMessage(message: unknown, transfer?: Transferable[]) {
        if (Array.isArray(transfer)) {
          for (const item of transfer) {
            if (item instanceof ArrayBuffer) {
              new Uint8Array(item).fill(0);
            }
          }
        }
        if (isTerminated) return;
        const req = message as { type?: string; requestId?: string };
        if (req?.type !== 'GENERATE_PROOF' || typeof req.requestId !== 'string') {
          return;
        }
        const requestId = req.requestId;
        if (mode === 'malformed_message') {
          queueMicrotask(() => {
            if (!isTerminated) {
              worker.onmessageerror?.(new MessageEvent('messageerror'));
            }
          });
          return;
        }
        if (mode === 'interrupted_proving') {
          queueMicrotask(() => {
            if (isTerminated) return;
            worker.onmessage?.(
              new MessageEvent('message', {
                data: { type: 'PROGRESS', requestId, stage: 'loading_circuits' },
              })
            );
            worker.onmessage?.(
              new MessageEvent('message', {
                data: { type: 'PROGRESS', requestId, stage: 'executing_helper' },
              })
            );
            worker.onerror?.(new ErrorEvent('error', { message: 'Synthetic proving interrupted' }));
          });
          return;
        }
        queueMicrotask(() => {
          if (isTerminated) return;
          worker.onmessage?.(
            new MessageEvent('message', {
              data: { type: 'PROGRESS', requestId, stage: 'loading_circuits' },
            })
          );
          worker.onmessage?.(
            new MessageEvent('message', {
              data: { type: 'PROGRESS', requestId, stage: 'generating_proof' },
            })
          );
          worker.onmessage?.(
            new MessageEvent('message', {
              data: {
                type: 'RESULT',
                requestId,
                proof: {
                  credentialRoot: '0',
                  nullifier: '0',
                  proof: '00',
                  publicInputs: '[]',
                  proofBytes: 1,
                  publicInputBytes: 2,
                },
              },
            })
          );
        });
      },
      terminate() {
        isTerminated = true;
      },
    };

    spawnedWorkers.push(worker);
    return worker as unknown as Worker;
  };

  return { workerFactory, spawnedWorkers };
}

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

  runSyntheticCrashRecovery(
    faultMode: SyntheticWorkerFaultMode,
    fixture?: unknown
  ): SyntheticCrashRecoveryReport {
    const report = runSyntheticCrashRecoveryFixture(faultMode, fixture);
    logger.info('Completed synthetic worker crash-recovery rehearsal', {
      faultMode: report.faultMode,
      initialFailureCode: report.initialFailureCode,
      uiStage: report.uiAfterRecovery.uiStage,
    });
    return report;
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