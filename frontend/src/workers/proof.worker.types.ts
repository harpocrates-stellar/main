export interface WorkerOwnershipToken {
  /** Monotonic generation of the worker/operation epoch. */
  generation: number;
  /** Unique operation identifier owned by this generation. */
  operationId: string;
}

export interface StaleMessageRejection {
  accepted: false;
  reason: 'stale_generation' | 'cancelled' | 'unowned_operation' | 'not_initialized';
  expectedGeneration: number;
  receivedGeneration?: number;
}

export type WorkerMessageDispatchResult =
  | { accepted: true; generation: number; operationId: string }
  | StaleMessageRejection;

export type WorkerTeardownStatus = 'confirmed' | 'forced';

export interface WorkerTeardownOptions {
  /**
   * Bounded interval (in milliseconds) to wait for an explicit `teardown_ack`
   * after cancellation before forcibly terminating the worker.
   * Must be a positive finite number.
   */
  timeoutMs?: number;
}

export interface WorkerTeardownResult {
  /** Distinguishes confirmed resource cleanup from forced termination. */
  status: WorkerTeardownStatus;
  /** True when the worker acknowledged teardown within the bounded interval. */
  confirmed: boolean;
  /** True when the bounded interval elapsed and the worker was forcibly terminated. */
  forced: boolean;
  /** Monotonic generation associated with the teardown request. */
  generation: number;
  /** Identifier of the cancel/teardown request. */
  cancelId: string;
  /** Bounded interval (in milliseconds) used for the teardown wait. */
  timeoutMs: number;
}

export interface ProofWorkerMessage {
  protocolVersion?: number;
  type: 'init' | 'verify' | 'cancel' | 'status';
  payload?: {
    evidence?: string;
    proof?: string;
    contract?: string;
    metadata?: Record<string, unknown>;
    timeout?: number;
  };
  id?: string;
  generation?: number;
}

export interface ProofWorkerResponse {
  type: 'success' | 'error' | 'status' | 'progress' | 'teardown_ack';
  id?: string;
  generation?: number;
  data?: {
    valid?: boolean;
    result?: unknown;
    message?: string;
    stage?: string;
    percent?: number;
  };
  error?: {
    code: string;
    message: string;
    privacySafe: boolean;
    reloadRequired?: boolean;
  };
}

export interface CSPPolicyConfig {
  maxMemoryMB: number;
  maxExecutionTimeMs: number;
  allowedOrigins: string[];
  sandbox: boolean;
}

export type {
  ProofWorkerAdmissionReasonCode,
  ProofWorkerExecutionMode,
  ProofWorkerResourceAdmissionDecision,
  ProofWorkerResourceAdmissionInput,
} from '../proofWorkerMemory';

export interface WorkerStatus {
  isRunning: boolean;
  currentTaskId?: string;
  memoryUsage?: number;
}
