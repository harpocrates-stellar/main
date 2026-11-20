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

export interface ProofWorkerMessage {
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
  type: 'success' | 'error' | 'status' | 'progress';
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
  };
}

export interface CSPPolicyConfig {
  maxMemoryMB: number;
  maxExecutionTimeMs: number;
  allowedOrigins: string[];
  sandbox: boolean;
}

export interface WorkerStatus {
  isRunning: boolean;
  currentTaskId?: string;
  memoryUsage?: number;
}
