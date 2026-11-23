export const PROOF_WORKER_PROTOCOL_VERSION = 1 as const;

export type ProofWorkerProtocolVersion = typeof PROOF_WORKER_PROTOCOL_VERSION;

export type WorkerProtocolVersionCheckResult =
  | {
      readonly compatible: true;
      readonly protocolVersion: number;
      readonly reloadRequired: false;
    }
  | {
      readonly compatible: false;
      readonly code: 'PROTOCOL_VERSION_MISMATCH';
      readonly expectedVersion: number;
      readonly receivedVersion: number | null;
      readonly reloadRequired: true;
      readonly message: string;
      readonly privacySafe: true;
    };

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
}

export interface ProofWorkerResponse {
  protocolVersion?: number;
  type: 'success' | 'error' | 'status';
  id?: string;
  data?: {
    valid?: boolean;
    result?: unknown;
    message?: string;
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
