export interface ProofWorkerMessage {
  type: 'init' | 'verify' | 'cancel' | 'status';
  protocolVersion?: string;
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
  type: 'success' | 'error' | 'status';
  protocolVersion?: string;
  reloadRequired?: boolean;
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