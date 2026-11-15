export interface ProofWorkerMessage {
  type: 'init' | 'verify' | 'cancel' | 'status' | 'teardown';
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
  type: 'success' | 'error' | 'status' | 'teardown_ack';
  id?: string;
  data?: {
    valid?: boolean;
    result?: unknown;
    message?: string;
    resourcesCleaned?: boolean;
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