import type {
  CSPPolicyConfig,
  ProofWorkerMessage,
  ProofWorkerResponse,
  WorkerStatus,
} from './proof.worker.types';
import { ProofWorkerLogger } from './proof-worker-logger';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import {
  assessWorkerSupport,
  detectWorkerCapabilities,
  type WorkerCapabilityId,
  type WorkerCapabilitySnapshot,
  type WorkerSupportTier,
} from './multiBrowserWorkerSupport';
import {
  inspectProofWorkerArtifactMetadata,
  type BrowserArtifactManifestLike,
  type ProofWorkerArtifactMetadataReport,
} from '../proofWorkerMemory';

export interface OfflineWorkerCapabilityReport {
  readonly offline: true;
  readonly ready: boolean;
  readonly browser: {
    readonly ok: boolean;
    readonly tier: WorkerSupportTier;
    readonly capabilities: WorkerCapabilitySnapshot;
    readonly missing: readonly WorkerCapabilityId[];
    readonly reason: string;
  };
  readonly artifacts: ProofWorkerArtifactMetadataReport;
  readonly csp: {
    readonly sandbox: boolean;
    readonly maxMemoryMB: number;
    readonly maxExecutionTimeMs: number;
    readonly allowedOriginsCount: number;
  };
  readonly issues: readonly string[];
}

export interface OfflineWorkerCapabilityReportOptions {
  globalObj?: typeof globalThis;
  cspConfig?: Partial<CSPPolicyConfig>;
  manifest?: BrowserArtifactManifestLike;
}

/**
 * Build an offline capability report for browser proof workers.
 * Inspects required browser features and configured artifact metadata
 * without spawning a worker, loading proving artifacts, or contacting network endpoints.
 */
export function buildOfflineWorkerCapabilityReport(
  options: OfflineWorkerCapabilityReportOptions = {}
): OfflineWorkerCapabilityReport {
  const cspConfig = validateCSPPolicy(options.cspConfig || {});
  const capabilities = detectWorkerCapabilities(options.globalObj);
  const assessment = assessWorkerSupport(options.globalObj);
  const artifacts = inspectProofWorkerArtifactMetadata(options.manifest);

  const issues: string[] = [];
  if (!assessment.ok) {
    issues.push(assessment.reason);
  }
  if (artifacts.publishedArtifactCount === 0) {
    issues.push('No published proving artifacts configured in manifest.');
  }
  if (!artifacts.allArtifactsWithinLimit) {
    issues.push('One or more configured proving artifacts exceed the worker artifact byte limit.');
  }
  const cspMemoryBudgetBytes = cspConfig.maxMemoryMB * 1024 * 1024;
  if (artifacts.totalPublishedArtifactBytes > cspMemoryBudgetBytes) {
    issues.push('Configured proving artifact metadata exceeds CSP maxMemoryMB budget.');
  }

  return Object.freeze({
    offline: true,
    ready: issues.length === 0,
    browser: Object.freeze({
      ok: assessment.ok,
      tier: assessment.tier,
      capabilities,
      missing: assessment.missing,
      reason: assessment.reason,
    }),
    artifacts,
    csp: Object.freeze({
      sandbox: cspConfig.sandbox,
      maxMemoryMB: cspConfig.maxMemoryMB,
      maxExecutionTimeMs: cspConfig.maxExecutionTimeMs,
      allowedOriginsCount: cspConfig.allowedOrigins.length,
    }),
    issues: Object.freeze(issues),
  });
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
      type: 'cancel',
      id: messageId,
    };

    logger.info('Sending cancel message', { id: messageId });
    // In a real implementation, this would post to the actual worker
    // this.worker?.postMessage(message);
  }

  getStatus(): WorkerStatus {
    return {
      isRunning: false, // In a real implementation, this would check the actual worker state
      currentTaskId: undefined,
      memoryUsage: undefined,
    };
  }

  getOfflineCapabilityReport(
    options: Omit<OfflineWorkerCapabilityReportOptions, 'cspConfig'> = {}
  ): OfflineWorkerCapabilityReport {
    return buildOfflineWorkerCapabilityReport({
      ...options,
      cspConfig: this.cspConfig,
    });
  }

  getCSPHeaders(): Record<string, string> {
    return createCSPHeaders(this.cspConfig);
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