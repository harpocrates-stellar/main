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
const textEncoder = new TextEncoder();

export const PROOF_WORKER_DIAGNOSTIC_MAX_BYTES = PROOF_WORKER_MEMORY_LIMITS.maxDiagnosticBytes;

export type ProofWorkerDiagnosticLevel = 'debug' | 'info' | 'warn' | 'error';

export interface ProofWorkerDiagnosticInput {
  level?: ProofWorkerDiagnosticLevel;
  stage?: string;
  errorCode?: string;
  code?: string;
  id?: string;
  message?: string;
  context?: Record<string, unknown>;
}

export interface BoundedProofWorkerDiagnostic {
  level: ProofWorkerDiagnosticLevel;
  stage: string;
  errorCode?: string;
  code?: string;
  id?: string;
  message: string;
  context?: Record<string, unknown>;
  redactedWitnessValues: number;
  truncated: boolean;
  byteLength: number;
}

const WITNESS_KEY_PATTERN =
  /(witness|credential_?secret|nullifier_?secret|private_?inputs?|secret|seed|evidence|proof|assignment|nullifier|commitment)/i;

const SAFE_DIAGNOSTIC_KEYS = new Set([
  'stage',
  'errorCode',
  'code',
  'id',
  'level',
  'event',
  'status',
  'ok',
  'retryable',
  'duration_ms',
  'durationMs',
  'reason',
  'component',
]);

function utf8ByteLength(value: string): number {
  return textEncoder.encode(value).byteLength;
}

function truncateUtf8(value: string, maxBytes: number): string {
  if (maxBytes <= 0) return '';
  if (utf8ByteLength(value) <= maxBytes) return value;
  const suffix = '...[truncated]';
  const suffixBytes = utf8ByteLength(suffix);
  if (maxBytes <= suffixBytes) {
    let out = '';
    for (const ch of value) {
      if (utf8ByteLength(out + ch) > maxBytes) break;
      out += ch;
    }
    return out;
  }
  const budget = maxBytes - suffixBytes;
  let out = '';
  for (const ch of value) {
    if (utf8ByteLength(out + ch) > budget) break;
    out += ch;
  }
  return out + suffix;
}

function redactWitnessTokensInString(raw: string): { text: string; count: number } {
  let count = 0;
  let text = raw.replace(
    /\b(witness|credential_?secret|nullifier_?secret|private_?inputs?|secret|seed|evidence|proof|assignment)\s*([:=])\s*([^\s,;}\]]+)/gi,
    (_match, key: string, sep: string) => {
      count += 1;
      return `${key}${sep}[REDACTED:witness]`;
    },
  );
  text = text.replace(/\b0x[0-9a-fA-F]{16,}\b/g, () => {
    count += 1;
    return '[REDACTED:witness]';
  });
  text = text.replace(/\b[0-9a-fA-F]{32,}\b/g, () => {
    count += 1;
    return '[REDACTED:witness]';
  });
  text = text.replace(/\b\d{20,}\b/g, () => {
    count += 1;
    return '[REDACTED:witness]';
  });
  return { text, count };
}

function isWitnessShapedArray(value: unknown[]): boolean {
  if (value.length === 0) return false;
  if (value.some((item) => typeof item === 'bigint' || item instanceof ArrayBuffer || ArrayBuffer.isView(item))) {
    return true;
  }
  if (
    value.length >= 4 &&
    value.every(
      (item) =>
        typeof item === 'number' ||
        (typeof item === 'string' && (/^(0x)?[0-9a-fA-F]{16,}$/.test(item) || /^\d{20,}$/.test(item))),
    )
  ) {
    return true;
  }
  return false;
}

function redactWitnessValue(
  value: unknown,
  counter: { count: number },
  key?: string,
  depth = 0,
): unknown {
  if (key && !SAFE_DIAGNOSTIC_KEYS.has(key) && WITNESS_KEY_PATTERN.test(key)) {
    counter.count += 1;
    return '[REDACTED:witness]';
  }
  if (value === null || value === undefined) return value;
  if (typeof value === 'bigint' || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    counter.count += 1;
    return '[REDACTED:witness]';
  }
  if (typeof value === 'string') {
    const redacted = redactWitnessTokensInString(value);
    counter.count += redacted.count;
    return redacted.text;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= 6) return '[REDACTED:depth_limit]';
  if (Array.isArray(value)) {
    if (isWitnessShapedArray(value)) {
      counter.count += 1;
      return '[REDACTED:witness_array]';
    }
    return value.slice(0, 32).map((item) => redactWitnessValue(item, counter, undefined, depth + 1));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactWitnessValue(v, counter, k, depth + 1);
    }
    return out;
  }
  return String(value);
}

function normalizeIdentifier(value: string | undefined, fallback?: string): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return fallback;
  return trimmed.slice(0, 128);
}

/**
 * Redacts witness-shaped values, preserves stable stage and error identifiers,
 * and caps the serialized UTF-8 payload byte length before forwarding a
 * proof-worker diagnostic to telemetry.
 */
export function boundProofWorkerDiagnostic(
  input: ProofWorkerDiagnosticInput,
  options?: { maxBytes?: number },
): BoundedProofWorkerDiagnostic {
  const requestedMax = options?.maxBytes ?? PROOF_WORKER_DIAGNOSTIC_MAX_BYTES;
  const maxBytes =
    Number.isFinite(requestedMax) && requestedMax > 0
      ? Math.floor(requestedMax)
      : PROOF_WORKER_DIAGNOSTIC_MAX_BYTES;

  const counter = { count: 0 };
  const level: ProofWorkerDiagnosticLevel = input.level ?? 'info';
  const stage = normalizeIdentifier(input.stage, 'unknown') ?? 'unknown';
  const errorCode = normalizeIdentifier(input.errorCode);
  const code = normalizeIdentifier(input.code);
  const id = normalizeIdentifier(input.id);

  const redactedMessage = redactWitnessTokensInString(input.message ?? '');
  counter.count += redactedMessage.count;
  let message = redactedMessage.text;

  let context: Record<string, unknown> | undefined;
  if (input.context && Object.keys(input.context).length > 0) {
    const witnessRedacted = redactWitnessValue(input.context, counter) as Record<string, unknown>;
    const scrubbed = scrubTelemetryFields(witnessRedacted);
    if (scrubbed.data && typeof scrubbed.data === 'object' && !Array.isArray(scrubbed.data)) {
      context = scrubbed.data as Record<string, unknown>;
    }
  }

  let truncated = false;
  const buildEnvelope = (
    msg: string,
    ctx: Record<string, unknown> | undefined,
    isTruncated: boolean,
    bytes: number,
  ): BoundedProofWorkerDiagnostic => {
    const env: BoundedProofWorkerDiagnostic = {
      level,
      stage,
      ...(errorCode ? { errorCode } : {}),
      ...(code ? { code } : {}),
      ...(id ? { id } : {}),
      message: msg,
      ...(ctx ? { context: ctx } : {}),
      redactedWitnessValues: counter.count,
      truncated: isTruncated,
      byteLength: bytes,
    };
    return env;
  };

  let envelope = buildEnvelope(message, context, false, 0);
  let serializedBytes = utf8ByteLength(JSON.stringify(envelope));
  envelope = buildEnvelope(message, context, false, serializedBytes);
  serializedBytes = utf8ByteLength(JSON.stringify(envelope));
  envelope.byteLength = serializedBytes;

  if (serializedBytes > maxBytes) {
    truncated = true;
    // First drop bulky context while retaining stable stage & error identifiers.
    context = undefined;
    envelope = buildEnvelope(message, undefined, true, 0);
    serializedBytes = utf8ByteLength(JSON.stringify(envelope));

    if (serializedBytes > maxBytes) {
      const overheadBytes = utf8ByteLength(
        JSON.stringify(buildEnvelope('', undefined, true, maxBytes)),
      );
      const messageBudget = Math.max(0, maxBytes - overheadBytes);
      message = truncateUtf8(message, messageBudget);
    }

    envelope = buildEnvelope(message, undefined, truncated, 0);
    serializedBytes = utf8ByteLength(JSON.stringify(envelope));
    envelope = buildEnvelope(message, undefined, truncated, serializedBytes);
    serializedBytes = utf8ByteLength(JSON.stringify(envelope));
    envelope.byteLength = serializedBytes;
  }

  return envelope;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Strictly validate a worker/main-thread protocol version without fallback parsing.
 * Rejects missing, non-integer, stringified, or mismatched versions fail-closed.
 */
export function validateWorkerProtocolVersion(
  receivedVersion: unknown,
  expectedVersion: number = PROOF_WORKER_PROTOCOL_VERSION
): WorkerProtocolVersionCheckResult {
  const isValidInteger =
    typeof receivedVersion === 'number' &&
    Number.isSafeInteger(receivedVersion) &&
    receivedVersion > 0;

  if (!isValidInteger) {
    return Object.freeze({
      compatible: false,
      code: 'PROTOCOL_VERSION_MISMATCH',
      expectedVersion,
      receivedVersion: null,
      reloadRequired: true,
      message: `Incompatible worker protocol version (expected ${expectedVersion}, received unknown). Reload required.`,
      privacySafe: true,
    });
  }

  if (receivedVersion !== expectedVersion) {
    return Object.freeze({
      compatible: false,
      code: 'PROTOCOL_VERSION_MISMATCH',
      expectedVersion,
      receivedVersion,
      reloadRequired: true,
      message: `Incompatible worker protocol version (expected ${expectedVersion}, received ${receivedVersion}). Reload required.`,
      privacySafe: true,
    });
  }

  return Object.freeze({
    compatible: true,
    protocolVersion: expectedVersion,
    reloadRequired: false,
  });
}

export function createProtocolMismatchResponse(
  check: Extract<WorkerProtocolVersionCheckResult, { compatible: false }>,
  id?: string
): ProofWorkerResponse {
  return {
    type: 'error',
    protocolVersion: check.expectedVersion,
    ...(id !== undefined ? { id } : {}),
    error: {
      code: check.code,
      message: check.message,
      privacySafe: true,
      reloadRequired: true,
    },
  };
}

export class ProofWorkerManager {
  // Preserve the currently active proof result to avoid losing state on unexpected messages
  private activeProofResult: ProofWorkerResponse | null = null;

  private worker: Worker | null = null;
  private cspConfig: ReturnType<typeof validateCSPPolicy>;
  private messageHandlers: Map<string, (response: ProofWorkerResponse) => void> = new Map();
  private isInitialized = false;
  private readonly protocolVersion = PROOF_WORKER_PROTOCOL_VERSION;

  constructor(config?: Partial<ReturnType<typeof validateCSPPolicy>>) {
    this.cspConfig = validateCSPPolicy(config || {});
  }

  async init(origin?: string): Promise<void> {

  }
    if (this.isInitialized) {
      logger.warn('Worker already initialized');
      return;
    }

    if (origin && !isOriginAllowed(origin, this.cspConfig)) {
      throw new Error(`Origin not allowed: ${origin}`);
    }

    try {
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
        protocolVersion: this.protocolVersion,
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
      this.worker?.postMessage(message);
    });
  }

  /** Registers a transient buffer so it is wiped when the session completes or is reused. */
  trackBuffer<T extends ArrayBuffer | ArrayBufferView>(buffer: T): T {
    return this.bufferLedger.track(buffer);
  }

  /** Releases a buffer once it has been transferred or exported. */
  releaseBuffer(buffer: ArrayBuffer | ArrayBufferView): void {
    this.bufferLedger.release(buffer);
  }

  async cancelProof(): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('Worker manager not initialized');
    }

    const messageId = `cancel_${Date.now()}`;

    const message: ProofWorkerMessage = {
      protocolVersion: this.protocolVersion,
      type: 'cancel',
      id: messageId,
    };

    logger.info('Sending cancel message', { id: messageId });
    this.worker?.postMessage(message);
  }

  getProtocolVersion(): number {
    return this.protocolVersion;
  }

  /**
   * Validate an incoming worker message's protocol version before accepting any
   * transferred buffers or parsing payload fields. Returns a clear reload-required
   * error response on mismatch and settles any matching pending request.
   */
  handleWorkerMessage(
    rawMessage: unknown,
    acceptBuffers?: () => readonly ArrayBuffer[]
  ): ProofWorkerResponse {
    const candidate = isRecord(rawMessage) ? rawMessage : null;
    const id = candidate && typeof candidate.id === 'string' ? candidate.id : undefined;
    const check = validateWorkerProtocolVersion(
      candidate ? candidate.protocolVersion : undefined,
      this.protocolVersion
    );

    if (!check.compatible) {
      logger.warn('Rejected incompatible worker protocol version', {
        expectedVersion: check.expectedVersion,
        receivedVersion: check.receivedVersion,
        reloadRequired: true,
      });
      const mismatchResponse = createProtocolMismatchResponse(check, id);
      if (id !== undefined) {
        const handler = this.messageHandlers.get(id);
        handler?.(mismatchResponse);
      }
      return mismatchResponse;
    }

    // Protocol version verified: safe to accept transferred buffers and dispatch.
    acceptBuffers?.();
    const response = candidate as unknown as ProofWorkerResponse;
    if (id !== undefined) {
      const handler = this.messageHandlers.get(id);
      handler?.(response);
    }
    return response;
  }

  getStatus(): WorkerStatus {
    return {
      isRunning: false,
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

  forwardDiagnosticToTelemetry(
    diagnostic: ProofWorkerDiagnosticInput,
    options?: { maxBytes?: number; emit?: typeof emitScrubbedTelemetry },
  ): BoundedProofWorkerDiagnostic {
    const bounded = boundProofWorkerDiagnostic(diagnostic, { maxBytes: options?.maxBytes });
    const sink = options?.emit ?? emitScrubbedTelemetry;
    sink(bounded.level, 'proof_worker.diagnostic', { ...bounded });
    return bounded;
  }

  destroy(): void {
    this.bufferLedger.clear();
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.messageHandlers.clear();
    this.isInitialized = false;
    logger.info('Worker manager destroyed');
  }
}
