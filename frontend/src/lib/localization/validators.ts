import type { Evidence, Proof, Contract, DeploymentMetadata } from './types';

/**
 * Validation constants for localization boundaries.
 * Ensures privacy-preserving checks at public interfaces.
 */
const MAX_ARTIFACT_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_PROOF_SIZE = 1 * 1024 * 1024; // 1MB
const SUPPORTED_VERSIONS = ['1.0.0', '1.1.0', '1.2.0'];
const EXPIRY_BUFFER_MS = 5 * 60 * 1000; // 5 minutes buffer for clock skew

/**
 * Result of a validation check.
 */
export interface ValidationResult {
  valid: boolean;
  error?: string;
  sanitized?: Record<string, unknown>;
}

/**
 * Validates that the input is not null, undefined, or empty.
 * Privacy-safe: does not log the actual value.
 */
export function validatePresence<T>(value: T, fieldName: string): ValidationResult {
  if (value === null || value === undefined) {
    return {
      valid: false,
      error: `Missing required field: ${fieldName}`,
    };
  }
  if (typeof value === 'string' && value.trim() === '') {
    return {
      valid: false,
      error: `Empty field: ${fieldName}`,
    };
  }
  return { valid: true };
}

/**
 * Validates artifact size to prevent DoS via oversized inputs.
 * Privacy-safe: logs size, not content.
 */
export function validateArtifactSize(data: Uint8Array | string, fieldName: string): ValidationResult {
  const size = typeof data === 'string' ? new TextEncoder().encode(data).length : data.length;
  if (size > MAX_ARTIFACT_SIZE) {
    return {
      valid: false,
      error: `Artifact too large: ${size} bytes (max ${MAX_ARTIFACT_SIZE})`,
    };
  }
  return { valid: true };
}

/**
 * Validates proof size to prevent DoS.
 */
export function validateProofSize(proof: Proof): ValidationResult {
  const proofStr = JSON.stringify(proof);
  const size = new TextEncoder().encode(proofStr).length;
  if (size > MAX_PROOF_SIZE) {
    return {
      valid: false,
      error: `Proof too large: ${size} bytes (max ${MAX_PROOF_SIZE})`,
    };
  }
  return { valid: true };
}

/**
 * Validates that the version is supported.
 */
export function validateVersion(version: string): ValidationResult {
  if (!SUPPORTED_VERSIONS.includes(version)) {
    return {
      valid: false,
      error: `Unsupported version: ${version}. Supported: ${SUPPORTED_VERSIONS.join(', ')}`,
    };
  }
  return { valid: true };
}

/**
 * Validates that the evidence has not expired.
 * Privacy-safe: uses current time, does not log timestamps.
 */
export function validateNotExpired(evidence: Evidence): ValidationResult {
  const now = Date.now();
  const expiry = evidence.expiresAt;
  if (!expiry) {
    return { valid: true };
  }
  if (expiry < now - EXPIRY_BUFFER_MS) {
    return {
      valid: false,
      error: 'Evidence has expired',
    };
  }
  return { valid: true };
}

/**
 * Validates that the contract is not revoked.
 */
export function validateNotRevoked(contract: Contract): ValidationResult {
  if (contract.revoked) {
    return {
      valid: false,
      error: 'Contract has been revoked',
    };
  }
  return { valid: true };
}

/**
 * Sanitizes evidence for logging, removing sensitive fields.
 * Privacy-safe: ensures no secrets, keys, or private media are logged.
 */
export function sanitizeEvidenceForLogging(evidence: Evidence): Record<string, unknown> {
  const { privateKey, secret, media, witnessValue, ...safeEvidence } = evidence as any;
  return safeEvidence;
}

/**
 * Validates a deployment metadata object.
 */
export function validateDeploymentMetadata(metadata: DeploymentMetadata): ValidationResult {
  const versionCheck = validateVersion(metadata.version);
  if (!versionCheck.valid) {
    return versionCheck;
  }
  const presenceCheck = validatePresence(metadata.contractId, 'contractId');
  if (!presenceCheck.valid) {
    return presenceCheck;
  }
  return { valid: true };
}

/**
 * Main validation entry point for evidence.
 * Returns a combined result or the first failure.
 */
export function validateEvidence(evidence: Evidence): ValidationResult {
  const presence = validatePresence(evidence, 'evidence');
  if (!presence.valid) return presence;

  const size = validateArtifactSize(evidence.data, 'evidence.data');
  if (!size.valid) return size;

  const expiry = validateNotExpired(evidence);
  if (!expiry.valid) return expiry;

  return { valid: true };
}

/**
 * Validates a proof object.
 */
export function validateProof(proof: Proof): ValidationResult {
  const presence = validatePresence(proof, 'proof');
  if (!presence.valid) return presence;

  const size = validateProofSize(proof);
  if (!size.valid) return size;

  return { valid: true };
}

/**
 * Validates a contract object.
 */
export function validateContract(contract: Contract): ValidationResult {
  const presence = validatePresence(contract, 'contract');
  if (!presence.valid) return presence;

  const revoked = validateNotRevoked(contract);
  if (!revoked.valid) return revoked;

  return { valid: true };
}