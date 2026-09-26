import type { Evidence, Proof, Contract, Deployment } from './types';
import { HarpocratesError } from './errors';
import { Logger } from './logger';

/**
 * Localization Boundary Module
 *
 * This module enforces privacy-preserving, interoperable, and safe
 * handling of evidence, proofs, contracts, and deployments at the
 * frontend public boundaries.
 *
 * Trust-Boundary: All inputs are treated as untrusted. Outputs are
 * sanitized to prevent leakage of secrets, witness values, or private keys.
 *
 * Privacy: No real media, secrets, or private keys are logged or exposed.
 * Failure responses are stable and generic to avoid information leakage.
 */

const logger = Logger.getInstance('localization-boundary');

// Constants for validation
const MAX_EVIDENCE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_PROOF_SIZE = 5 * 1024 * 1024; // 5MB
const MAX_CONTRACT_SIZE = 2 * 1024 * 1024; // 2MB
const MAX_DEPLOYMENT_SIZE = 1 * 1024 * 1024; // 1MB
const MAX_ARTIFACT_SIZE = 50 * 1024 * 1024; // 50MB

/**
 * Sanitizes an object for safe logging or display.
 * Removes sensitive fields like private keys, secrets, and raw media.
 */
function sanitizeForDisplay<T extends Record<string, unknown>>(obj: T): Record<string, unknown> {
  const safe: Record<string, unknown> = {};
  const sensitiveKeys = new Set([
    'privateKey',
    'secret',
    'password',
    'token',
    'credential',
    'rawMedia',
    'witnessValue',
    'signature',
    'proofData',
  ]);

  for (const [key, value] of Object.entries(obj)) {
    if (sensitiveKeys.has(key)) {
      safe[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      safe[key] = sanitizeForDisplay(value as Record<string, unknown>);
    } else {
      safe[key] = value;
    }
  }

  return safe;
}

/**
 * Validates the size of a buffer or string.
 * Throws HarpocratesError if the size exceeds the limit.
 */
function validateSize(data: Buffer | string, maxSize: number, context: string): void {
  const size = typeof data === 'string' ? Buffer.byteLength(data, 'utf-8') : data.length;
  if (size > maxSize) {
    logger.warn(`Oversized ${context}: ${size} bytes exceeds limit of ${maxSize} bytes`);
    throw new HarpocratesError(
      `Input too large: ${context} exceeds maximum size of ${maxSize} bytes`,
      'OVERSIZED_INPUT'
    );
  }
}

/**
 * Validates that the input is well-formed JSON.
 * Throws HarpocratesError if parsing fails.
 */
function validateJson<T>(data: string, context: string): T {
  try {
    return JSON.parse(data) as T;
  } catch (error) {
    logger.warn(`Malformed JSON in ${context}: ${(error as Error).message}`);
    throw new HarpocratesError(
      `Invalid ${context} format`,
      'MALFORMED_INPUT'
    );
  }
}

/**
 * Validates that the evidence is not expired.
 * Throws HarpocratesError if the evidence is expired.
 */
function validateNotExpired(evidence: Evidence, context: string): void {
  if (evidence.expiry && new Date(evidence.expiry) < new Date()) {
    logger.warn(`Expired ${context}: ${context} expired at ${evidence.expiry}`);
    throw new HarpocratesError(
      `${context} has expired`,
      'EXPIRED_INPUT'
    );
  }
}

/**
 * Validates that the proof is not revoked.
 * Throws HarpocratesError if the proof is revoked.
 */
function validateNotRevoked(proof: Proof, context: string): void {
  if (proof.revoked) {
    logger.warn(`Revoked ${context}: ${context} is revoked`);
    throw new HarpocratesError(
      `${context} has been revoked`,
      'REVOKED_INPUT'
    );
  }
}

/**
 * Validates that the contract is supported.
 * Throws HarpocratesError if the contract is unsupported.
 */
function validateSupportedContract(contract: Contract, context: string): void {
  const supportedVersions = ['v1', 'v2'];
  if (!supportedVersions.includes(contract.version)) {
    logger.warn(`Unsupported ${context}: ${context} version ${contract.version} is not supported`);
    throw new HarpocratesError(
      `Unsupported ${context} version: ${contract.version}`,
      'UNSUPPORTED_INPUT'
    );
  }
}

/**
 * Validates that the deployment is valid.
 * Throws HarpocratesError if the deployment is invalid.
 */
function validateDeployment(deployment: Deployment, context: string): void {
  if (!deployment.contractAddress || !deployment.blockNumber) {
    logger.warn(`Invalid ${context}: ${context} missing required fields`);
    throw new HarpocratesError(
      `Invalid ${context} format`,
      'MALFORMED_INPUT'
    );
  }
}

/**
 * Validates an evidence object.
 * Throws HarpocratesError if the evidence is invalid.
 */
export function validateEvidence(evidence: Evidence): void {
  validateSize(evidence.data, MAX_EVIDENCE_SIZE, 'evidence');
  validateNotExpired(evidence, 'evidence');
  if (evidence.proof) {
    validateProof(evidence.proof);
  }
}

/**
 * Validates a proof object.
 * Throws HarpocratesError if the proof is invalid.
 */
export function validateProof(proof: Proof): void {
  validateSize(proof.data, MAX_PROOF_SIZE, 'proof');
  validateNotRevoked(proof, 'proof');
}

/**
 * Validates a contract object.
 * Throws HarpocratesError if the contract is invalid.
 */
export function validateContract(contract: Contract): void {
  validateSize(contract.data, MAX_CONTRACT_SIZE, 'contract');
  validateSupportedContract(contract, 'contract');
}

/**
 * Validates a deployment object.
 * Throws HarpocratesError if the deployment is invalid.
 */
export function validateDeployment(deployment: Deployment): void {
  validateSize(deployment.data, MAX_DEPLOYMENT_SIZE, 'deployment');
  validateDeployment(deployment, 'deployment');
}

/**
 * Validates an artifact object.
 * Throws HarpocratesError if the artifact is invalid.
 */
export function validateArtifact(data: Buffer | string): void {
  validateSize(data, MAX_ARTIFACT_SIZE, 'artifact');
}

/**
 * Parses and validates a JSON string as an evidence object.
 * Throws HarpocratesError if the JSON is malformed or the evidence is invalid.
 */
export function parseAndValidateEvidence(data: string): Evidence {
  const evidence = validateJson<Evidence>(data, 'evidence');
  validateEvidence(evidence);
  return evidence;
}

/**
 * Parses and validates a JSON string as a proof object.
 * Throws HarpocratesError if the JSON is malformed or the proof is invalid.
 */
export function parseAndValidateProof(data: string): Proof {
  const proof = validateJson<Proof>(data, 'proof');
  validateProof(proof);
  return proof;
}

/**
 * Parses and validates a JSON string as a contract object.
 * Throws HarpocratesError if the JSON is malformed or the contract is invalid.
 */
export function parseAndValidateContract(data: string): Contract {
  const contract = validateJson<Contract>(data, 'contract');
  validateContract(contract);
  return contract;
}

/**
 * Parses and validates a JSON string as a deployment object.
 * Throws HarpocratesError if the JSON is malformed or the deployment is invalid.
 */
export function parseAndValidateDeployment(data: string): Deployment {
  const deployment = validateJson<Deployment>(data, 'deployment');
  validateDeployment(deployment);
  return deployment;
}

/**
 * Sanitizes an error object for safe logging or display.
 * Removes sensitive fields from the error.
 */
export function sanitizeError(error: Error): Record<string, unknown> {
  return {
    name: error.name,
    message: error.message,
    code: (error as HarpocratesError).code,
    stack: error.stack,
  };
}

/**
 * Logs a sanitized version of an object.
 * Used for debugging without leaking sensitive information.
 */
export function logSanitized<T extends Record<string, unknown>>(label: string, obj: T): void {
  logger.debug(`${label}:`, sanitizeForDisplay(obj));
}

/**
 * Handles a dependency failure gracefully.
 * Logs the error and throws a HarpocratesError with a stable message.
 */
export function handleDependencyFailure(error: Error): never {
  logger.error('Dependency failure:', sanitizeError(error));
  throw new HarpocratesError(
    'Internal service error',
    'DEPENDENCY_FAILURE'
  );
}

/**
 * Checks if a cancellation has been requested.
 * Throws HarpocratesError if cancellation is detected.
 */
export function checkCancellation(signal: AbortSignal): void {
  if (signal.aborted) {
    logger.info('Operation cancelled');
    throw new HarpocratesError(
      'Operation cancelled',
      'CANCELLED'
    );
  }
}

/**
 * Validates keyboard input for safety.
 * Throws HarpocratesError if the input contains dangerous characters.
 */
export function validateKeyboardInput(input: string): void {
  const dangerousPatterns = /[<>"'&;(){}\[\]]/;
  if (dangerousPatterns.test(input)) {
    logger.warn('Dangerous characters detected in keyboard input');
    throw new HarpocratesError(
      'Invalid input',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates mobile behavior constraints.
 * Throws HarpocratesError if the input is not suitable for mobile.
 */
export function validateMobileInput(input: string): void {
  if (input.length > 1000) {
    logger.warn('Input too long for mobile');
    throw new HarpocratesError(
      'Input too long',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is not empty.
 * Throws HarpocratesError if the input is empty.
 */
export function validateNotEmpty<T>(input: T, context: string): void {
  if (input === null || input === undefined || (typeof input === 'string' && input.length === 0)) {
    logger.warn(`Empty ${context}`);
    throw new HarpocratesError(
      `Empty ${context}`,
      'EMPTY_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid URL.
 * Throws HarpocratesError if the input is not a valid URL.
 */
export function validateUrl(input: string): void {
  try {
    new URL(input);
  } catch (error) {
    logger.warn(`Invalid URL: ${input}`);
    throw new HarpocratesError(
      'Invalid URL',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid email.
 * Throws HarpocratesError if the input is not a valid email.
 */
export function validateEmail(input: string): void {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(input)) {
    logger.warn(`Invalid email: ${input}`);
    throw new HarpocratesError(
      'Invalid email',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid phone number.
 * Throws HarpocratesError if the input is not a valid phone number.
 */
export function validatePhoneNumber(input: string): void {
  const phoneRegex = /^\+?[1-9]\d{1,14}$/;
  if (!phoneRegex.test(input)) {
    logger.warn(`Invalid phone number: ${input}`);
    throw new HarpocratesError(
      'Invalid phone number',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid date.
 * Throws HarpocratesError if the input is not a valid date.
 */
export function validateDate(input: string): void {
  const date = new Date(input);
  if (isNaN(date.getTime())) {
    logger.warn(`Invalid date: ${input}`);
    throw new HarpocratesError(
      'Invalid date',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid number.
 * Throws HarpocratesError if the input is not a valid number.
 */
export function validateNumber(input: string): void {
  const number = Number(input);
  if (isNaN(number)) {
    logger.warn(`Invalid number: ${input}`);
    throw new HarpocratesError(
      'Invalid number',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid boolean.
 * Throws HarpocratesError if the input is not a valid boolean.
 */
export function validateBoolean(input: string): void {
  if (input !== 'true' && input !== 'false') {
    logger.warn(`Invalid boolean: ${input}`);
    throw new HarpocratesError(
      'Invalid boolean',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid string.
 * Throws HarpocratesError if the input is not a valid string.
 */
export function validateString(input: string): void {
  if (typeof input !== 'string') {
    logger.warn(`Invalid string: ${input}`);
    throw new HarpocratesError(
      'Invalid string',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid array.
 * Throws HarpocratesError if the input is not a valid array.
 */
export function validateArray(input: unknown[]): void {
  if (!Array.isArray(input)) {
    logger.warn(`Invalid array: ${input}`);
    throw new HarpocratesError(
      'Invalid array',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid object.
 * Throws HarpocratesError if the input is not a valid object.
 */
export function validateObject(input: Record<string, unknown>): void {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    logger.warn(`Invalid object: ${input}`);
    throw new HarpocratesError(
      'Invalid object',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid function.
 * Throws HarpocratesError if the input is not a valid function.
 */
export function validateFunction(input: Function): void {
  if (typeof input !== 'function') {
    logger.warn(`Invalid function: ${input}`);
    throw new HarpocratesError(
      'Invalid function',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid symbol.
 * Throws HarpocratesError if the input is not a valid symbol.
 */
export function validateSymbol(input: symbol): void {
  if (typeof input !== 'symbol') {
    logger.warn(`Invalid symbol: ${input}`);
    throw new HarpocratesError(
      'Invalid symbol',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid bigint.
 * Throws HarpocratesError if the input is not a valid bigint.
 */
export function validateBigInt(input: bigint): void {
  if (typeof input !== 'bigint') {
    logger.warn(`Invalid bigint: ${input}`);
    throw new HarpocratesError(
      'Invalid bigint',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid null.
 * Throws HarpocratesError if the input is not a valid null.
 */
export function validateNull(input: null): void {
  if (input !== null) {
    logger.warn(`Invalid null: ${input}`);
    throw new HarpocratesError(
      'Invalid null',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid undefined.
 * Throws HarpocratesError if the input is not a valid undefined.
 */
export function validateUndefined(input: undefined): void {
  if (input !== undefined) {
    logger.warn(`Invalid undefined: ${input}`);
    throw new HarpocratesError(
      'Invalid undefined',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid number.
 * Throws HarpocratesError if the input is not a valid number.
 */
export function validateNumberType(input: number): void {
  if (typeof input !== 'number') {
    logger.warn(`Invalid number: ${input}`);
    throw new HarpocratesError(
      'Invalid number',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid string.
 * Throws HarpocratesError if the input is not a valid string.
 */
export function validateStringType(input: string): void {
  if (typeof input !== 'string') {
    logger.warn(`Invalid string: ${input}`);
    throw new HarpocratesError(
      'Invalid string',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid boolean.
 * Throws HarpocratesError if the input is not a valid boolean.
 */
export function validateBooleanType(input: boolean): void {
  if (typeof input !== 'boolean') {
    logger.warn(`Invalid boolean: ${input}`);
    throw new HarpocratesError(
      'Invalid boolean',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid object.
 * Throws HarpocratesError if the input is not a valid object.
 */
export function validateObjectType(input: object): void {
  if (typeof input !== 'object' || input === null) {
    logger.warn(`Invalid object: ${input}`);
    throw new HarpocratesError(
      'Invalid object',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid array.
 * Throws HarpocratesError if the input is not a valid array.
 */
export function validateArrayType(input: unknown[]): void {
  if (!Array.isArray(input)) {
    logger.warn(`Invalid array: ${input}`);
    throw new HarpocratesError(
      'Invalid array',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid function.
 * Throws HarpocratesError if the input is not a valid function.
 */
export function validateFunctionType(input: Function): void {
  if (typeof input !== 'function') {
    logger.warn(`Invalid function: ${input}`);
    throw new HarpocratesError(
      'Invalid function',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid symbol.
 * Throws HarpocratesError if the input is not a valid symbol.
 */
export function validateSymbolType(input: symbol): void {
  if (typeof input !== 'symbol') {
    logger.warn(`Invalid symbol: ${input}`);
    throw new HarpocratesError(
      'Invalid symbol',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid bigint.
 * Throws HarpocratesError if the input is not a valid bigint.
 */
export function validateBigIntType(input: bigint): void {
  if (typeof input !== 'bigint') {
    logger.warn(`Invalid bigint: ${input}`);
    throw new HarpocratesError(
      'Invalid bigint',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid null.
 * Throws HarpocratesError if the input is not a valid null.
 */
export function validateNullType(input: null): void {
  if (input !== null) {
    logger.warn(`Invalid null: ${input}`);
    throw new HarpocratesError(
      'Invalid null',
      'INVALID_INPUT'
    );
  }
}

/**
 * Validates that the input is a valid undefined.
 * Throws HarpocratesError if the input is not a valid undefined.
 */
export function validateUndefinedType(input: undefined): void {
  if (input !== undefined) {
    logger.warn(`Invalid undefined: ${input}`);
    throw new HarpocratesError(
      'Invalid undefined',
      'INVALID_INPUT'
    );
  }
}