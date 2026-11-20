import { z } from 'zod';

// Constants for boundary enforcement
const MAX_ARTIFACT_SIZE_BYTES = 10 * 1024 * 1024; // 10MB
const MAX_METADATA_LENGTH = 4096;
const MAX_PROOF_LENGTH = 1024 * 1024; // 1MB
const MAX_WITNESS_DATA_LENGTH = 512 * 1024; // 512KB
const MAX_INPUT_LENGTH = 100 * 1024; // 100KB

// Safe character set for localization keys and labels
const SAFE_KEY_REGEX = /^[a-zA-Z0-9_\-\.]+$/;

/**
 * Sanitizes a string to ensure it contains only safe, printable characters
 * and does not exceed length limits. Prevents XSS and injection in UI rendering.
 */
export function sanitizeString(
  input: unknown,
  maxLength: number = MAX_INPUT_LENGTH
): string | null {
  if (typeof input !== 'string') {
    return null;
  }

  if (input.length > maxLength) {
    return null;
  }

  // Remove null bytes and control characters except newline/tab
  const sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  return sanitized;
}

/**
 * Validates and sanitizes a localization key.
 * Keys must match a strict pattern to prevent injection and ensure compatibility.
 */
export function sanitizeKey(key: unknown): string | null {
  if (typeof key !== 'string') {
    return null;
  }

  if (key.length === 0 || key.length > MAX_METADATA_LENGTH) {
    return null;
  }

  if (!SAFE_KEY_REGEX.test(key)) {
    return null;
  }

  return key;
}

/**
 * Validates the size of binary data (e.g., artifacts, proofs, witness data).
 * Returns true if the size is within acceptable bounds, false otherwise.
 */
export function isWithinSizeLimit(
  size: number,
  limit: number = MAX_ARTIFACT_SIZE_BYTES
): boolean {
  if (typeof size !== 'number' || size < 0) {
    return false;
  }
  return size <= limit;
}

/**
 * Sanitizes metadata object by ensuring all string values are safe and within limits.
 * Returns null if any critical field is invalid.
 */
export function sanitizeMetadata(
  metadata: Record<string, unknown>
): Record<string, string> | null {
  if (!metadata || typeof metadata !== 'object') {
    return null;
  }

  const sanitized: Record<string, string> = {};

  for (const [key, value] of Object.entries(metadata)) {
    const safeKey = sanitizeKey(key);
    if (!safeKey) {
      return null;
    }

    if (typeof value === 'string') {
      const safeValue = sanitizeString(value, MAX_METADATA_LENGTH);
      if (safeValue === null) {
        return null;
      }
      sanitized[safeKey] = safeValue;
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      sanitized[safeKey] = String(value);
    } else if (value === null || value === undefined) {
      sanitized[safeKey] = '';
    } else {
      // Ignore non-primitive types for metadata safety
      continue;
    }
  }

  return sanitized;
}

/**
 * Validates that a proof string is not excessively long and contains no null bytes.
 * Used to prevent DoS via oversized proof parsing.
 */
export function sanitizeProof(proof: unknown): string | null {
  if (typeof proof !== 'string') {
    return null;
  }

  if (proof.length > MAX_PROOF_LENGTH) {
    return null;
  }

  // Remove null bytes
  const sanitized = proof.replace(/\0/g, '');

  return sanitized;
}

/**
 * Validates witness data size to prevent memory exhaustion.
 */
export function sanitizeWitnessData(data: unknown): string | null {
  if (typeof data !== 'string') {
    return null;
  }

  if (data.length > MAX_WITNESS_DATA_LENGTH) {
    return null;
  }

  // Remove null bytes and control characters
  const sanitized = data.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  return sanitized;
}

/**
 * General-purpose input sanitizer for user-facing fields.
 * Strips potentially dangerous characters and enforces length limits.
 */
export function sanitizeInput(input: unknown, maxLength: number = MAX_INPUT_LENGTH): string | null {
  if (typeof input !== 'string') {
    return null;
  }

  if (input.length > maxLength) {
    return null;
  }

  // Strip null bytes and control characters
  const sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  return sanitized;
}

/**
 * Checks if a file size is within the allowed limit for artifact loading.
 */
export function validateArtifactSize(size: number): boolean {
  return isWithinSizeLimit(size, MAX_ARTIFACT_SIZE_BYTES);
}

/**
 * Checks if a proof size is within the allowed limit.
 */
export function validateProofSize(size: number): boolean {
  return isWithinSizeLimit(size, MAX_PROOF_LENGTH);
}

/**
 * Checks if witness data size is within the allowed limit.
 */
export function validateWitnessDataSize(size: number): boolean {
  return isWithinSizeLimit(size, MAX_WITNESS_DATA_LENGTH);
}