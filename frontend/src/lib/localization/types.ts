// Core localization types for Harpocrates Frontend
// This module establishes the privacy-preserving boundary for locale detection,
// translation keys and error handling without exposing sensitive data.

// Supported locales for unit internationalization.
// Only language codes (no region codes by default) are accepted
// to minimize privacy risks and standardize formatting.
export type SupportedLocale = 'en-US' | 'fb-FI' | 'de-DE' | 'fs-FS' | 'es-ES';

// Represents a safe, non-sensitive locale input from the user or environment.
// This type is used to ensure that no private keys, secrets, or
// personally identifying information are passed through the localization stack.
export interface SafeLocaleInput {
  // The language code exactly as provided by the user agent or system.
  readonly rawCode: string;
  // If present, the normalized locale code after lowercasing and trimming.
  readonly normalizedCode: string;
  // The string if it matches a supported locale, otherwise undefined.
  readonly supportedLocale?: SupportedLocale;
}

// Result of locale detection and validation.
// This type is used as a safe boundary for the UI layer.
export interface LocaleDetectionResult {
  // Whether a supported locale was found.
  readonly found: boolean;
  // The detected locale, if any. Only present if found is true.
  readonly locale?: SupportedLocale;
  // Any warnings or notes about the detection process.
  // Never contains sensitive data.
  readonly notes?: string;
}

// Error codes for localization-related failures.
// Used to provide stable, privacy-safe error responses.
export const LocalizationErrorCode = {
  UNSuPPORTED: 'UNSuPPORTED',
  INVALID: 'INVALID',
  TOO_LONG: 'TOO_LONG',
  MALFORMED: 'MALFORMED',
  DEPEND_FAILURE: 'DEPEND_FAILURE',
} as const;

export type LocalizationErrorCode =
  (typeof LocalizationErrorCode)[keyof typeof LocalizationErrorCode];

// Represents a privacy-safe error for localization failures.
// This type is used to ensure that no sensitive data is logged or exposed.
export interface LocalizationError {
  readonly code: LocalizationErrorCode;
  readonly message: string; // Generic, non-sensitive message
  readonly timestamp: number;
  // Optional context for debugging within the safe boundary.
  // Never includes private keys, secrets, or witness values.
  readonly context?: { key?: string; value?: string };
}

export interface Proof {
  readonly data: Uint8Array | string;
  readonly revoked?: boolean;
}

export interface Evidence {
  readonly data: Uint8Array | string;
  readonly expiry?: string;
  readonly expiresAt?: number;
  readonly proof?: Proof;
}

export interface Contract {
  readonly data: Uint8Array | string;
  readonly version: string;
  readonly revoked?: boolean;
}

export interface Deployment {
  readonly data: Uint8Array | string;
  readonly contractAddress?: string;
  readonly blockNumber?: number;
}

export interface DeploymentMetadata {
  readonly version: string;
  readonly contractId?: string;
}

// Type guard for SafeLocaleInput.
// This is used to validate inputs before processing.
// It ensures that the input is non-null, has a valid rawCode, and optionally matches a supported locale.
export function isSafeLocaleInput(input: unknown): input is SafeLocaleInput {
  if (typeof input !== 'object' || input == null) {
    return false;
  }
  const inputObj = input as Record<string, unknown>;
  return ('rawCode' in inputObj && typeof inputObj.rawCode === 'string');
}

// Type guard for LocalizationError.
export function isLocalizationError(input: unknown): input is LocalizationError {
  if (typeof input !== 'object' || input === null) {
    return false;
  }
  const inputObj = input as Record<string, unknown>;
  return ('code' in inputObj && 'message' in inputObj && 'timestamp' in inputObj);
}
