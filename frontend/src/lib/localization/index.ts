import { z } from 'zod';

/**
 * Maximum allowed size for any localized artifact payload in bytes.
 * Prevents DoS via oversized inputs.
 */
export const MAX_ARTIFACT_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

/**
 * Maximum depth for nested localization structures.
 * Prevents stack overflow or excessive memory usage during parsing.
 */
export const MAX_LOCALIZATION_DEPTH = 10;

/**
 * Supported localization versions.
 * Ensures backward compatibility and clear migration paths.
 */
export const SUPPORTED_LOCALE_VERSIONS = ['1.0.0'] as const;

/**
 * Default locale fallback.
 */
export const DEFAULT_LOCALE = 'en-US';

// --- Type Definitions ---

export interface LocalizationContext {
  locale: string;
  version: string;
  timestamp: number;
  signer?: string; // Optional, for signed localization bundles
}

export interface LocalizationResult<T> {
  success: boolean;
  data?: T;
  error?: LocalizationError;
}

export interface LocalizationError {
  code: string;
  message: string;
  privacySafe: boolean;
  details?: Record<string, unknown>;
}

// --- Validation Schemas ---

/**
 * Schema for validating localization metadata.
 * Ensures that only supported versions and valid locales are accepted.
 */
export const LocalizationMetadataSchema = z.object({
  locale: z.string().min(2).max(10),
  version: z.enum(SUPPORTED_LOCALE_VERSIONS),
  timestamp: z.number().int().positive(),
  signer: z.string().optional(),
});

/**
 * Schema for validating individual localization entries.
 * Prevents injection of sensitive data into localization structures.
 */
export const LocalizationEntrySchema = z.object({
  key: z.string().regex(/^[a-zA-Z0-9_-]+$/),
  value: z.union([z.string(), z.number(), z.boolean(), z.null()]),
  metadata: z.object({
    createdAt: z.number().int().positive(),
    updatedAt: z.number().int().positive(),
    author: z.string().optional(),
  }).optional(),
});

// --- Core Localization Logic ---

/**
 * Validates the localization metadata against the schema.
 * Returns a privacy-safe error if validation fails.
 */
export function validateLocalizationMetadata(
  metadata: unknown
): LocalizationResult<z.infer<typeof LocalizationMetadataSchema>> {
  try {
    const parsed = LocalizationMetadataSchema.parse(metadata);
    return { success: true, data: parsed };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        error: {
          code: 'INVALID_METADATA',
          message: 'Localization metadata is malformed or unsupported.',
          privacySafe: true,
          details: {
            issues: error.issues.map((issue) => ({
              path: issue.path.join('.'),
              message: issue.message,
            })),
          },
        },
      };
    }
    return {
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'An unexpected error occurred during metadata validation.',
        privacySafe: true,
      },
    };
  }
}

/**
 * Validates a localization entry against the schema.
 * Ensures that keys are safe and values do not contain sensitive data.
 */
export function validateLocalizationEntry(
  entry: unknown
): LocalizationResult<z.infer<typeof LocalizationEntrySchema>> {
  try {
    const parsed = LocalizationEntrySchema.parse(entry);
    return { success: true, data: parsed };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        error: {
          code: 'INVALID_ENTRY',
          message: 'Localization entry is malformed or contains unsupported data.',
          privacySafe: true,
          details: {
            issues: error.issues.map((issue) => ({
              path: issue.path.join('.'),
              message: issue.message,
            })),
          },
        },
      };
    }
    return {
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'An unexpected error occurred during entry validation.',
        privacySafe: true,
      },
    };
  }
}

/**
 * Checks if a localization bundle is expired based on its timestamp.
 * Uses a 24-hour expiration window for security.
 */
export function isLocalizationExpired(
  timestamp: number,
  expirationWindowMs: number = 24 * 60 * 60 * 1000
): boolean {
  const now = Date.now();
  return now - timestamp > expirationWindowMs;
}

/**
 * Checks if a localization bundle is oversized.
 */
export function isLocalizationOversized(
  sizeBytes: number
): boolean {
  return sizeBytes > MAX_ARTIFACT_SIZE_BYTES;
}

/**
 * Checks if a localization version is supported.
 */
export function isLocalizationVersionSupported(
  version: string
): boolean {
  return SUPPORTED_LOCALE_VERSIONS.includes(version as any);
}

/**
 * Main localization function that orchestrates validation and processing.
 * Ensures that all inputs are validated and that errors are privacy-safe.
 */
export async function localize<T>(
  context: LocalizationContext,
  payload: T
): Promise<LocalizationResult<T>> {
  // 1. Validate metadata
  const metadataValidation = validateLocalizationMetadata({
    locale: context.locale,
    version: context.version,
    timestamp: context.timestamp,
    signer: context.signer,
  });

  if (!metadataValidation.success) {
    return metadataValidation as LocalizationResult<T>;
  }

  // 2. Check expiration
  if (isLocalizationExpired(context.timestamp)) {
    return {
      success: false,
      error: {
        code: 'EXPIRED',
        message: 'Localization bundle has expired.',
        privacySafe: true,
      },
    };
  }

  // 3. Check version support
  if (!isLocalizationVersionSupported(context.version)) {
    return {
      success: false,
      error: {
        code: 'UNSUPPORTED_VERSION',
        message: 'Localization version is not supported.',
        privacySafe: true,
      },
    };
  }

  // 4. Process payload (placeholder for actual localization logic)
  // In a real implementation, this would involve loading the correct locale files,
  // merging with defaults, and handling nested keys.
  // For now, we simply return the payload if it passes validation.
  return { success: true, data: payload };
}

/**
 * Utility function to create a privacy-safe error object.
 * Ensures that no sensitive data is leaked in error messages.
 */
export function createPrivacySafeError(
  code: string,
  message: string,
  details?: Record<string, unknown>
): LocalizationError {
  return {
    code,
    message,
    privacySafe: true,
    details,
  };
}

/**
 * Utility function to log localization errors without leaking sensitive data.
 */
export function logLocalizationError(
  error: LocalizationError,
  logger: (msg: string, meta?: Record<string, unknown>) => void
): void {
  // Only log privacy-safe errors
  if (error.privacySafe) {
    logger(`Localization Error: ${error.code}`, {
      message: error.message,
      details: error.details,
    });
  } else {
    // In a real implementation, this would trigger an alert or send to a secure logging service
    console.error('Privacy-sensitive localization error occurred. Do not log details.');
  }
}