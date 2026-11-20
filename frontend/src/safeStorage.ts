type StorageName = 'localStorage' | 'sessionStorage'

export type VaultErrorCode =
  | 'VAULT_EMPTY'
  | 'VAULT_CORRUPTED'
  | 'VAULT_UNSUPPORTED_VERSION'
  | 'VAULT_ENCRYPTION_FAILED'
  | 'VAULT_DECRYPTION_FAILED'
  | 'VAULT_STORAGE_READ_FAILED'
  | 'VAULT_STORAGE_WRITE_FAILED'
  | 'VAULT_STORAGE_REMOVE_FAILED'
  | 'STORAGE_UNAVAILABLE'
  | 'STORAGE_QUOTA_EXCEEDED'
  | 'UNKNOWN_ERROR'

export interface RedactedErrorCause {
  name: string
  code: VaultErrorCode
  redacted: true
  cause?: RedactedErrorCause
}

export interface SerializedVaultError {
  name: string
  code: VaultErrorCode
  operation: string
  redacted: true
  message: string
  cause?: RedactedErrorCause
}

const KNOWN_ERROR_CODES = new Set<VaultErrorCode>([
  'VAULT_EMPTY',
  'VAULT_CORRUPTED',
  'VAULT_UNSUPPORTED_VERSION',
  'VAULT_ENCRYPTION_FAILED',
  'VAULT_DECRYPTION_FAILED',
  'VAULT_STORAGE_READ_FAILED',
  'VAULT_STORAGE_WRITE_FAILED',
  'VAULT_STORAGE_REMOVE_FAILED',
  'STORAGE_UNAVAILABLE',
  'STORAGE_QUOTA_EXCEEDED',
  'UNKNOWN_ERROR',
])

const MAX_CAUSE_DEPTH = 4

export function classifyErrorCode(error: unknown, fallback: VaultErrorCode = 'UNKNOWN_ERROR'): VaultErrorCode {
  if (error && typeof error === 'object') {
    const candidate = error as { code?: unknown; name?: unknown }
    if (typeof candidate.code === 'string' && KNOWN_ERROR_CODES.has(candidate.code as VaultErrorCode)) {
      return candidate.code as VaultErrorCode
    }
    if (candidate.name === 'QuotaExceededError') return 'STORAGE_QUOTA_EXCEEDED'
    if (candidate.name === 'SecurityError') return 'STORAGE_UNAVAILABLE'
    if (candidate.name === 'OperationError') return 'VAULT_DECRYPTION_FAILED'
  }
  return fallback
}

export function redactErrorCause(
  cause: unknown,
  fallbackCode: VaultErrorCode = 'UNKNOWN_ERROR',
  depth = 0
): RedactedErrorCause | undefined {
  if (cause === undefined || cause === null || depth >= MAX_CAUSE_DEPTH) {
    return undefined
  }

  const name =
    cause instanceof Error
      ? cause.name || 'Error'
      : typeof cause === 'object' && typeof (cause as { name?: unknown }).name === 'string'
        ? ((cause as { name: string }).name || 'Error')
        : typeof cause

  const nestedRaw =
    typeof cause === 'object' && 'cause' in cause ? (cause as { cause?: unknown }).cause : undefined

  const redactedCause: RedactedErrorCause = {
    name,
    code: classifyErrorCode(cause, fallbackCode),
    redacted: true,
  }

  const nested = redactErrorCause(nestedRaw, fallbackCode, depth + 1)
  if (nested) {
    redactedCause.cause = nested
  }

  return redactedCause
}

export class VaultStorageError extends Error {
  readonly code: VaultErrorCode
  readonly operation: string
  readonly redacted = true as const
  override readonly cause?: RedactedErrorCause

  constructor(
    code: VaultErrorCode,
    operation: string,
    options?: { message?: string; cause?: unknown }
  ) {
    super(options?.message ?? `Vault storage operation "${operation}" failed (${code})`)
    this.name = 'VaultStorageError'
    this.code = code
    this.operation = operation
    this.cause = redactErrorCause(options?.cause, code)
  }

  toJSON(): SerializedVaultError {
    return {
      name: this.name,
      code: this.code,
      operation: this.operation,
      redacted: this.redacted,
      message: this.message,
      ...(this.cause ? { cause: this.cause } : {}),
    }
  }
}

export type PersistedUiPreferences = {
  currentView?: 'landing' | 'studio' | 'verify'
  selectedTier?: 'silent' | 'source' | 'seal'
}

const STORAGE_KEY = 'harpocrates:ui-preferences'
const VIEWS = new Set(['landing', 'studio', 'verify'])
const TIERS = new Set(['silent', 'source', 'seal'])

/**
 * The only application data permitted in browser storage is:
 * - currentView: the active public navigation view
 * - selectedTier: the active public identity-tier selection
 *
 * Everything else is excluded by construction. In particular, seeds, proof
 * witnesses, generated proofs, and raw private inputs must remain in memory.
 * 
 * Note: Credential seeds may be stored locally ONLY in the encrypted VaultEnvelope
 * managed by `CredentialVault`, which provides explicit lock/unlock semantics and
 * publishes its supported format parameters via `VAULT_FORMAT_COMPATIBILITY`.
 */
function sanitizePreferences(value: unknown): PersistedUiPreferences {
  if (!value || typeof value !== 'object') return {}

  const candidate = value as Record<string, unknown>
  const safe: PersistedUiPreferences = {}

  if (typeof candidate.currentView === 'string' && VIEWS.has(candidate.currentView)) {
    safe.currentView = candidate.currentView as PersistedUiPreferences['currentView']
  }
  if (typeof candidate.selectedTier === 'string' && TIERS.has(candidate.selectedTier)) {
    safe.selectedTier = candidate.selectedTier as PersistedUiPreferences['selectedTier']
  }

  return safe
}

function browserStorage(name: StorageName): Storage {
  return window[name]
}

function createSafeStorage(name: StorageName) {
  return {
    setItem(key: string, value: string) {
      try {
        browserStorage(name).setItem(key, value)
      } catch (err) {
        const code = classifyErrorCode(err, 'VAULT_STORAGE_WRITE_FAILED')
        throw new VaultStorageError(code, 'setItem', { cause: err })
      }
    },

    getItem(key: string): string | null {
      try {
        return browserStorage(name).getItem(key)
      } catch (err) {
        const code = classifyErrorCode(err, 'VAULT_STORAGE_READ_FAILED')
        throw new VaultStorageError(code, 'getItem', { cause: err })
      }
    },

    removeItem(key: string) {
      try {
        browserStorage(name).removeItem(key)
      } catch (err) {
        const code = classifyErrorCode(err, 'VAULT_STORAGE_REMOVE_FAILED')
        throw new VaultStorageError(code, 'removeItem', { cause: err })
      }
    },

    setUiPreferences(value: PersistedUiPreferences) {
      const safe = sanitizePreferences(value)
      try {
        browserStorage(name).setItem(STORAGE_KEY, JSON.stringify(safe))
      } catch (err) {
        const code = classifyErrorCode(err, 'VAULT_STORAGE_WRITE_FAILED')
        throw new VaultStorageError(code, 'setUiPreferences', { cause: err })
      }
    },

    getUiPreferences(): PersistedUiPreferences {
      let stored: string | null
      try {
        stored = browserStorage(name).getItem(STORAGE_KEY)
      } catch (err) {
        const code = classifyErrorCode(err, 'VAULT_STORAGE_READ_FAILED')
        throw new VaultStorageError(code, 'getUiPreferences', { cause: err })
      }
      if (!stored) return {}

      try {
        return sanitizePreferences(JSON.parse(stored))
      } catch {
        return {}
      }
    },

    clearUiPreferences() {
      try {
        browserStorage(name).removeItem(STORAGE_KEY)
      } catch (err) {
        const code = classifyErrorCode(err, 'VAULT_STORAGE_REMOVE_FAILED')
        throw new VaultStorageError(code, 'clearUiPreferences', { cause: err })
      }
    },
  }
}

export const safeLocalStorage = createSafeStorage('localStorage')
export const safeSessionStorage = createSafeStorage('sessionStorage')
