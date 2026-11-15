type StorageName = 'localStorage' | 'sessionStorage'

export type SafeStorageReasonCode =
  | 'STORAGE_READ_FAILED'
  | 'STORAGE_WRITE_FAILED'
  | 'STORAGE_REMOVE_FAILED'
  | 'STORAGE_QUOTA_EXCEEDED'
  | 'STORAGE_ACCESS_DENIED'

export interface SerializedSafeStorageCause {
  readonly reasonCode: SafeStorageReasonCode
  readonly errorType: string
  readonly cause?: SerializedSafeStorageCause
}

export interface SerializedSafeStorageError {
  readonly name: 'SafeStorageError'
  readonly reasonCode: SafeStorageReasonCode
  readonly message: string
  readonly storage: StorageName
  readonly cause?: SerializedSafeStorageCause
}

const SAFE_STORAGE_MESSAGES: Record<SafeStorageReasonCode, string> = {
  STORAGE_READ_FAILED: 'Browser storage read failed',
  STORAGE_WRITE_FAILED: 'Browser storage write failed',
  STORAGE_REMOVE_FAILED: 'Browser storage clear failed',
  STORAGE_QUOTA_EXCEEDED: 'Browser storage quota exceeded',
  STORAGE_ACCESS_DENIED: 'Browser storage access denied',
}

function classifyStorageCause(err: unknown, fallback: SafeStorageReasonCode): SafeStorageReasonCode {
  if (typeof err === 'object' && err !== null) {
    const name = (err as { name?: unknown }).name
    if (name === 'QuotaExceededError') return 'STORAGE_QUOTA_EXCEEDED'
    if (name === 'SecurityError') return 'STORAGE_ACCESS_DENIED'
  }
  return fallback
}

function safeStorageErrorType(err: unknown): string {
  if (typeof err !== 'object' || err === null) return 'UnknownError'
  const rawName = (err as { name?: unknown }).name
  if (
    rawName === 'DOMException' ||
    rawName === 'QuotaExceededError' ||
    rawName === 'SecurityError' ||
    rawName === 'TypeError' ||
    rawName === 'Error'
  ) {
    return rawName
  }
  return 'Error'
}

function redactStorageCause(
  rawCause: unknown,
  fallback: SafeStorageReasonCode,
  seen = new Set<object>(),
  depth = 0
): SerializedSafeStorageCause | undefined {
  if (rawCause === undefined || rawCause === null || depth >= 5) return undefined
  if (typeof rawCause === 'object') {
    if (seen.has(rawCause)) return undefined
    seen.add(rawCause)
  }
  const reasonCode = classifyStorageCause(rawCause, fallback)
  const errorType = safeStorageErrorType(rawCause)
  const nextRaw =
    typeof rawCause === 'object' && rawCause !== null && 'cause' in rawCause
      ? (rawCause as { cause?: unknown }).cause
      : undefined
  const deeper = redactStorageCause(nextRaw, reasonCode, seen, depth + 1)
  return deeper
    ? Object.freeze({ reasonCode, errorType, cause: deeper })
    : Object.freeze({ reasonCode, errorType })
}

export class SafeStorageError extends Error {
  readonly reasonCode: SafeStorageReasonCode
  readonly storage: StorageName
  readonly serializedCause?: SerializedSafeStorageCause

  constructor(storage: StorageName, fallback: SafeStorageReasonCode, cause?: unknown) {
    const reasonCode = classifyStorageCause(cause, fallback)
    const message = SAFE_STORAGE_MESSAGES[reasonCode]
    super(message)
    this.name = 'SafeStorageError'
    this.reasonCode = reasonCode
    this.storage = storage
    const redacted = redactStorageCause(cause, reasonCode)
    if (redacted !== undefined) {
      this.serializedCause = redacted
    }
    Object.defineProperty(this, 'stack', {
      value: `${this.name} [${this.reasonCode}]: ${message}`,
      enumerable: false,
      configurable: true,
      writable: false,
    })
  }

  toJSON(): SerializedSafeStorageError {
    return this.serializedCause
      ? {
          name: 'SafeStorageError',
          reasonCode: this.reasonCode,
          message: this.message,
          storage: this.storage,
          cause: this.serializedCause,
        }
      : {
          name: 'SafeStorageError',
          reasonCode: this.reasonCode,
          message: this.message,
          storage: this.storage,
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
 * managed by `CredentialVault`, which provides explicit lock/unlock semantics.
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
      } catch (cause) {
        throw new SafeStorageError(name, 'STORAGE_WRITE_FAILED', cause)
      }
    },

    getItem(key: string): string | null {
      try {
        return browserStorage(name).getItem(key)
      } catch (cause) {
        throw new SafeStorageError(name, 'STORAGE_READ_FAILED', cause)
      }
    },

    removeItem(key: string) {
      try {
        browserStorage(name).removeItem(key)
      } catch (cause) {
        throw new SafeStorageError(name, 'STORAGE_REMOVE_FAILED', cause)
      }
    },

    setUiPreferences(value: PersistedUiPreferences) {
      const safe = sanitizePreferences(value)
      try {
        browserStorage(name).setItem(STORAGE_KEY, JSON.stringify(safe))
      } catch (cause) {
        throw new SafeStorageError(name, 'STORAGE_WRITE_FAILED', cause)
      }
    },

    getUiPreferences(): PersistedUiPreferences {
      let stored: string | null
      try {
        stored = browserStorage(name).getItem(STORAGE_KEY)
      } catch (cause) {
        throw new SafeStorageError(name, 'STORAGE_READ_FAILED', cause)
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
      } catch (cause) {
        throw new SafeStorageError(name, 'STORAGE_REMOVE_FAILED', cause)
      }
    },
  }
}

export const safeLocalStorage = createSafeStorage('localStorage')
export const safeSessionStorage = createSafeStorage('sessionStorage')
