type StorageName = 'localStorage' | 'sessionStorage'

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
      browserStorage(name).setItem(key, value)
    },

    getItem(key: string): string | null {
      return browserStorage(name).getItem(key)
    },

    removeItem(key: string) {
      browserStorage(name).removeItem(key)
    },

    setUiPreferences(value: PersistedUiPreferences) {
      const safe = sanitizePreferences(value)
      browserStorage(name).setItem(STORAGE_KEY, JSON.stringify(safe))
    },

    getUiPreferences(): PersistedUiPreferences {
      const stored = browserStorage(name).getItem(STORAGE_KEY)
      if (!stored) return {}

      try {
        return sanitizePreferences(JSON.parse(stored))
      } catch {
        return {}
      }
    },

    clearUiPreferences() {
      browserStorage(name).removeItem(STORAGE_KEY)
    },
  }
}

export const safeLocalStorage = createSafeStorage('localStorage')
export const safeSessionStorage = createSafeStorage('sessionStorage')

export type BrowserStorageFailureCode =
  | 'STORAGE_PERMISSION_DENIED'
  | 'STORAGE_QUOTA_EXCEEDED'
  | 'STORAGE_UNAVAILABLE'

export type BrowserStorageOperation = 'probe' | 'read' | 'write' | 'remove'

const STORAGE_RECOVERY_GUIDANCE: Record<BrowserStorageFailureCode, string> = {
  STORAGE_PERMISSION_DENIED:
    'Allow site data and local storage access for this origin in your browser privacy settings, then retry without resetting your encrypted vault.',
  STORAGE_QUOTA_EXCEEDED:
    'Free browser storage space for this origin without clearing harpocrates:credential-vault, then retry the vault operation.',
  STORAGE_UNAVAILABLE:
    'Open Harpocrates in a standard browser context with Web Storage enabled before accessing local vault persistence.',
}

export class BrowserStorageAccessError extends Error {
  readonly code: BrowserStorageFailureCode
  readonly storageName: StorageName
  readonly operation: BrowserStorageOperation
  readonly recoveryGuidance: string

  constructor(
    code: BrowserStorageFailureCode,
    storageName: StorageName,
    operation: BrowserStorageOperation,
    message: string,
  ) {
    super(message)
    this.name = 'BrowserStorageAccessError'
    this.code = code
    this.storageName = storageName
    this.operation = operation
    this.recoveryGuidance = STORAGE_RECOVERY_GUIDANCE[code]
  }
}

export function classifyBrowserStorageError(
  err: unknown,
  storageName: StorageName = 'localStorage',
  operation: BrowserStorageOperation = 'read',
): BrowserStorageAccessError {
  if (err instanceof BrowserStorageAccessError) {
    return err
  }

  const name =
    err && typeof err === 'object' && 'name' in err && typeof err.name === 'string'
      ? err.name
      : ''
  const rawMessage =
    err && typeof err === 'object' && 'message' in err && typeof err.message === 'string'
      ? err.message
      : ''
  const lower = `${name} ${rawMessage}`.toLowerCase()

  if (
    name === 'SecurityError' ||
    name === 'NotAllowedError' ||
    lower.includes('security') ||
    lower.includes('access is denied') ||
    lower.includes('permission')
  ) {
    return new BrowserStorageAccessError(
      'STORAGE_PERMISSION_DENIED',
      storageName,
      operation,
      `Browser ${storageName} permission denied during ${operation}`,
    )
  }

  if (
    name === 'QuotaExceededError' ||
    name === 'NS_ERROR_DOM_QUOTA_REACHED' ||
    lower.includes('quota')
  ) {
    return new BrowserStorageAccessError(
      'STORAGE_QUOTA_EXCEEDED',
      storageName,
      operation,
      `Browser ${storageName} quota exceeded during ${operation}`,
    )
  }

  return new BrowserStorageAccessError(
    'STORAGE_UNAVAILABLE',
    storageName,
    operation,
    `Browser ${storageName} is unavailable during ${operation}`,
  )
}

function getCheckedStorage(
  storageName: StorageName,
  operation: BrowserStorageOperation,
): Storage {
  try {
    if (typeof window === 'undefined') {
      throw new Error('Window is undefined')
    }
    const storage = window[storageName]
    if (!storage) {
      throw new Error(`${storageName} is null`)
    }
    return storage
  } catch (err) {
    throw classifyBrowserStorageError(err, storageName, operation)
  }
}

export function readStorageKeyChecked(storageName: StorageName, key: string): string | null {
  const storage = getCheckedStorage(storageName, 'read')
  try {
    return storage.getItem(key)
  } catch (err) {
    throw classifyBrowserStorageError(err, storageName, 'read')
  }
}

export function writeStorageKeyChecked(
  storageName: StorageName,
  key: string,
  value: string,
): void {
  const storage = getCheckedStorage(storageName, 'write')
  try {
    storage.setItem(key, value)
  } catch (err) {
    throw classifyBrowserStorageError(err, storageName, 'write')
  }
}

export function removeStorageKeyChecked(storageName: StorageName, key: string): void {
  const storage = getCheckedStorage(storageName, 'remove')
  try {
    storage.removeItem(key)
  } catch (err) {
    throw classifyBrowserStorageError(err, storageName, 'remove')
  }
}
