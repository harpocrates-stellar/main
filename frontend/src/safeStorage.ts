type StorageName = 'localStorage' | 'sessionStorage'

export type SafeStorageLike = {
  setItem(key: string, value: string): void
  getItem(key: string): string | null
  removeItem(key: string): void
}

export type PersistedUiPreferences = {
  currentView?: 'landing' | 'studio' | 'verify'
  selectedTier?: 'silent' | 'source' | 'seal'
  vaultRecoveryRehearsed?: boolean
}

export const STORAGE_KEY = 'harpocrates:ui-preferences'
export const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VIEWS = new Set(['landing', 'studio', 'verify'])
const TIERS = new Set(['silent', 'source', 'seal'])

export interface CrossTabStorageChangeEvent {
  key: string | null
  oldValue: string | null
  newValue: string | null
  storageArea: Storage | null
}

export type CrossTabStorageListener = (change: CrossTabStorageChangeEvent) => void

/**
 * Register a cross-tab storage change listener.
 * In web browsers, window fires a 'storage' event when another tab or window
 * modifies localStorage.
 *
 * Handles both key-specific events and storage-wide clear events (where event.key is null).
 * Returns an unregister cleanup function.
 */
export function addCrossTabStorageListener(
  targetKey: string,
  listener: CrossTabStorageListener,
): () => void {
  if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') {
    return () => {}
  }

  const handler = (event: StorageEvent) => {
    // If event.storageArea is present, ensure it targets localStorage
    if (event.storageArea && event.storageArea !== window.localStorage) {
      return
    }

    // Match exact key or storage-wide clear event (where key is null)
    if (event.key === targetKey || event.key === null) {
      listener({
        key: event.key,
        oldValue: event.oldValue,
        newValue: event.newValue,
        storageArea: event.storageArea,
      })
    }
  }

  window.addEventListener('storage', handler)
  return () => {
    window.removeEventListener('storage', handler)
  }
}

/**
 * The only application data permitted in browser storage is:
 * - currentView: the active public navigation view
 * - selectedTier: the active public identity-tier selection
 * - vaultRecoveryRehearsed: whether the one-time vault recovery rehearsal has completed
 *
 * Everything else is excluded by construction. In particular, seeds, proof
 * witnesses, generated proofs, and raw private inputs must remain in memory.
 * 
 * Note: Credential seeds may be stored locally ONLY in the encrypted VaultEnvelope 
 * managed by `CredentialVault`, which provides explicit lock/unlock semantics.
 * Vault backup export destinations and encrypted backup payloads are never persisted
 * in `safeStorage`; destinations must be explicitly selected by the user per export.
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
  if (typeof candidate.vaultRecoveryRehearsed === 'boolean') {
    safe.vaultRecoveryRehearsed = candidate.vaultRecoveryRehearsed
  }

  return safe
}

function browserStorage(name: StorageName): Storage {
  return window[name]
}

/**
 * In-memory storage container conforming to the standard Web Storage interface.
 * Used for isolated testing and synthetic vault recovery rehearsals without touching
 * the browser's live persistence or active private credentials.
 */
export function createIsolatedStateContainer(): Storage {
  const store = new Map<string, string>()

  return {
    get length(): number {
      return store.size
    },
    clear(): void {
      store.clear()
    },
    getItem(key: string): string | null {
      return store.has(key) ? store.get(key)! : null
    },
    key(index: number): string | null {
      const keys = Array.from(store.keys())
      return keys[index] ?? null
    },
    removeItem(key: string): void {
      store.delete(key)
    },
    setItem(key: string, value: string): void {
      store.set(key, String(value))
    },
  }
}

export type StorageTarget = StorageName | Storage

export function createSafeStorage(target: StorageTarget) {
  function getStorage(): Storage {
    if (typeof target === 'string') {
      return browserStorage(target)
    }
    return target
  }

  return {
    setItem(key: string, value: string) {
      getStorage().setItem(key, value)
    },

    getItem(key: string): string | null {
      return getStorage().getItem(key)
    },

    removeItem(key: string) {
      getStorage().removeItem(key)
    },

    setUiPreferences(value: PersistedUiPreferences) {
      const safe = sanitizePreferences(value)
      getStorage().setItem(STORAGE_KEY, JSON.stringify(safe))
    },

    getUiPreferences(): PersistedUiPreferences {
      const stored = getStorage().getItem(STORAGE_KEY)
      if (!stored) return {}

      try {
        return sanitizePreferences(JSON.parse(stored))
      } catch {
        return {}
      }
    },

    clearUiPreferences() {
      getStorage().removeItem(STORAGE_KEY)
    },

    onKeyChange(key: string, listener: CrossTabStorageListener): () => void {
      return addCrossTabStorageListener(key, listener)
    },
  }
}

export function createIsolatedSafeStorage(container: Storage = createIsolatedStateContainer()) {
  return createSafeStorage(container)
}

export const safeLocalStorage = createSafeStorage('localStorage')
export const safeSessionStorage = createSafeStorage('sessionStorage')
