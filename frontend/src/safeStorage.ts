type StorageName = 'localStorage' | 'sessionStorage'

export type SafeStorageLike = {
  setItem(key: string, value: string): void
  getItem(key: string): string | null
  removeItem(key: string): void
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
 * staged format migration (preserving the previous encrypted envelope in
 * `harpocrates:credential-vault:backup` until the replacement envelope verifies).
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
