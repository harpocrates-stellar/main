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

export interface ExternalStorageChangeEvent {
  key: string | null
  oldValue: string | null
  newValue: string | null
}

/**
 * Computes a deterministic, non-secret 64-bit FNV-1a hexadecimal fingerprint
 * for change detection across browser tabs without exposing envelope contents.
 */
export function computeEnvelopeChangeFingerprint(rawEnvelope: string | null): string | null {
  if (!rawEnvelope) return null
  let hash = 0xcbf29ce484222325n
  const prime = 0x100000001b3n
  const mask = 0xffffffffffffffffn
  for (let i = 0; i < rawEnvelope.length; i++) {
    hash ^= BigInt(rawEnvelope.charCodeAt(i))
    hash = (hash * prime) & mask
  }
  return hash.toString(16).padStart(16, '0')
}

/**
 * Subscribes to cross-tab `window` storage events affecting `targetKey`
 * (including full storage clears where `event.key === null`).
 */
export function subscribeToStorageKeyChanges(
  targetKey: string,
  onChange: (event: ExternalStorageChangeEvent) => void,
): () => void {
  if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') {
    return () => {}
  }

  const handler = (event: StorageEvent) => {
    if (event.storageArea && event.storageArea !== window.localStorage) {
      return
    }
    if (event.key !== targetKey && event.key !== null) {
      return
    }
    const newValue =
      event.key === null ? window.localStorage.getItem(targetKey) : event.newValue
    onChange({
      key: event.key,
      oldValue: event.oldValue,
      newValue,
    })
  }

  window.addEventListener('storage', handler)
  return () => {
    window.removeEventListener('storage', handler)
  }
}
