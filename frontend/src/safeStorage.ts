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

export const VAULT_BACKUP_PRESENCE_KEY = 'harpocrates:credential-vault:backup-status'
const STORAGE_PROBE_KEY = 'harpocrates:storage-probe'
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T[0-9:.+-]+Z?$/

export type StorageAvailabilityStatus = 'available' | 'read-only' | 'unavailable'

export interface StorageAvailabilityProbe {
  readonly available: boolean
  readonly status: StorageAvailabilityStatus
}

export interface VaultBackupPresenceRecord {
  readonly backupPresent: boolean
  readonly recordedFormatVersion: number | null
  readonly recordedAtIso: string | null
}

function sanitizeBackupPresenceRecord(value: unknown): VaultBackupPresenceRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {
      backupPresent: false,
      recordedFormatVersion: null,
      recordedAtIso: null,
    }
  }

  const candidate = value as Record<string, unknown>
  const backupPresent = candidate.backupPresent === true
  const recordedFormatVersion =
    typeof candidate.recordedFormatVersion === 'number' &&
    Number.isSafeInteger(candidate.recordedFormatVersion) &&
    candidate.recordedFormatVersion >= 1
      ? candidate.recordedFormatVersion
      : null
  const recordedAtIso =
    typeof candidate.recordedAtIso === 'string' &&
    candidate.recordedAtIso.length <= 40 &&
    ISO_TIMESTAMP_PATTERN.test(candidate.recordedAtIso)
      ? candidate.recordedAtIso
      : null

  return Object.freeze({
    backupPresent,
    recordedFormatVersion: backupPresent ? recordedFormatVersion : null,
    recordedAtIso: backupPresent ? recordedAtIso : null,
  })
}

export function probeLocalStorageAvailability(): StorageAvailabilityProbe {
  let storage: Storage
  try {
    if (typeof window === 'undefined' || !window.localStorage) {
      return Object.freeze({ available: false, status: 'unavailable' })
    }
    storage = window.localStorage
    storage.getItem(STORAGE_PROBE_KEY)
  } catch {
    return Object.freeze({ available: false, status: 'unavailable' })
  }

  try {
    storage.setItem(STORAGE_PROBE_KEY, '1')
    storage.removeItem(STORAGE_PROBE_KEY)
    return Object.freeze({ available: true, status: 'available' })
  } catch {
    return Object.freeze({ available: false, status: 'read-only' })
  }
}

export function readVaultBackupPresence(): VaultBackupPresenceRecord {
  try {
    if (typeof window === 'undefined' || !window.localStorage) {
      return sanitizeBackupPresenceRecord(null)
    }
    const raw = window.localStorage.getItem(VAULT_BACKUP_PRESENCE_KEY)
    if (!raw) return sanitizeBackupPresenceRecord(null)
    return sanitizeBackupPresenceRecord(JSON.parse(raw))
  } catch {
    return sanitizeBackupPresenceRecord(null)
  }
}

export function writeVaultBackupPresence(record: VaultBackupPresenceRecord): void {
  const safeRecord = sanitizeBackupPresenceRecord(record)
  browserStorage('localStorage').setItem(
    VAULT_BACKUP_PRESENCE_KEY,
    JSON.stringify(safeRecord),
  )
}

export function clearVaultBackupPresence(): void {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.removeItem(VAULT_BACKUP_PRESENCE_KEY)
    }
  } catch {
    // Ignore storage removal errors when storage is already unavailable
  }
}
