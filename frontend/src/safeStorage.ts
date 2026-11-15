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

export const VAULT_LOCK_CHANNEL_NAME = 'harpocrates:credential-vault:lock'
export const VAULT_LOCK_SIGNAL_STORAGE_KEY = 'harpocrates:credential-vault:lock-signal'

export interface VaultLockBroadcastPayload {
  readonly type: 'VAULT_EXPLICIT_LOCK'
  readonly sessionGeneration: number
}

export interface VaultLockTransport {
  publishLock(payload: VaultLockBroadcastPayload): void
  subscribeLock(onLock: (payload: VaultLockBroadcastPayload) => void): () => void
  close(): void
}

/**
 * Enforces an exact two-field allowlist (`type` and `sessionGeneration`) so no
 * secret witness material, key, or envelope field can ever cross tab boundaries.
 */
export function sanitizeVaultLockBroadcastPayload(
  candidate: unknown,
): VaultLockBroadcastPayload | null {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return null
  }

  const record = candidate as Record<string, unknown>
  const keys = Object.keys(record)
  if (
    keys.length !== 2 ||
    !keys.includes('type') ||
    !keys.includes('sessionGeneration')
  ) {
    return null
  }

  if (record.type !== 'VAULT_EXPLICIT_LOCK') {
    return null
  }

  const generation = record.sessionGeneration
  if (
    typeof generation !== 'number' ||
    !Number.isSafeInteger(generation) ||
    generation < 1
  ) {
    return null
  }

  return Object.freeze({
    type: 'VAULT_EXPLICIT_LOCK',
    sessionGeneration: generation,
  })
}

export function createBrowserVaultLockTransport(
  channelName = VAULT_LOCK_CHANNEL_NAME,
): VaultLockTransport {
  const listeners = new Set<(payload: VaultLockBroadcastPayload) => void>()
  let channel: BroadcastChannel | null = null

  if (typeof BroadcastChannel === 'function') {
    channel = new BroadcastChannel(channelName)
    channel.onmessage = (event: MessageEvent<unknown>) => {
      const safePayload = sanitizeVaultLockBroadcastPayload(event.data)
      if (!safePayload) return
      for (const listener of listeners) {
        listener(safePayload)
      }
    }
    ;(channel as unknown as { unref?: () => void }).unref?.()
  }

  const storageHandler = (event: StorageEvent) => {
    if (event.key !== VAULT_LOCK_SIGNAL_STORAGE_KEY || !event.newValue) {
      return
    }
    try {
      const parsed: unknown = JSON.parse(event.newValue)
      const safePayload = sanitizeVaultLockBroadcastPayload(parsed)
      if (!safePayload) return
      for (const listener of listeners) {
        listener(safePayload)
      }
    } catch {
      // Ignore malformed cross-tab storage payloads
    }
  }

  if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
    window.addEventListener('storage', storageHandler)
  }

  return {
    publishLock(payload: VaultLockBroadcastPayload) {
      const safePayload = sanitizeVaultLockBroadcastPayload(payload)
      if (!safePayload) {
        throw new Error('Invalid vault lock broadcast payload')
      }
      if (channel) {
        channel.postMessage(safePayload)
        return
      }
      if (typeof window !== 'undefined' && window.localStorage) {
        window.localStorage.setItem(
          VAULT_LOCK_SIGNAL_STORAGE_KEY,
          JSON.stringify(safePayload),
        )
      }
    },

    subscribeLock(onLock: (payload: VaultLockBroadcastPayload) => void): () => void {
      listeners.add(onLock)
      return () => {
        listeners.delete(onLock)
      }
    },

    close() {
      listeners.clear()
      if (channel) {
        channel.close()
        channel = null
      }
      if (
        typeof window !== 'undefined' &&
        typeof window.removeEventListener === 'function'
      ) {
        window.removeEventListener('storage', storageHandler)
      }
    },
  }
}
