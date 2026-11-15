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

export interface IsolatedMigrationWorkspace {
  stagePlaintextBuffer(source: ArrayBuffer | Uint8Array): Uint8Array
  stageCandidateEnvelope(serializedEnvelope: string): void
  readCandidateEnvelope(): string | null
  disposeAndZero(): void
  isDisposed(): boolean
}

/**
 * Ephemeral in-memory workspace used during staged vault format migrations so
 * plaintext bytes and unverified candidate envelopes never touch Web Storage
 * and are deterministically zeroed on completion or failure.
 */
export function createIsolatedMigrationWorkspace(): IsolatedMigrationWorkspace {
  const trackedBuffers: Uint8Array[] = []
  const state: { candidateEnvelope: string | null; disposed: boolean } = {
    candidateEnvelope: null,
    disposed: false,
  }

  function ensureActive(): void {
    if (state.disposed) {
      throw new Error('Isolated migration workspace has already been disposed')
    }
  }

  return {
    stagePlaintextBuffer(source: ArrayBuffer | Uint8Array): Uint8Array {
      ensureActive()
      const view = source instanceof Uint8Array ? source : new Uint8Array(source)
      const isolatedCopy = new Uint8Array(view.byteLength)
      isolatedCopy.set(view)
      trackedBuffers.push(isolatedCopy)
      return isolatedCopy
    },

    stageCandidateEnvelope(serializedEnvelope: string): void {
      ensureActive()
      state.candidateEnvelope = serializedEnvelope
    },

    readCandidateEnvelope(): string | null {
      ensureActive()
      return state.candidateEnvelope
    },

    disposeAndZero(): void {
      for (const buf of trackedBuffers) {
        buf.fill(0)
      }
      trackedBuffers.length = 0
      state.candidateEnvelope = null
      state.disposed = true
    },

    isDisposed(): boolean {
      return state.disposed
    },
  }
}

/**
 * Replaces `key` in browser storage only if its current raw value still matches
 * `expectedPreviousRaw`, preserving the previous encrypted value on write errors.
 */
export function commitVerifiedStorageReplacement(
  name: StorageName,
  key: string,
  expectedPreviousRaw: string,
  verifiedNewRaw: string,
): void {
  const storage = browserStorage(name)
  const currentRaw = storage.getItem(key)
  if (currentRaw !== expectedPreviousRaw) {
    throw new Error(
      'Vault storage changed concurrently during migration; aborting commit to preserve state',
    )
  }

  storage.setItem(key, verifiedNewRaw)
  const readBack = storage.getItem(key)
  if (readBack !== verifiedNewRaw) {
    storage.setItem(key, expectedPreviousRaw)
    throw new Error('Post-write storage verification failed; previous envelope restored')
  }
}
