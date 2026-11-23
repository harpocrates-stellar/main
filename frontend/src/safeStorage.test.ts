import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  safeLocalStorage,
  safeSessionStorage,
  STORAGE_KEY,
  VAULT_STORAGE_KEY,
  addCrossTabStorageListener,
} from './safeStorage'

describe.each([
  ['localStorage', safeLocalStorage],
  ['sessionStorage', safeSessionStorage],
] as const)('%s safety boundary', (storageName, safeStorage) => {
  beforeEach(() => {
    window.localStorage.clear()
    window.sessionStorage.clear()
    vi.restoreAllMocks()
  })

  it('persists only the documented public UI preferences', () => {
    const setItem = vi.spyOn(window[storageName as 'localStorage' | 'sessionStorage'], 'setItem')

    safeStorage.setUiPreferences({
      currentView: 'studio',
      selectedTier: 'silent',
      vaultRecoveryRehearsed: true,
    })

    expect(setItem).toHaveBeenCalledOnce()
    expect(setItem).toHaveBeenCalledWith(
      STORAGE_KEY,
      JSON.stringify({ currentView: 'studio', selectedTier: 'silent', vaultRecoveryRehearsed: true }),
    )
    expect(safeStorage.getUiPreferences()).toEqual({
      currentView: 'studio',
      selectedTier: 'silent',
      vaultRecoveryRehearsed: true,
    })
    expect(setItem.mock.instances[0]).toBe(window[storageName])
  })

  it('excludes seeds, proof witnesses, proofs, and raw private inputs', () => {
    const setItem = vi.spyOn(window[storageName as 'localStorage' | 'sessionStorage'], 'setItem')
    const sensitive = {
      currentView: 'verify',
      selectedTier: 'source',
      vaultRecoveryRehearsed: true,
      credentialSeed: 'credential-seed-secret',
      nullifierSeed: 'nullifier-seed-secret',
      witness: 'proof-witness-secret',
      proof: 'generated-proof-secret',
      privateInputs: {
        credential_secret: 'raw-credential-secret',
        nullifier_secret: 'raw-nullifier-secret',
      },
    }

    safeStorage.setUiPreferences(sensitive)

    expect(setItem).toHaveBeenCalledOnce()
    const serialized = setItem.mock.calls[0][1]
    expect(JSON.parse(serialized)).toEqual({
      currentView: 'verify',
      selectedTier: 'source',
      vaultRecoveryRehearsed: true,
    })
    expect(serialized).not.toContain('seed-secret')
    expect(serialized).not.toContain('witness-secret')
    expect(serialized).not.toContain('proof-secret')
    expect(serialized).not.toContain('raw-')
  })

  it('filters untrusted stored values on read', () => {
    window[storageName].setItem(
      STORAGE_KEY,
      JSON.stringify({
        currentView: 'landing',
        selectedTier: 'seal',
        vaultRecoveryRehearsed: true,
        credentialSeed: 'previously-stored-secret',
        witness: 'previously-stored-witness',
      }),
    )

    expect(safeStorage.getUiPreferences()).toEqual({
      currentView: 'landing',
      selectedTier: 'seal',
      vaultRecoveryRehearsed: true,
    })
  })

  it('redacts private vault values and nested causes from storage error serialization', () => {
    const innerCause = Object.assign(
      new Error('raw inner secret: credential-seed-secret nullifier-seed-secret'),
      { name: 'OperationError', credentialSeed: 'credential-seed-secret' },
    )
    const quotaError = Object.assign(
      new Error('QuotaExceededError: value={"credentialSeed":"credential-seed-secret"}'),
      { name: 'QuotaExceededError', cause: innerCause },
    )

    vi.spyOn(window[storageName], 'setItem').mockImplementation(() => {
      throw quotaError
    })

    let caught: unknown
    try {
      safeStorage.setItem('harpocrates:test', 'secret-payload')
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(VaultStorageError)
    const serialized = JSON.stringify(caught)
    expect(serialized).not.toContain('credential-seed-secret')
    expect(serialized).not.toContain('nullifier-seed-secret')
    expect(serialized).not.toContain('secret-payload')

    const parsed = JSON.parse(serialized)
    expect(parsed).toEqual({
      name: 'VaultStorageError',
      code: 'STORAGE_QUOTA_EXCEEDED',
      operation: 'setItem',
      redacted: true,
      message: 'Vault storage operation "setItem" failed (STORAGE_QUOTA_EXCEEDED)',
      cause: {
        name: 'QuotaExceededError',
        code: 'STORAGE_QUOTA_EXCEEDED',
        redacted: true,
        cause: {
          name: 'OperationError',
          code: 'VAULT_DECRYPTION_FAILED',
          redacted: true,
        },
      },
    })
  })
})

describe('addCrossTabStorageListener', () => {
  beforeEach(() => {
    window.localStorage.clear()
    window.sessionStorage.clear()
    vi.restoreAllMocks()
  })

  it('notifies listener when storage event matches target key', () => {
    const listener = vi.fn()
    const unsubscribe = addCrossTabStorageListener(VAULT_STORAGE_KEY, listener)

    const event = new StorageEvent('storage', {
      key: VAULT_STORAGE_KEY,
      oldValue: '{"v":1,"salt":"a"}',
      newValue: '{"v":1,"salt":"b"}',
      storageArea: window.localStorage,
    })
    window.dispatchEvent(event)

    expect(listener).toHaveBeenCalledOnce()
    expect(listener).toHaveBeenCalledWith({
      key: VAULT_STORAGE_KEY,
      oldValue: '{"v":1,"salt":"a"}',
      newValue: '{"v":1,"salt":"b"}',
      storageArea: window.localStorage,
    })

    unsubscribe()
  })

  it('notifies listener when storage is cleared (key is null)', () => {
    const listener = vi.fn()
    const unsubscribe = addCrossTabStorageListener(VAULT_STORAGE_KEY, listener)

    const clearEvent = new StorageEvent('storage', {
      key: null,
      oldValue: null,
      newValue: null,
      storageArea: window.localStorage,
    })
    window.dispatchEvent(clearEvent)

    expect(listener).toHaveBeenCalledOnce()
    expect(listener).toHaveBeenCalledWith({
      key: null,
      oldValue: null,
      newValue: null,
      storageArea: window.localStorage,
    })

    unsubscribe()
  })

  it('ignores storage events for other keys', () => {
    const listener = vi.fn()
    const unsubscribe = addCrossTabStorageListener(VAULT_STORAGE_KEY, listener)

    const irrelevantEvent = new StorageEvent('storage', {
      key: 'some-other-key',
      oldValue: 'old',
      newValue: 'new',
      storageArea: window.localStorage,
    })
    window.dispatchEvent(irrelevantEvent)

    expect(listener).not.toHaveBeenCalled()
    unsubscribe()
  })

  it('ignores storage events originating from sessionStorage', () => {
    const listener = vi.fn()
    const unsubscribe = addCrossTabStorageListener(VAULT_STORAGE_KEY, listener)

    const sessionEvent = new StorageEvent('storage', {
      key: VAULT_STORAGE_KEY,
      oldValue: 'old',
      newValue: 'new',
      storageArea: window.sessionStorage,
    })
    window.dispatchEvent(sessionEvent)

    expect(listener).not.toHaveBeenCalled()
    unsubscribe()
  })

  it('stops listening when unsubscribed', () => {
    const listener = vi.fn()
    const unsubscribe = addCrossTabStorageListener(VAULT_STORAGE_KEY, listener)

    unsubscribe()

    const event = new StorageEvent('storage', {
      key: VAULT_STORAGE_KEY,
      oldValue: 'a',
      newValue: 'b',
      storageArea: window.localStorage,
    })
    window.dispatchEvent(event)

    expect(listener).not.toHaveBeenCalled()
  })

  it('safeLocalStorage.onKeyChange provides equivalent listener', () => {
    const listener = vi.fn()
    const unsubscribe = safeLocalStorage.onKeyChange(VAULT_STORAGE_KEY, listener)

    const event = new StorageEvent('storage', {
      key: VAULT_STORAGE_KEY,
      oldValue: null,
      newValue: 'new-envelope',
      storageArea: window.localStorage,
    })
    window.dispatchEvent(event)

    expect(listener).toHaveBeenCalledOnce()
    unsubscribe()
  })
})
