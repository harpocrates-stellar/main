import { beforeEach, describe, expect, it, vi } from 'vitest'
import { safeLocalStorage, safeSessionStorage, VaultStorageError } from './safeStorage'

const STORAGE_KEY = 'harpocrates:ui-preferences'

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
    })

    expect(setItem).toHaveBeenCalledOnce()
    expect(setItem).toHaveBeenCalledWith(
      STORAGE_KEY,
      JSON.stringify({ currentView: 'studio', selectedTier: 'silent' }),
    )
    expect(safeStorage.getUiPreferences()).toEqual({
      currentView: 'studio',
      selectedTier: 'silent',
    })
    expect(setItem.mock.instances[0]).toBe(window[storageName])
  })

  it('excludes seeds, proof witnesses, proofs, and raw private inputs', () => {
    const setItem = vi.spyOn(window[storageName as 'localStorage' | 'sessionStorage'], 'setItem')
    const sensitive = {
      currentView: 'verify',
      selectedTier: 'source',
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
        credentialSeed: 'previously-stored-secret',
        witness: 'previously-stored-witness',
      }),
    )

    expect(safeStorage.getUiPreferences()).toEqual({
      currentView: 'landing',
      selectedTier: 'seal',
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
