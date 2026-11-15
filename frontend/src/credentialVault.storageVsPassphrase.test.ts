import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  CredentialVault,
  VAULT_RECOVERY_GUIDANCE,
  VaultAccessError,
} from './credentialVault'

describe('Distinguish unavailable browser storage from incorrect vault passphrase (#1148)', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('returns distinct error codes and recovery guidance for permission-denied storage vs wrong passphrase', async () => {
    const setupVault = new CredentialVault()
    const seeds = {
      credentialSeed: 'cred-seed-alpha',
      nullifierSeed: 'null-seed-beta',
    }
    await setupVault.setup('CorrectHorseBattery#1', seeds)
    const encryptedSnapshot = window.localStorage.getItem('harpocrates:credential-vault')
    expect(encryptedSnapshot).toBeTruthy()

    // Case 1: Wrong passphrase on accessible storage
    const passphraseVault = new CredentialVault()
    const wrongPassOutcome = await passphraseVault.unlockWithDiagnostics('WrongPassphrase#9')
    expect(wrongPassOutcome).toEqual({
      ok: false,
      code: 'INCORRECT_PASSPHRASE',
      message: 'Incorrect vault passphrase',
      recoveryGuidance: VAULT_RECOVERY_GUIDANCE.INCORRECT_PASSPHRASE,
    })

    // Case 2: Storage permission denied (`SecurityError`)
    const removeSpy = vi.spyOn(window.localStorage, 'removeItem')
    const getSpy = vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => {
      const err = new Error('The operation is insecure.')
      err.name = 'SecurityError'
      throw err
    })

    const blockedVault = new CredentialVault()
    await expect(blockedVault.unlock('CorrectHorseBattery#1')).rejects.toMatchObject({
      name: 'VaultAccessError',
      code: 'STORAGE_PERMISSION_DENIED',
      recoveryGuidance: VAULT_RECOVERY_GUIDANCE.STORAGE_PERMISSION_DENIED,
    })

    const blockedOutcome = await blockedVault.unlockWithDiagnostics('CorrectHorseBattery#1')
    expect(blockedOutcome).toEqual({
      ok: false,
      code: 'STORAGE_PERMISSION_DENIED',
      message: 'Browser localStorage permission denied during read',
      recoveryGuidance: VAULT_RECOVERY_GUIDANCE.STORAGE_PERMISSION_DENIED,
    })
    expect(blockedOutcome.code).not.toBe(wrongPassOutcome.code)
    expect(blockedOutcome.recoveryGuidance).not.toBe(wrongPassOutcome.recoveryGuidance)
    expect(removeSpy).not.toHaveBeenCalled()

    // Once storage permission is restored, the encrypted vault is still intact and unlocks cleanly!
    getSpy.mockRestore()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(encryptedSnapshot)
    const recoveredOutcome = await blockedVault.unlockWithDiagnostics('CorrectHorseBattery#1')
    expect(recoveredOutcome).toEqual({ ok: true })
    expect(blockedVault.getSeeds()).toEqual(seeds)
  })

  it('distinguishes completely missing window.localStorage from empty vault or bad passphrase', async () => {
    const originalDescriptor = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      get() {
        return null
      },
    })

    try {
      const vault = new CredentialVault()
      const outcome = await vault.unlockWithDiagnostics('AnyPassphrase#1')
      expect(outcome).toEqual({
        ok: false,
        code: 'STORAGE_UNAVAILABLE',
        message: 'Browser localStorage is unavailable during read',
        recoveryGuidance: VAULT_RECOVERY_GUIDANCE.STORAGE_UNAVAILABLE,
      })
    } finally {
      if (originalDescriptor) {
        Object.defineProperty(window, 'localStorage', originalDescriptor)
      }
    }
  })

  it('preserves existing encrypted vault when setup encounters a write permission or quota failure', async () => {
    const initialVault = new CredentialVault()
    const initialSeeds = {
      credentialSeed: 'preserved-cred',
      nullifierSeed: 'preserved-null',
    }
    await initialVault.setup('InitialPass#1', initialSeeds)
    const storedBeforeFailure = window.localStorage.getItem('harpocrates:credential-vault')

    const removeSpy = vi.spyOn(window.localStorage, 'removeItem')
    const setSpy = vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => {
      const err = new Error('Storage quota exceeded')
      err.name = 'QuotaExceededError'
      throw err
    })

    const nextVault = new CredentialVault()
    await expect(
      nextVault.setup('ReplacementPass#2', {
        credentialSeed: 'new-cred',
        nullifierSeed: 'new-null',
      }),
    ).rejects.toThrow(VaultAccessError)

    expect(nextVault.getLastFailure()?.code).toBe('STORAGE_QUOTA_EXCEEDED')
    expect(removeSpy).not.toHaveBeenCalled()

    setSpy.mockRestore()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(storedBeforeFailure)

    const verifyVault = new CredentialVault()
    expect(await verifyVault.unlock('InitialPass#1')).toBe(true)
    expect(verifyVault.getSeeds()).toEqual(initialSeeds)
  })
})
