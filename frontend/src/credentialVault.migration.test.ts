import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  CredentialVault,
  VAULT_VERSION,
  VAULT_VERSION_V2,
  VaultMigrationError,
  createLegacyV0VaultEnvelope,
} from './credentialVault'
import { createIsolatedMigrationWorkspace } from './safeStorage'

describe('Staged credential vault format migration (#1144)', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('migrates v1 -> v2 through isolated decrypt, validation, candidate verification, and single post-verify storage write', async () => {
    const setupVault = new CredentialVault()
    const originalSeeds = {
      credentialSeed: 'staged-migration-cred-001',
      nullifierSeed: 'staged-migration-null-002',
    }
    await setupVault.setup('MigrationPass#2026!', originalSeeds)
    setupVault.lock()

    const callOrder: string[] = []
    const origDecrypt = crypto.subtle.decrypt.bind(crypto.subtle)
    const origEncrypt = crypto.subtle.encrypt.bind(crypto.subtle)
    const origSetItem = window.localStorage.setItem.bind(window.localStorage)

    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
      callOrder.push('decrypt')
      return origDecrypt(...args)
    })
    vi.spyOn(crypto.subtle, 'encrypt').mockImplementation(async (...args) => {
      callOrder.push('encrypt')
      return origEncrypt(...args)
    })
    const setItemSpy = vi
      .spyOn(window.localStorage, 'setItem')
      .mockImplementation((k: string, v: string) => {
        callOrder.push(`setItem:${k}`)
        origSetItem(k, v)
      })

    const migratingVault = new CredentialVault()
    expect(migratingVault.needsMigration(VAULT_VERSION_V2)).toBe(true)

    const result = await migratingVault.migrateFormat('MigrationPass#2026!', {
      targetVersion: VAULT_VERSION_V2,
      unlockAfterMigration: true,
    })

    expect(result).toEqual({
      status: 'migrated',
      fromVersion: 1,
      toVersion: 2,
      stagesCompleted: [
        'snapshot',
        'isolated-decrypt-and-validate',
        'isolated-encrypt-and-verify',
        'atomic-storage-commit',
      ],
      isolatedWorkspaceDisposed: true,
    })

    // Storage write happens ONCE and strictly AFTER source decrypt, candidate encrypt, and candidate verify decrypt!
    expect(setItemSpy).toHaveBeenCalledTimes(1)
    expect(callOrder).toEqual([
      'decrypt', // Stage 2: isolated source decrypt
      'encrypt', // Stage 3: isolated candidate encrypt
      'decrypt', // Stage 3: isolated candidate verification decrypt
      'setItem:harpocrates:credential-vault', // Stage 4: post-verification storage replacement
    ])

    expect(migratingVault.getStoredFormatVersion()).toBe(VAULT_VERSION_V2)
    expect(migratingVault.needsMigration(VAULT_VERSION_V2)).toBe(false)
    expect(migratingVault.getSeeds()).toEqual(originalSeeds)

    // Reloaded vault unlocks v2 envelope cleanly and rejects tampered AAD version header
    const reloadedVault = new CredentialVault()
    expect(await reloadedVault.unlock('MigrationPass#2026!')).toBe(true)
    expect(reloadedVault.getSeeds()).toEqual(originalSeeds)
  })

  it('migrates legacy v0 envelopes into v1 or v2 while blocking direct unmigrated v0 unlock', async () => {
    const legacySeeds = {
      credentialSeed: 'legacy-v0-cred',
      nullifierSeed: 'legacy-v0-null',
    }
    const v0Envelope = await createLegacyV0VaultEnvelope('LegacyPass#0', legacySeeds)
    window.localStorage.setItem(
      'harpocrates:credential-vault',
      JSON.stringify(v0Envelope),
    )

    const vault = new CredentialVault()
    await expect(vault.unlock('LegacyPass#0')).rejects.toThrow(
      'Legacy vault version 0 requires staged format migration before unlocking',
    )

    const migrated = await vault.migrateFormat('LegacyPass#0', {
      targetVersion: VAULT_VERSION,
      unlockAfterMigration: true,
    })
    expect(migrated.fromVersion).toBe(0)
    expect(migrated.toVersion).toBe(1)
    expect(vault.getSeeds()).toEqual(legacySeeds)

    const freshVault = new CredentialVault()
    expect(await freshVault.unlock('LegacyPass#0')).toBe(true)
    expect(freshVault.getSeeds()).toEqual(legacySeeds)
  })

  it('preserves the previous encrypted envelope byte-for-byte when candidate verification fails in Stage 3', async () => {
    const vault = new CredentialVault()
    const seeds = {
      credentialSeed: 'must-survive-cred',
      nullifierSeed: 'must-survive-null',
    }
    await vault.setup('SafePass#1', seeds)
    vault.lock()

    const previousEncryptedRaw = window.localStorage.getItem(
      'harpocrates:credential-vault',
    )!
    const setItemSpy = vi.spyOn(window.localStorage, 'setItem')

    await expect(
      vault.migrateFormat('SafePass#1', {
        targetVersion: VAULT_VERSION_V2,
        transformCandidateBeforeVerify: (candidateJson) => {
          const parsed = JSON.parse(candidateJson)
          // Flip the first byte of candidate ciphertext so Stage 3 verification fails
          const firstByte = parseInt(parsed.ct.slice(0, 2), 16) ^ 0xff
          parsed.ct = firstByte.toString(16).padStart(2, '0') + parsed.ct.slice(2)
          return JSON.stringify(parsed)
        },
      }),
    ).rejects.toMatchObject({
      name: 'VaultMigrationError',
      stage: 'isolated-encrypt-and-verify',
    })

    // Previous encrypted envelope was NEVER overwritten
    expect(setItemSpy).not.toHaveBeenCalled()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(
      previousEncryptedRaw,
    )

    // Original v1 vault still unlocks cleanly
    expect(await vault.unlock('SafePass#1')).toBe(true)
    expect(vault.getSeeds()).toEqual(seeds)
  })

  it('preserves previous encrypted envelope on wrong passphrase (Stage 2) and on storage quota failure (Stage 4)', async () => {
    const vault = new CredentialVault()
    const seeds = {
      credentialSeed: 'stage-guard-cred',
      nullifierSeed: 'stage-guard-null',
    }
    await vault.setup('CorrectPass#1', seeds)
    const previousRaw = window.localStorage.getItem('harpocrates:credential-vault')!

    // Stage 2 failure: wrong passphrase
    await expect(
      vault.migrateFormat('WrongPass#99', { targetVersion: VAULT_VERSION_V2 }),
    ).rejects.toEqual(
      expect.objectContaining({
        name: 'VaultMigrationError',
        stage: 'isolated-decrypt-and-validate',
      }),
    )
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(previousRaw)

    // Stage 4 failure: storage throws QuotaExceededError during final commit
    const setSpy = vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => {
      const err = new Error('QuotaExceededError')
      err.name = 'QuotaExceededError'
      throw err
    })

    await expect(
      vault.migrateFormat('CorrectPass#1', { targetVersion: VAULT_VERSION_V2 }),
    ).rejects.toThrow(VaultMigrationError)

    setSpy.mockRestore()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(previousRaw)

    const verifyVault = new CredentialVault()
    expect(await verifyVault.unlock('CorrectPass#1')).toBe(true)
    expect(verifyVault.getSeeds()).toEqual(seeds)
  })

  it('zeroes isolated staging buffers deterministically on disposal', () => {
    const workspace = createIsolatedMigrationWorkspace()
    const source = new Uint8Array([10, 20, 30, 40])
    const staged = workspace.stagePlaintextBuffer(source)
    expect([...staged]).toEqual([10, 20, 30, 40])

    workspace.stageCandidateEnvelope('{"v":2}')
    expect(workspace.readCandidateEnvelope()).toBe('{"v":2}')

    workspace.disposeAndZero()
    expect(workspace.isDisposed()).toBe(true)
    expect([...staged]).toEqual([0, 0, 0, 0])
    expect(() => workspace.readCandidateEnvelope()).toThrow(
      'Isolated migration workspace has already been disposed',
    )
  })
})
