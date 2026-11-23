import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  CredentialVault,
  VAULT_BACKUP_STORAGE_KEY,
  VAULT_STORAGE_KEY,
  VAULT_VERSION,
  VAULT_VERSION_V1,
  VaultMigrationError,
  VaultValidationError,
} from './credentialVault'
import type { SafeStorageLike } from './safeStorage'

function bufToHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function createLegacyV1Envelope(
  password: string,
  payload: Record<string, unknown>
): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  )
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as unknown as ArrayBuffer,
      iterations: 600000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as ArrayBuffer },
    key,
    enc.encode(JSON.stringify(payload))
  )
  return JSON.stringify({
    v: VAULT_VERSION_V1,
    salt: bufToHex(salt as unknown as ArrayBuffer),
    iv: bufToHex(iv as unknown as ArrayBuffer),
    ct: bufToHex(ct),
  })
}

describe('CredentialVault', () => {
  let vault: CredentialVault

  beforeEach(() => {
    window.localStorage.clear()
    vi.useFakeTimers()
    vault = new CredentialVault()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('should initially be locked and empty', () => {
    expect(vault.isLocked()).toBe(true)
    expect(vault.getSeeds()).toBeNull()
    expect(vault.hasVault()).toBe(false)
  })

  it('should setup, unlock, and return seeds', async () => {
    const seeds = { credentialSeed: 'cred123', nullifierSeed: 'null456' }
    await vault.setup('myPassword123!', seeds)

    expect(vault.isLocked()).toBe(false)
    expect(vault.hasVault()).toBe(true)
    expect(vault.getSeeds()).toEqual(seeds)
  })

  it('should lock the vault on demand', async () => {
    const seeds = { credentialSeed: 'cred123', nullifierSeed: 'null456' }
    await vault.setup('pass', seeds)
    expect(vault.isLocked()).toBe(false)

    vault.lock()
    expect(vault.isLocked()).toBe(true)
    expect(vault.getSeeds()).toBeNull()
  })

  it('should lock automatically after inactivity timeout', async () => {
    const seeds = { credentialSeed: 'test', nullifierSeed: 'test2' }
    // 1 minute timeout for test
    const fastVault = new CredentialVault(60 * 1000)
    await fastVault.setup('pass', seeds)

    expect(fastVault.isLocked()).toBe(false)

    vi.advanceTimersByTime(30 * 1000)
    expect(fastVault.isLocked()).toBe(false) // 30s elapsed

    // Reset timeout by fetching seeds
    fastVault.getSeeds()

    vi.advanceTimersByTime(45 * 1000)
    expect(fastVault.isLocked()).toBe(false) // 45s elapsed since reset

    vi.advanceTimersByTime(20 * 1000)
    expect(fastVault.isLocked()).toBe(true) // 65s elapsed since reset, should lock
  })

  it('should restore from localStorage correctly with valid password', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    
    // Simulate page reload
    const restoredVault = new CredentialVault()
    expect(restoredVault.hasVault()).toBe(true)
    expect(restoredVault.isLocked()).toBe(true)

    const success = await restoredVault.unlock('secret')
    expect(success).toBe(true)
    expect(restoredVault.isLocked()).toBe(false)
    expect(restoredVault.getSeeds()).toEqual(seeds)
  })

  it('should fail to unlock with invalid password', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    
    const restoredVault = new CredentialVault()
    const success = await restoredVault.unlock('wrong')
    
    expect(success).toBe(false)
    expect(restoredVault.isLocked()).toBe(true)
  })

  it('should completely destroy vault data', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    expect(vault.hasVault()).toBe(true)

    vault.destroy()
    expect(vault.hasVault()).toBe(false)
    expect(vault.isLocked()).toBe(true)
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBeNull()
  })

  it('should detect unsupported vault versions', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    
    // Mutate version in localStorage
    const stored = JSON.parse(window.localStorage.getItem('harpocrates:credential-vault')!)
    stored.v = 999
    window.localStorage.setItem('harpocrates:credential-vault', JSON.stringify(stored))

    const restoredVault = new CredentialVault()
    await expect(restoredVault.unlock('secret')).rejects.toThrow('Unsupported vault version: 999')
  })

  it('should detect completely corrupted envelopes', async () => {
    window.localStorage.setItem('harpocrates:credential-vault', 'this is not valid json')
    const restoredVault = new CredentialVault()
    await expect(restoredVault.unlock('secret')).rejects.toThrow('Vault corrupted: unable to parse envelope')
  })

  describe('staged format migration (v1 -> v2)', () => {
    it('decrypts and validates in isolated memory, verifies v2, and replaces v1 storage', async () => {
      const seeds = { credentialSeed: 'legacy-cred-1', nullifierSeed: 'legacy-null-2' }
      const legacyRaw = await createLegacyV1Envelope('migration-pass', seeds)
      window.localStorage.setItem(VAULT_STORAGE_KEY, legacyRaw)

      const migrator = new CredentialVault()
      expect(migrator.getVaultVersion()).toBe(VAULT_VERSION_V1)
      expect(migrator.needsMigration()).toBe(true)

      const result = await migrator.migrate('migration-pass')
      expect(result).toEqual({
        migrated: true,
        fromVersion: VAULT_VERSION_V1,
        toVersion: VAULT_VERSION,
      })

      // Migration operates in isolated memory and leaves the vault locked.
      expect(migrator.isLocked()).toBe(true)
      expect(migrator.getSeeds()).toBeNull()
      expect(migrator.hasBackup()).toBe(false)
      expect(migrator.getVaultVersion()).toBe(VAULT_VERSION)
      expect(migrator.needsMigration()).toBe(false)

      const storedAfter = JSON.parse(window.localStorage.getItem(VAULT_STORAGE_KEY)!)
      expect(storedAfter.v).toBe(VAULT_VERSION)
      expect(storedAfter.kdf).toBe('PBKDF2-SHA256')
      expect(storedAfter.cipher).toBe('AES-GCM-256')

      // Unlocking the migrated v2 vault returns the exact original seeds.
      expect(await migrator.unlock('migration-pass')).toBe(true)
      expect(migrator.getSeeds()).toEqual(seeds)

      // Subsequent migrate() call is a no-op.
      const second = await migrator.migrate('migration-pass')
      expect(second).toEqual({
        migrated: false,
        fromVersion: VAULT_VERSION,
        toVersion: VAULT_VERSION,
      })
    }, 20000)

    it('automatically stages migration during unlock of a legacy v1 vault', async () => {
      const seeds = { credentialSeed: 'auto-cred', nullifierSeed: 'auto-null' }
      const legacyRaw = await createLegacyV1Envelope('auto-pass', seeds)
      window.localStorage.setItem(VAULT_STORAGE_KEY, legacyRaw)

      const restored = new CredentialVault()
      expect(await restored.unlock('auto-pass')).toBe(true)
      expect(restored.getSeeds()).toEqual(seeds)
      expect(restored.getVaultVersion()).toBe(VAULT_VERSION)
      expect(restored.hasBackup()).toBe(false)
    }, 20000)

    it('preserves the previous v1 envelope when unlocking with the wrong password', async () => {
      const seeds = { credentialSeed: 'keep-cred', nullifierSeed: 'keep-null' }
      const legacyRaw = await createLegacyV1Envelope('right-pass', seeds)
      window.localStorage.setItem(VAULT_STORAGE_KEY, legacyRaw)

      const restored = new CredentialVault()
      expect(await restored.unlock('wrong-pass')).toBe(false)
      expect(restored.isLocked()).toBe(true)
      expect(window.localStorage.getItem(VAULT_STORAGE_KEY)).toBe(legacyRaw)
      expect(window.localStorage.getItem(VAULT_BACKUP_STORAGE_KEY)).toBeNull()
    })

    it('fails closed and preserves v1 storage when decrypted payload fails validation', async () => {
      const legacyRaw = await createLegacyV1Envelope('valid-pass', {
        credentialSeed: '',
        nullifierSeed: 'only-one-seed',
      })
      window.localStorage.setItem(VAULT_STORAGE_KEY, legacyRaw)

      const migrator = new CredentialVault()
      await expect(migrator.migrate('valid-pass')).rejects.toThrow(VaultValidationError)
      expect(migrator.isLocked()).toBe(true)
      expect(window.localStorage.getItem(VAULT_STORAGE_KEY)).toBe(legacyRaw)
      expect(window.localStorage.getItem(VAULT_BACKUP_STORAGE_KEY)).toBeNull()
    })

    it('preserves the previous v1 envelope when staged v2 verification fails', async () => {
      const seeds = { credentialSeed: 'verify-cred', nullifierSeed: 'verify-null' }
      const legacyRaw = await createLegacyV1Envelope('verify-pass', seeds)
      window.localStorage.setItem(VAULT_STORAGE_KEY, legacyRaw)

      const migrator = new CredentialVault()
      await expect(
        migrator.migrate('verify-pass', {
          verifyEnvelope: async () => {
            throw new VaultMigrationError('Simulated verification failure')
          },
        })
      ).rejects.toThrow('Simulated verification failure')

      expect(migrator.isLocked()).toBe(true)
      expect(window.localStorage.getItem(VAULT_STORAGE_KEY)).toBe(legacyRaw)
      expect(window.localStorage.getItem(VAULT_BACKUP_STORAGE_KEY)).toBeNull()
    })

    it('preserves the previous encrypted envelope if replacing primary storage fails', async () => {
      const seeds = { credentialSeed: 'disk-cred', nullifierSeed: 'disk-null' }
      const legacyRaw = await createLegacyV1Envelope('disk-pass', seeds)

      const backing = new Map<string, string>([[VAULT_STORAGE_KEY, legacyRaw]])
      let failPrimaryWrite = true
      const flakyStorage: SafeStorageLike = {
        getItem: (key) => backing.get(key) ?? null,
        setItem: (key, value) => {
          if (key === VAULT_STORAGE_KEY && failPrimaryWrite) {
            failPrimaryWrite = false
            throw new Error('QuotaExceededError')
          }
          backing.set(key, value)
        },
        removeItem: (key) => {
          backing.delete(key)
        },
      }

      const migrator = new CredentialVault({ storage: flakyStorage })
      await expect(migrator.migrate('disk-pass')).rejects.toThrow(VaultMigrationError)
      expect(migrator.isLocked()).toBe(true)
      expect(backing.get(VAULT_STORAGE_KEY)).toBe(legacyRaw)
      expect(backing.get(VAULT_BACKUP_STORAGE_KEY)).toBe(legacyRaw)
    }, 20000)
  })
})
