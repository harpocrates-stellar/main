import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  CredentialVault,
  VAULT_FORMAT_COMPATIBILITY,
  getVaultFormatCompatibility,
  validateVaultEnvelope,
} from './credentialVault'

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

  it('should expose a frozen machine-readable vault format compatibility descriptor', () => {
    const descriptor = getVaultFormatCompatibility()
    expect(descriptor).toBe(VAULT_FORMAT_COMPATIBILITY)
    expect(Object.isFrozen(descriptor)).toBe(true)
    expect(Object.isFrozen(descriptor.supportedEnvelopeVersions)).toBe(true)
    expect(Object.isFrozen(descriptor.supportedKdfVersions)).toBe(true)
    expect(Object.isFrozen(descriptor.kdf)).toBe(true)
    expect(Object.isFrozen(descriptor.cipher)).toBe(true)

    expect(descriptor).toEqual({
      storageKey: 'harpocrates:credential-vault',
      currentEnvelopeVersion: 1,
      supportedEnvelopeVersions: [1],
      currentKdfVersion: 'pbkdf2-sha256-v1',
      supportedKdfVersions: ['pbkdf2-sha256-v1'],
      kdf: {
        id: 'pbkdf2-sha256-v1',
        algorithm: 'PBKDF2',
        hash: 'SHA-256',
        iterations: 600000,
        saltBytes: 16,
      },
      cipher: {
        algorithm: 'AES-GCM',
        keyLengthBits: 256,
        ivBytes: 12,
      },
      encoding: 'hex',
    })
  })

  it('should reject non-object envelopes and invalid required hex parameters consistently', async () => {
    expect(() => validateVaultEnvelope(null)).toThrow('Vault corrupted: envelope must be an object')
    expect(() => validateVaultEnvelope([])).toThrow('Vault corrupted: envelope must be an object')

    const validSalt = 'aa'.repeat(16)
    const validIv = 'bb'.repeat(12)
    const validCt = 'cc'.repeat(32)

    expect(validateVaultEnvelope({ v: 1, salt: validSalt, iv: validIv, ct: validCt })).toEqual({
      v: 1,
      salt: validSalt,
      iv: validIv,
      ct: validCt,
    })

    // Wrong salt length
    expect(() => validateVaultEnvelope({ v: 1, salt: 'aabb', iv: validIv, ct: validCt })).toThrow(
      'Unsupported vault parameter: salt must be 16 bytes (32 hex chars)'
    )
    // Non-hex iv
    expect(() => validateVaultEnvelope({ v: 1, salt: validSalt, iv: 'zz'.repeat(12), ct: validCt })).toThrow(
      'Unsupported vault parameter: iv must be a non-empty hex string'
    )
    // Empty or odd-length ct
    expect(() => validateVaultEnvelope({ v: 1, salt: validSalt, iv: validIv, ct: '' })).toThrow(
      'Unsupported vault parameter: ct must be a non-empty hex string'
    )
    expect(() => validateVaultEnvelope({ v: 1, salt: validSalt, iv: validIv, ct: 'abc' })).toThrow(
      'Unsupported vault parameter: ct must be a non-empty hex string'
    )

    // Unlock also rejects mutated required parameters
    window.localStorage.setItem(
      VAULT_FORMAT_COMPATIBILITY.storageKey,
      JSON.stringify({ v: 1, salt: 'deadbeef', iv: validIv, ct: validCt })
    )
    const restoredVault = new CredentialVault()
    await expect(restoredVault.unlock('secret')).rejects.toThrow(
      'Unsupported vault parameter: salt must be 16 bytes (32 hex chars)'
    )
  })

  it('should reject unsupported KDF or cipher parameter overrides consistently', async () => {
    const base = {
      v: 1,
      salt: 'aa'.repeat(16),
      iv: 'bb'.repeat(12),
      ct: 'cc'.repeat(32),
    }

    expect(() => validateVaultEnvelope({ ...base, kdf: 'argon2id-v1' })).toThrow(
      'Unsupported vault parameter: kdf "argon2id-v1"'
    )
    expect(() => validateVaultEnvelope({ ...base, cipher: 'AES-CBC' })).toThrow(
      'Unsupported vault parameter: cipher "AES-CBC"'
    )
    expect(() => validateVaultEnvelope({ ...base, iterations: 1000 })).toThrow(
      'Unsupported vault parameter: iterations "1000"'
    )
    expect(() => validateVaultEnvelope({ ...base, hash: 'SHA-512' })).toThrow(
      'Unsupported vault parameter: hash "SHA-512"'
    )
    expect(() => validateVaultEnvelope({ ...base, keyLengthBits: 128 })).toThrow(
      'Unsupported vault parameter: keyLengthBits "128"'
    )

    // Matching explicit parameters are accepted
    expect(
      validateVaultEnvelope({
        ...base,
        kdf: 'pbkdf2-sha256-v1',
        cipher: 'AES-GCM',
        iterations: 600000,
        hash: 'SHA-256',
        keyLengthBits: 256,
      })
    ).toMatchObject(base)
  })
})
