import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  CredentialVault,
  MAX_VAULT_CIPHERTEXT_BYTES,
  MAX_VAULT_ENVELOPE_BYTES,
  VaultEnvelopeSizeError,
  parseVaultEnvelope,
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

  it('should export and import a valid vault envelope', async () => {
    const seeds = { credentialSeed: 'export-cred', nullifierSeed: 'export-null' }
    await vault.setup('passphrase-1', seeds)

    const exported = vault.exportEnvelope()
    expect(exported).not.toBeNull()

    window.localStorage.clear()
    const targetVault = new CredentialVault()
    expect(targetVault.hasVault()).toBe(false)

    const imported = await targetVault.importEnvelope(exported!, 'passphrase-1')
    expect(imported).toBe(true)
    expect(targetVault.isLocked()).toBe(false)
    expect(targetVault.hasVault()).toBe(true)
    expect(targetVault.getSeeds()).toEqual(seeds)
  })

  it('should accept an imported envelope at the exact MAX_VAULT_ENVELOPE_BYTES boundary', async () => {
    const seeds = { credentialSeed: 'boundary-cred', nullifierSeed: 'boundary-null' }
    await vault.setup('boundary-pass', seeds)
    const exported = vault.exportEnvelope()!

    const padLength = MAX_VAULT_ENVELOPE_BYTES - new TextEncoder().encode(exported).byteLength
    expect(padLength).toBeGreaterThan(0)
    const exactBoundaryEnvelope = `${exported}${' '.repeat(padLength)}`
    expect(new TextEncoder().encode(exactBoundaryEnvelope).byteLength).toBe(MAX_VAULT_ENVELOPE_BYTES)

    window.localStorage.clear()
    const targetVault = new CredentialVault()
    const imported = await targetVault.importEnvelope(exactBoundaryEnvelope, 'boundary-pass')
    expect(imported).toBe(true)
    expect(targetVault.getSeeds()).toEqual(seeds)
  })

  it('should reject oversized imported envelope before key derivation and preserve existing vault', async () => {
    const existingSeeds = { credentialSeed: 'keep-cred', nullifierSeed: 'keep-null' }
    await vault.setup('existing-pass', existingSeeds)
    const existingStored = window.localStorage.getItem('harpocrates:credential-vault')!

    const importKeySpy = vi.spyOn(crypto.subtle, 'importKey')
    const deriveKeySpy = vi.spyOn(crypto.subtle, 'deriveKey')

    const oversized = `${existingStored}${' '.repeat(MAX_VAULT_ENVELOPE_BYTES - existingStored.length + 1)}`
    expect(new TextEncoder().encode(oversized).byteLength).toBe(MAX_VAULT_ENVELOPE_BYTES + 1)

    await expect(vault.importEnvelope(oversized, 'any-pass')).rejects.toBeInstanceOf(VaultEnvelopeSizeError)
    expect(importKeySpy).not.toHaveBeenCalled()
    expect(deriveKeySpy).not.toHaveBeenCalled()

    // Existing encrypted vault and in-memory state are preserved
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(existingStored)
    expect(vault.isLocked()).toBe(false)
    expect(vault.getSeeds()).toEqual(existingSeeds)

    const freshVault = new CredentialVault()
    await expect(freshVault.unlock('existing-pass')).resolves.toBe(true)
    expect(freshVault.getSeeds()).toEqual(existingSeeds)
  })

  it('should reject multi-byte UTF-8 envelope exceeding MAX_VAULT_ENVELOPE_BYTES before key derivation', async () => {
    const existingSeeds = { credentialSeed: 'utf8-cred', nullifierSeed: 'utf8-null' }
    await vault.setup('utf8-pass', existingSeeds)
    const existingStored = window.localStorage.getItem('harpocrates:credential-vault')!

    const importKeySpy = vi.spyOn(crypto.subtle, 'importKey')
    const deriveKeySpy = vi.spyOn(crypto.subtle, 'deriveKey')

    // Each 'é' is 1 UTF-16 code unit but 2 UTF-8 bytes, so .length <= max while UTF-8 bytes > max
    const multiByteOversized = 'é'.repeat(Math.floor(MAX_VAULT_ENVELOPE_BYTES / 2) + 1)
    expect(multiByteOversized.length).toBeLessThanOrEqual(MAX_VAULT_ENVELOPE_BYTES)
    expect(new TextEncoder().encode(multiByteOversized).byteLength).toBeGreaterThan(MAX_VAULT_ENVELOPE_BYTES)

    await expect(vault.importEnvelope(multiByteOversized, 'any-pass')).rejects.toBeInstanceOf(VaultEnvelopeSizeError)
    expect(importKeySpy).not.toHaveBeenCalled()
    expect(deriveKeySpy).not.toHaveBeenCalled()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(existingStored)
  })

  it('should enforce MAX_VAULT_CIPHERTEXT_BYTES boundary before decoding ciphertext or deriving keys', async () => {
    const existingSeeds = { credentialSeed: 'ct-cred', nullifierSeed: 'ct-null' }
    await vault.setup('ct-pass', existingSeeds)
    const existingStored = window.localStorage.getItem('harpocrates:credential-vault')!

    const validSalt = 'aa'.repeat(16)
    const validIv = 'bb'.repeat(12)

    // Exact ciphertext byte limit passes parseVaultEnvelope
    const exactCtEnvelope = JSON.stringify({
      v: 1,
      salt: validSalt,
      iv: validIv,
      ct: 'cc'.repeat(MAX_VAULT_CIPHERTEXT_BYTES),
    })
    expect(parseVaultEnvelope(exactCtEnvelope).ct.length).toBe(MAX_VAULT_CIPHERTEXT_BYTES * 2)

    // One byte over ciphertext limit is rejected before PBKDF2 even when outer JSON < MAX_VAULT_ENVELOPE_BYTES
    const oversizedCtEnvelope = JSON.stringify({
      v: 1,
      salt: validSalt,
      iv: validIv,
      ct: 'cc'.repeat(MAX_VAULT_CIPHERTEXT_BYTES + 1),
    })
    expect(new TextEncoder().encode(oversizedCtEnvelope).byteLength).toBeLessThan(MAX_VAULT_ENVELOPE_BYTES)

    const importKeySpy = vi.spyOn(crypto.subtle, 'importKey')
    const deriveKeySpy = vi.spyOn(crypto.subtle, 'deriveKey')

    await expect(vault.importEnvelope(oversizedCtEnvelope, 'any-pass')).rejects.toBeInstanceOf(
      VaultEnvelopeSizeError
    )
    expect(importKeySpy).not.toHaveBeenCalled()
    expect(deriveKeySpy).not.toHaveBeenCalled()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(existingStored)
  })

  it('should preserve existing encrypted vault when import fails with wrong password or malformed input', async () => {
    const existingSeeds = { credentialSeed: 'orig-cred', nullifierSeed: 'orig-null' }
    await vault.setup('orig-pass', existingSeeds)
    const existingStored = window.localStorage.getItem('harpocrates:credential-vault')!

    // Prepare a second valid envelope in an isolated vault
    const otherSeeds = { credentialSeed: 'other-cred', nullifierSeed: 'other-null' }
    const tempVault = new CredentialVault()
    await tempVault.setup('other-pass', otherSeeds)
    const otherEnvelope = tempVault.exportEnvelope()!

    // Restore original encrypted vault into localStorage
    window.localStorage.setItem('harpocrates:credential-vault', existingStored)

    // Wrong password on valid-sized envelope returns false and preserves original vault
    await expect(vault.importEnvelope(otherEnvelope, 'wrong-pass')).resolves.toBe(false)
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(existingStored)
    expect(vault.getSeeds()).toEqual(existingSeeds)

    // Malformed hex encoding throws before key derivation and preserves original vault
    const deriveKeySpy = vi.spyOn(crypto.subtle, 'deriveKey')
    const badHexEnvelope = JSON.stringify({
      v: 1,
      salt: 'zz'.repeat(16),
      iv: 'bb'.repeat(12),
      ct: 'cc'.repeat(32),
    })
    await expect(vault.importEnvelope(badHexEnvelope, 'orig-pass')).rejects.toThrow(
      'Vault corrupted: invalid salt encoding'
    )
    expect(deriveKeySpy).not.toHaveBeenCalled()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(existingStored)
  })

  it('should reject oversized stored vault envelope during unlock before key derivation', async () => {
    const oversizedStored = JSON.stringify({
      v: 1,
      salt: 'aa'.repeat(16),
      iv: 'bb'.repeat(12),
      ct: 'cc'.repeat(MAX_VAULT_ENVELOPE_BYTES),
    })
    window.localStorage.setItem('harpocrates:credential-vault', oversizedStored)

    const importKeySpy = vi.spyOn(crypto.subtle, 'importKey')
    const deriveKeySpy = vi.spyOn(crypto.subtle, 'deriveKey')

    const restoredVault = new CredentialVault()
    await expect(restoredVault.unlock('secret')).rejects.toBeInstanceOf(VaultEnvelopeSizeError)
    expect(importKeySpy).not.toHaveBeenCalled()
    expect(deriveKeySpy).not.toHaveBeenCalled()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(oversizedStored)
  })
})
