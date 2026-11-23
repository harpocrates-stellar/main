import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  CredentialVault,
  rehearseVaultRecovery,
  hasVaultRecoveryRehearsed,
  resetVaultRecoveryRehearsal,
  validateVaultEnvelope,
  type VaultEnvelope,
} from './credentialVault'
import { createIsolatedStateContainer } from './safeStorage'

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

  it('should validate envelope structure and reject invalid parameters', () => {
    expect(() => validateVaultEnvelope(null)).toThrow('Vault corrupted: envelope must be an object')
    expect(() => validateVaultEnvelope([])).toThrow('Vault corrupted: envelope must be an object')
    expect(() => validateVaultEnvelope({ v: 2, salt: 'aa', iv: 'bb', ct: 'cc' })).toThrow('Unsupported vault version: 2')
    expect(() => validateVaultEnvelope({ v: 1, salt: 'odd', iv: 'bb', ct: 'cc' })).toThrow('salt must be a non-empty hex string with even length')
    expect(() => validateVaultEnvelope({ v: 1, salt: 'aa', iv: '', ct: 'cc' })).toThrow('iv must be a non-empty hex string with even length')
    expect(() => validateVaultEnvelope({ v: 1, salt: 'aa', iv: 'bb', ct: 'not-hex!' })).toThrow('ct must be a non-empty hex string with even length')

    const valid: VaultEnvelope = { v: 1, salt: 'deadbeef', iv: '0102030405060708090a0b0c', ct: 'aabbccdd' }
    expect(validateVaultEnvelope(valid)).toEqual(valid)
  })

  it('should export and import vault through isolated containers', async () => {
    const isolatedContainer = createIsolatedStateContainer()
    const isolatedVault = new CredentialVault({ storage: isolatedContainer })

    // Exporting an empty vault throws
    expect(() => isolatedVault.exportVault()).toThrow('Vault is empty')

    const seeds = { credentialSeed: 'isolated-cred', nullifierSeed: 'isolated-null' }
    await isolatedVault.setup('testPass123!', seeds)

    const envelope = isolatedVault.exportVault()
    expect(envelope.v).toBe(1)
    expect(envelope.salt).toBeDefined()
    expect(envelope.iv).toBeDefined()
    expect(envelope.ct).toBeDefined()

    // Import into a target container
    const targetContainer = createIsolatedStateContainer()
    const targetVault = new CredentialVault({ storage: targetContainer })
    expect(targetVault.hasVault()).toBe(false)

    targetVault.importVault(envelope)
    expect(targetVault.hasVault()).toBe(true)
    expect(targetVault.isLocked()).toBe(true)

    // Unlocking target vault restores identical seeds
    const unlocked = await targetVault.unlock('testPass123!')
    expect(unlocked).toBe(true)
    expect(targetVault.getSeeds()).toEqual(seeds)

    // Window localStorage was not touched
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBeNull()
  })

  it('should reject importing malformed or corrupted envelopes', async () => {
    const isolatedContainer = createIsolatedStateContainer()
    const isolatedVault = new CredentialVault({ storage: isolatedContainer })

    expect(() => isolatedVault.importVault('invalid-json')).toThrow('Vault corrupted: unable to parse envelope')
    expect(() => isolatedVault.importVault({ v: 1, salt: 'invalid', iv: 'aa', ct: 'bb' } as unknown as VaultEnvelope))
      .toThrow('Unsupported vault parameter: salt must be a non-empty hex string with even length')
  })
})

describe('Vault Recovery Rehearsal with Synthetic Material', () => {
  beforeEach(() => {
    window.localStorage.clear()
    vi.useRealTimers()
  })

  afterEach(() => {
    window.localStorage.clear()
  })

  it('should execute a successful one-time vault recovery rehearsal without touching live credentials', async () => {
    // 1. Arrange: Setup existing real private credentials in window.localStorage
    const realSeeds = { credentialSeed: 'real-production-secret-1', nullifierSeed: 'real-production-secret-2' }
    const realVault = new CredentialVault()
    await realVault.setup('realMasterPassword#1', realSeeds)
    const initialRealEnvelope = window.localStorage.getItem('harpocrates:credential-vault')
    expect(initialRealEnvelope).not.toBeNull()

    // Status is initially false
    expect(hasVaultRecoveryRehearsed()).toBe(false)

    // 2. Act: Perform recovery rehearsal with synthetic material
    const result = await rehearseVaultRecovery()

    // 3. Assert: Verify rehearsal results
    expect(result.success).toBe(true)
    expect(result.syntheticSeedsVerified).toBe(true)
    expect(result.isolatedExportVerified).toBe(true)
    expect(result.isolatedImportVerified).toBe(true)
    expect(result.originalCredentialsUntouched).toBe(true)
    expect(result.rehearsalCompleted).toBe(true)
    expect(result.exportedEnvelope.v).toBe(1)
    expect(result.timestamp).toBeGreaterThan(0)

    // 4. Assert: Plaintext privacy - synthetic material never exposed unencrypted
    const exportedJson = JSON.stringify(result.exportedEnvelope)
    expect(exportedJson).not.toContain('synth_cred_')
    expect(exportedJson).not.toContain('synth_null_')

    // 5. Assert: Active user's real private credentials remain strictly unchanged and functional
    const postRehearsalEnvelope = window.localStorage.getItem('harpocrates:credential-vault')
    expect(postRehearsalEnvelope).toBe(initialRealEnvelope)

    // User can still unlock their real vault with their real password
    const restoredRealVault = new CredentialVault()
    const unlockedReal = await restoredRealVault.unlock('realMasterPassword#1')
    expect(unlockedReal).toBe(true)
    expect(restoredRealVault.getSeeds()).toEqual(realSeeds)

    // 6. Assert: One-time status is tracked in safe UI preferences
    expect(hasVaultRecoveryRehearsed()).toBe(true)

    // Resetting works
    resetVaultRecoveryRehearsal()
    expect(hasVaultRecoveryRehearsed()).toBe(false)
  }, 30000)

  it('should support instance method rehearseRecovery with custom synthetic material', async () => {
    const vaultInstance = new CredentialVault()
    const customSynthetic = {
      credentialSeed: 'synth_custom_credential_material_123',
      nullifierSeed: 'synth_custom_nullifier_material_456',
    }

    const result = await vaultInstance.rehearseRecovery({
      syntheticMaterial: customSynthetic,
      passphrase: 'RehearsalPassphrase#2026',
    })

    expect(result.success).toBe(true)
    expect(result.syntheticSeedsVerified).toBe(true)
    expect(result.isolatedExportVerified).toBe(true)
    expect(result.isolatedImportVerified).toBe(true)
    expect(result.originalCredentialsUntouched).toBe(true)
  }, 30000)

  it('should fail closed when recovery rehearsal passphrase does not match', async () => {
    const isolatedSource = createIsolatedStateContainer()
    const isolatedTarget = createIsolatedStateContainer()

    // Attempting rehearsal with an invalid unlock attempt
    const customSynthetic = {
      credentialSeed: 'synth_fail_cred_1',
      nullifierSeed: 'synth_fail_null_2',
    }

    // Set up source vault
    const sourceVault = new CredentialVault(15 * 60 * 1000, isolatedSource)
    await sourceVault.setup('correctPassphrase', customSynthetic)
    const exported = sourceVault.exportVault()

    // Import into target
    const destVault = new CredentialVault(15 * 60 * 1000, isolatedTarget)
    destVault.importVault(exported)

    // Attempt unlock with wrong passphrase
    const unlockSuccess = await destVault.unlock('wrongPassphrase')
    expect(unlockSuccess).toBe(false)
    expect(destVault.isLocked()).toBe(true)
    expect(destVault.getSeeds()).toBeNull()
  }, 30000)

  it('should fail closed if ciphertext in exported envelope is tampered', async () => {
    const isolatedSource = createIsolatedStateContainer()
    const isolatedTarget = createIsolatedStateContainer()

    const sourceVault = new CredentialVault(15 * 60 * 1000, isolatedSource)
    await sourceVault.setup('testPass', {
      credentialSeed: 'synth_1',
      nullifierSeed: 'synth_2',
    })

    const exported = sourceVault.exportVault()

    // Tamper ciphertext
    const tamperedCt = exported.ct.slice(0, -2) + (exported.ct.endsWith('00') ? 'ff' : '00')
    const tamperedEnvelope = { ...exported, ct: tamperedCt }

    const destVault = new CredentialVault(15 * 60 * 1000, isolatedTarget)
    destVault.importVault(tamperedEnvelope)

    // Decryption fails with invalid ciphertext
    const unlockSuccess = await destVault.unlock('testPass')
    expect(unlockSuccess).toBe(false)
    expect(destVault.isLocked()).toBe(true)
    expect(destVault.getSeeds()).toBeNull()
  }, 30000)
})
