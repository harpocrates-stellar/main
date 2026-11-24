import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  CredentialVault,
  VAULT_STORAGE_KEY,
  type VaultEvent,
} from './credentialVault'

describe('CredentialVault', () => {
  let vault: CredentialVault

  beforeEach(() => {
    window.localStorage.clear()
    vi.useFakeTimers()
    vault = new CredentialVault()
  })

  afterEach(() => {
    vault.dispose()
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('should initially be locked and empty', () => {
    expect(vault.isLocked()).toBe(true)
    expect(vault.getSeeds()).toBeNull()
    expect(vault.hasVault()).toBe(false)
    expect(vault.getStatus()).toBe('locked')
    expect(vault.isStale()).toBe(false)
  })

  it('should setup, unlock, and return seeds', async () => {
    const seeds = { credentialSeed: 'cred123', nullifierSeed: 'null456' }
    await vault.setup('myPassword123!', seeds)

    expect(vault.isLocked()).toBe(false)
    expect(vault.hasVault()).toBe(true)
    expect(vault.getSeeds()).toEqual(seeds)
    expect(vault.getStatus()).toBe('unlocked')
  })

  it('should lock the vault on demand', async () => {
    const seeds = { credentialSeed: 'cred123', nullifierSeed: 'null456' }
    await vault.setup('pass', seeds)
    expect(vault.isLocked()).toBe(false)

    vault.lock()
    expect(vault.isLocked()).toBe(true)
    expect(vault.getSeeds()).toBeNull()
    expect(vault.getStatus()).toBe('locked')
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
    fastVault.dispose()
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
    restoredVault.dispose()
  })

  it('should fail to unlock with invalid password', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    
    const restoredVault = new CredentialVault()
    const success = await restoredVault.unlock('wrong')
    
    expect(success).toBe(false)
    expect(restoredVault.isLocked()).toBe(true)
    restoredVault.dispose()
  })

  it('should completely destroy vault data', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    expect(vault.hasVault()).toBe(true)

    vault.destroy()
    expect(vault.hasVault()).toBe(false)
    expect(vault.isLocked()).toBe(true)
    expect(window.localStorage.getItem(VAULT_STORAGE_KEY)).toBeNull()
  })

  it('should detect unsupported vault versions', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    
    // Mutate version in localStorage
    const stored = JSON.parse(window.localStorage.getItem(VAULT_STORAGE_KEY)!)
    stored.v = 999
    window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(stored))

    const restoredVault = new CredentialVault()
    await expect(restoredVault.unlock('secret')).rejects.toThrow('Unsupported vault version: 999')
    restoredVault.dispose()
  })

  it('should detect completely corrupted envelopes', async () => {
    window.localStorage.setItem(VAULT_STORAGE_KEY, 'this is not valid json')
    const restoredVault = new CredentialVault()
    await expect(restoredVault.unlock('secret')).rejects.toThrow('Vault corrupted: unable to parse envelope')
    restoredVault.dispose()
  })

  describe('cross-tab change detection and active work recovery', () => {
    it('invalidates an unlocked view when another tab updates the envelope', async () => {
      const seedsA = { credentialSeed: 'seedA-cred', nullifierSeed: 'seedA-null' }
      await vault.setup('passwordA', seedsA)
      expect(vault.isLocked()).toBe(false)
      expect(vault.isStale()).toBe(false)

      const events: VaultEvent[] = []
      vault.subscribe((e) => events.push(e))

      // Another tab writes a newly updated envelope
      const otherTabVault = new CredentialVault()
      const seedsB = { credentialSeed: 'seedB-cred', nullifierSeed: 'seedB-null' }
      await otherTabVault.setup('passwordB', seedsB)
      otherTabVault.dispose()

      // Simulate the browser cross-tab StorageEvent
      const newStoredEnvelope = window.localStorage.getItem(VAULT_STORAGE_KEY)
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: newStoredEnvelope,
          storageArea: window.localStorage,
        })
      )

      // Unlocked view must now be invalidated
      expect(vault.isStale()).toBe(true)
      expect(vault.isLocked()).toBe(true)
      expect(vault.getStatus()).toBe('stale')
      expect(vault.getStaleReason()).toBe('envelope-updated')

      // Normal seed access fails-closed to prevent using stale witness material
      expect(vault.getSeeds()).toBeNull()

      // Active work is preserved in quarantine
      expect(vault.hasPreservedWork()).toBe(true)
      const preserved = vault.getPreservedWork()
      expect(preserved).not.toBeNull()
      expect(preserved?.seeds).toEqual(seedsA)
      expect(preserved?.staleReason).toBe('envelope-updated')

      // Event listener was notified
      expect(events).toHaveLength(1)
      expect(events[0].type).toBe('stale')
    })

    it('preserves custom active work registered before invalidation', async () => {
      const seeds = { credentialSeed: 'my-seed', nullifierSeed: 'my-nullifier' }
      await vault.setup('pass1', seeds)

      // User registers in-progress draft statement and metadata
      vault.setActiveWork({
        statementDraft: 'Proof of citizenship witness draft #42',
        tier: 'silent',
      })
      expect(vault.getActiveWork()).toEqual({
        statementDraft: 'Proof of citizenship witness draft #42',
        tier: 'silent',
      })

      // Cross-tab modification occurs
      window.localStorage.setItem(
        VAULT_STORAGE_KEY,
        JSON.stringify({ v: 1, salt: '11', iv: '22', ct: '33' })
      )
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )

      expect(vault.isStale()).toBe(true)
      const preserved = vault.getPreservedWork()
      expect(preserved?.customData).toEqual({
        statementDraft: 'Proof of citizenship witness draft #42',
        tier: 'silent',
      })
      expect(preserved?.seeds).toEqual(seeds)
    })

    it('recovers via "discard": cleans up preserved work and locks vault', async () => {
      const seeds = { credentialSeed: 'cred', nullifierSeed: 'null' }
      await vault.setup('pass', seeds)

      // Cross-tab modification
      window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify({ v: 1, salt: 'aa', iv: 'bb', ct: 'cc' }))
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )
      expect(vault.isStale()).toBe(true)

      // User chooses recovery action 'discard'
      await vault.recover('discard')

      expect(vault.isStale()).toBe(false)
      expect(vault.isLocked()).toBe(true)
      expect(vault.getStatus()).toBe('locked')
      expect(vault.hasPreservedWork()).toBe(false)
      expect(vault.getPreservedWork()).toBeNull()
      expect(vault.getSeeds()).toBeNull()
    })

    it('recovers via "overwrite": re-encrypts preserved work and restores unlocked state', async () => {
      const seedsA = { credentialSeed: 'seedA-keep-me', nullifierSeed: 'seedA-nullifier' }
      await vault.setup('originalPass', seedsA)

      // External tab wrote seedsB
      const otherVault = new CredentialVault()
      const seedsB = { credentialSeed: 'seedB-remote', nullifierSeed: 'seedB-nullifier' }
      await otherVault.setup('remotePass', seedsB)
      otherVault.dispose()

      // Dispatch cross-tab storage update
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )
      expect(vault.isStale()).toBe(true)

      // User chooses to keep local active work and overwrite remote vault
      await vault.recover('overwrite', { password: 'newLocalPass123!' })

      expect(vault.isStale()).toBe(false)
      expect(vault.isLocked()).toBe(false)
      expect(vault.getStatus()).toBe('unlocked')
      expect(vault.hasPreservedWork()).toBe(false)
      expect(vault.getSeeds()).toEqual(seedsA)

      // Verify stored vault now decrypts with newLocalPass123! to seedsA
      const verifyVault = new CredentialVault()
      const unlocked = await verifyVault.unlock('newLocalPass123!')
      expect(unlocked).toBe(true)
      expect(verifyVault.getSeeds()).toEqual(seedsA)
      verifyVault.dispose()
    }, 25000)

    it('recovers via "reload": unlocks new envelope when password is provided', async () => {
      const seedsA = { credentialSeed: 'seedA', nullifierSeed: 'nullA' }
      await vault.setup('passA', seedsA)

      // Another tab sets up passB and seedsB
      const otherVault = new CredentialVault()
      const seedsB = { credentialSeed: 'seedB', nullifierSeed: 'nullB' }
      await otherVault.setup('passB', seedsB)
      otherVault.dispose()

      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )
      expect(vault.isStale()).toBe(true)

      // User chooses 'reload' and inputs the new password
      const success = await vault.recover('reload', { password: 'passB' })
      expect(success).toBe(true)
      expect(vault.isStale()).toBe(false)
      expect(vault.isLocked()).toBe(false)
      expect(vault.getStatus()).toBe('unlocked')
      expect(vault.getSeeds()).toEqual(seedsB)
      expect(vault.hasPreservedWork()).toBe(false)
    }, 25000)

    it('recovers via "reload" without password: resets to clean locked state', async () => {
      const seedsA = { credentialSeed: 'seedA', nullifierSeed: 'nullA' }
      await vault.setup('passA', seedsA)

      // Cross-tab change
      window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify({ v: 1, salt: 'aa', iv: 'bb', ct: 'cc' }))
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )

      const success = await vault.recover('reload')
      expect(success).toBe(false) // Not unlocked, but cleanly locked
      expect(vault.isStale()).toBe(false)
      expect(vault.isLocked()).toBe(true)
      expect(vault.getStatus()).toBe('locked')
      expect(vault.hasPreservedWork()).toBe(false)
    })

    it('fails closed when "overwrite" is invoked without a password', async () => {
      const seeds = { credentialSeed: 's1', nullifierSeed: 's2' }
      await vault.setup('pass', seeds)

      window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify({ v: 1, salt: 'aa', iv: 'bb', ct: 'cc' }))
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )

      await expect(vault.recover('overwrite', { password: '' })).rejects.toThrow(
        'Password required to overwrite vault envelope'
      )

      // Preserved work is still protected and not lost
      expect(vault.isStale()).toBe(true)
      expect(vault.hasPreservedWork()).toBe(true)
      expect(vault.getPreservedWork()?.seeds).toEqual(seeds)
    })

    it('fails closed when "overwrite" is called when no preserved work exists', async () => {
      expect(vault.isStale()).toBe(false)
      await expect(vault.recover('overwrite', { password: 'pw' })).rejects.toThrow(
        'No preserved active work available to overwrite vault'
      )
    })

    it('returns false when "reload" fails due to incorrect password', async () => {
      const seedsA = { credentialSeed: 'seedA', nullifierSeed: 'nullA' }
      await vault.setup('passA', seedsA)

      // Another tab writes new vault
      const otherVault = new CredentialVault()
      await otherVault.setup('passB', { credentialSeed: 'seedB', nullifierSeed: 'nullB' })
      otherVault.dispose()

      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )

      const success = await vault.recover('reload', { password: 'wrongPassword' })
      expect(success).toBe(false)
      expect(vault.isLocked()).toBe(true)
      expect(vault.isStale()).toBe(false)
    })

    it('detects cross-tab vault deletion/destruction (newValue is null)', async () => {
      const seeds = { credentialSeed: 'c1', nullifierSeed: 'n1' }
      await vault.setup('pass', seeds)

      // Another tab deletes the vault
      window.localStorage.removeItem(VAULT_STORAGE_KEY)
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          oldValue: 'old',
          newValue: null,
          storageArea: window.localStorage,
        })
      )

      expect(vault.isStale()).toBe(true)
      expect(vault.getStaleReason()).toBe('envelope-removed')
      expect(vault.hasVault()).toBe(false)
      expect(vault.getPreservedWork()?.seeds).toEqual(seeds)

      // Active work can be resurrected into a new vault
      await vault.recover('overwrite', { password: 'resurrectPass' })
      expect(vault.hasVault()).toBe(true)
      expect(vault.isLocked()).toBe(false)
      expect(vault.getSeeds()).toEqual(seeds)
    })

    it('detects storage-wide clear (event.key is null)', async () => {
      const seeds = { credentialSeed: 'c1', nullifierSeed: 'n1' }
      await vault.setup('pass', seeds)

      window.localStorage.clear()
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: null,
          oldValue: null,
          newValue: null,
          storageArea: window.localStorage,
        })
      )

      expect(vault.isStale()).toBe(true)
      expect(vault.getStaleReason()).toBe('envelope-removed')
      expect(vault.getPreservedWork()?.seeds).toEqual(seeds)
    })

    it('detects corrupted or unsupported envelope written by another tab', async () => {
      const seeds = { credentialSeed: 'c1', nullifierSeed: 'n1' }
      await vault.setup('pass', seeds)

      window.localStorage.setItem(VAULT_STORAGE_KEY, 'corrupted-payload')
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: 'corrupted-payload',
          storageArea: window.localStorage,
        })
      )

      expect(vault.isStale()).toBe(true)
      expect(vault.getStaleReason()).toBe('envelope-corrupted')
    })

    it('does not invalidate when the stored envelope is identical', async () => {
      const seeds = { credentialSeed: 'c1', nullifierSeed: 'n1' }
      await vault.setup('pass', seeds)

      const currentStored = window.localStorage.getItem(VAULT_STORAGE_KEY)
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: currentStored,
          storageArea: window.localStorage,
        })
      )

      expect(vault.isStale()).toBe(false)
      expect(vault.isLocked()).toBe(false)
      expect(vault.getSeeds()).toEqual(seeds)
    })

    it('does not become stale if vault was already locked when storage changed', async () => {
      expect(vault.isLocked()).toBe(true)

      window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify({ v: 1, salt: 'aa', iv: 'bb', ct: 'cc' }))
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )

      expect(vault.isStale()).toBe(false)
      expect(vault.isLocked()).toBe(true)
      expect(vault.hasPreservedWork()).toBe(false)
    })

    it('pauses auto-lock timeout while in stale state to protect preserved work', async () => {
      const fastVault = new CredentialVault(10 * 1000) // 10s timeout
      await fastVault.setup('pass', { credentialSeed: 'cred', nullifierSeed: 'null' })

      // Trigger staleness
      window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify({ v: 1, salt: 'aa', iv: 'bb', ct: 'cc' }))
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )

      expect(fastVault.isStale()).toBe(true)
      expect(fastVault.hasPreservedWork()).toBe(true)

      // Advance clock past the 10s inactivity limit
      vi.advanceTimersByTime(30 * 1000)

      // Preserved work must NOT be erased by inactivity
      expect(fastVault.hasPreservedWork()).toBe(true)
      expect(fastVault.getPreservedWork()?.seeds.credentialSeed).toBe('cred')

      fastVault.dispose()
    })

    it('unified handleRecoveryAction executes all actions appropriately', async () => {
      const seeds = { credentialSeed: 'cred', nullifierSeed: 'null' }
      await vault.setup('pass', seeds)

      // Invalidate
      window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify({ v: 1, salt: 'aa', iv: 'bb', ct: 'cc' }))
      vault.checkStaleness()
      expect(vault.isStale()).toBe(true)

      // Overwrite via handleRecoveryAction
      const success = await vault.handleRecoveryAction('overwrite', { password: 'newPassword' })
      expect(success).toBe(true)
      expect(vault.isStale()).toBe(false)
      expect(vault.getSeeds()).toEqual(seeds)
    })
  })

  describe('backup export preview and destination selection', () => {
    it('returns envelope version and nonsecret compatibility metadata even when locked', async () => {
      const seeds = {
        credentialSeed: 'synthetic-cred-seed-secret-01',
        nullifierSeed: 'synthetic-null-seed-secret-02',
      }
      await vault.setup('synthetic-passphrase-99!', seeds)
      vault.lock()

      const storedRaw = window.localStorage.getItem('harpocrates:credential-vault')!
      const storedEnvelope = JSON.parse(storedRaw) as { salt: string; iv: string; ct: string }

      const preview = vault.getBackupExportPreview()
      expect(preview.ok).toBe(true)
      if (!preview.ok) return

      expect(preview.requiresDestinationSelection).toBe(true)
      expect(preview.metadata).toMatchObject({
        envelopeVersion: 1,
        compatible: true,
        kdf: 'PBKDF2-SHA256',
        kdfIterations: 600000,
        cipher: 'AES-256-GCM',
        saltBytes: 16,
        ivBytes: 12,
        containsSecretsInPreview: false,
      })
      expect(preview.metadata.ciphertextBytes).toBeGreaterThan(0)
      expect(preview.metadata.encryptedPayloadBytes).toBeGreaterThan(0)

      // Ensure no secret or raw cryptographic field values leak into preview metadata
      const serializedPreview = JSON.stringify(preview)
      expect(serializedPreview).not.toContain(seeds.credentialSeed)
      expect(serializedPreview).not.toContain(seeds.nullifierSeed)
      expect(serializedPreview).not.toContain('synthetic-passphrase-99!')
      expect(serializedPreview).not.toContain(storedEnvelope.salt)
      expect(serializedPreview).not.toContain(storedEnvelope.iv)
      expect(serializedPreview).not.toContain(storedEnvelope.ct)
    })

    it('fails closed when no vault exists, envelope is corrupted, or version is unsupported', () => {
      expect(vault.getBackupExportPreview()).toMatchObject({
        ok: false,
        code: 'NO_VAULT',
      })

      expect(buildVaultBackupPreview('not-json')).toMatchObject({
        ok: false,
        code: 'CORRUPTED_ENVELOPE',
      })

      expect(
        buildVaultBackupPreview(JSON.stringify({ v: 2, salt: 'aa', iv: 'bb', ct: 'cc' })),
      ).toMatchObject({
        ok: false,
        code: 'UNSUPPORTED_VERSION',
        envelopeVersion: 2,
      })

      expect(
        buildVaultBackupPreview(JSON.stringify({ v: 1, salt: 'not-hex!', iv: 'bb', ct: 'cc' })),
      ).toMatchObject({
        ok: false,
        code: 'INVALID_ENVELOPE_FIELDS',
        envelopeVersion: 1,
      })
    })

    it('requires explicit user selection of a valid encrypted export destination', async () => {
      const seeds = { credentialSeed: 'cred-export', nullifierSeed: 'null-export' }
      await vault.setup('export-passphrase', seeds)

      expect(vault.prepareEncryptedBackupExport(null)).toMatchObject({
        ok: false,
        code: 'DESTINATION_REQUIRED',
      })
      expect(vault.prepareEncryptedBackupExport(undefined)).toMatchObject({
        ok: false,
        code: 'DESTINATION_REQUIRED',
      })
      expect(
        vault.prepareEncryptedBackupExport('unknown-dest' as unknown as VaultExportDestination),
      ).toMatchObject({
        ok: false,
        code: 'INVALID_DESTINATION',
      })

      const result = vault.prepareEncryptedBackupExport('file-download')
      expect(result.ok).toBe(true)
      if (!result.ok) return

      expect(result.destination).toBe('file-download')
      expect(result.metadata.envelopeVersion).toBe(1)
      expect(result.serializedEnvelope).toBe(
        window.localStorage.getItem('harpocrates:credential-vault'),
      )
    })
  })
})
