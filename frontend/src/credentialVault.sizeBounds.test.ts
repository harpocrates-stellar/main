import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  CredentialVault,
  MAX_VAULT_CIPHERTEXT_BYTES,
  MAX_VAULT_ENVELOPE_BYTES,
  VaultEnvelopeSizeError,
  parseBoundedVaultEnvelope,
} from './credentialVault'

describe('CredentialVault bounded envelope size (#1150)', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('rejects oversized serialized vault envelopes before PBKDF2 key derivation and preserves existing vault', async () => {
    const existingVault = new CredentialVault()
    const liveSeeds = {
      credentialSeed: 'live-credential-seed-001',
      nullifierSeed: 'live-nullifier-seed-001',
    }
    await existingVault.setup('LivePassphrase#2026!', liveSeeds)
    const originalStored = window.localStorage.getItem('harpocrates:credential-vault')
    expect(originalStored).toBeTruthy()

    const importKeySpy = vi.spyOn(crypto.subtle, 'importKey')
    const deriveKeySpy = vi.spyOn(crypto.subtle, 'deriveKey')

    const oversizedPayload = JSON.stringify({
      v: 1,
      salt: 'aa'.repeat(16),
      iv: 'bb'.repeat(12),
      ct: 'cc'.repeat(MAX_VAULT_ENVELOPE_BYTES),
    })
    expect(oversizedPayload.length).toBeGreaterThan(MAX_VAULT_ENVELOPE_BYTES)

    await expect(
      existingVault.importEnvelope(oversizedPayload, { password: 'AnyPassphrase#1' }),
    ).rejects.toMatchObject({
      name: 'VaultEnvelopeSizeError',
      code: 'OVERSIZED_VAULT_ENVELOPE',
      maxBytes: MAX_VAULT_ENVELOPE_BYTES,
    })

    expect(importKeySpy).not.toHaveBeenCalled()
    expect(deriveKeySpy).not.toHaveBeenCalled()

    // Existing encrypted vault in storage and unlocked seeds in memory remain intact
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(originalStored)
    expect(existingVault.isLocked()).toBe(false)
    expect(existingVault.getSeeds()).toEqual(liveSeeds)

    const reloaded = new CredentialVault()
    expect(await reloaded.unlock('LivePassphrase#2026!')).toBe(true)
    expect(reloaded.getSeeds()).toEqual(liveSeeds)
  })

  it('rejects oversized ciphertext within envelope byte limit before decoding or deriving keys', async () => {
    const existingVault = new CredentialVault()
    const liveSeeds = {
      credentialSeed: 'keep-cred-seed',
      nullifierSeed: 'keep-null-seed',
    }
    await existingVault.setup('KeepSafePass#1', liveSeeds)
    const originalStored = window.localStorage.getItem('harpocrates:credential-vault')

    const deriveKeySpy = vi.spyOn(crypto.subtle, 'deriveKey')
    const decryptSpy = vi.spyOn(crypto.subtle, 'decrypt')

    // Total JSON < 16 KiB, but ciphertext exceeds 4 KiB (4097 bytes = 8194 hex chars)
    const oversizedCiphertextJson = JSON.stringify({
      v: 1,
      salt: '11'.repeat(16),
      iv: '22'.repeat(12),
      ct: 'ab'.repeat(MAX_VAULT_CIPHERTEXT_BYTES + 1),
    })
    expect(oversizedCiphertextJson.length).toBeLessThan(MAX_VAULT_ENVELOPE_BYTES)

    await expect(
      existingVault.importEnvelope(oversizedCiphertextJson, { password: 'KeepSafePass#1' }),
    ).rejects.toMatchObject({
      name: 'VaultEnvelopeSizeError',
      code: 'OVERSIZED_VAULT_CIPHERTEXT',
      actualBytes: MAX_VAULT_CIPHERTEXT_BYTES + 1,
      maxBytes: MAX_VAULT_CIPHERTEXT_BYTES,
    })

    expect(deriveKeySpy).not.toHaveBeenCalled()
    expect(decryptSpy).not.toHaveBeenCalled()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(originalStored)
  })

  it('enforces exact UTF-8 byte boundary (exact limit succeeds, +1 byte fails)', () => {
    const validBase = {
      v: 1,
      salt: '01'.repeat(16),
      iv: '02'.repeat(12),
      ct: '03'.repeat(32),
    }
    const baseJson = JSON.stringify(validBase)
    const exactLimit = new TextEncoder().encode(baseJson).byteLength

    expect(
      parseBoundedVaultEnvelope(baseJson, { maxEnvelopeBytes: exactLimit }),
    ).toEqual(validBase)

    expect(() =>
      parseBoundedVaultEnvelope(`${baseJson} `, { maxEnvelopeBytes: exactLimit }),
    ).toThrow(VaultEnvelopeSizeError)
  })

  it('preserves existing vault when imported envelope fails passphrase verification', async () => {
    const sourceVault = new CredentialVault()
    await sourceVault.setup('ImportedPass#99', {
      credentialSeed: 'imported-cred',
      nullifierSeed: 'imported-null',
    })
    const exportedCandidate = sourceVault.exportEnvelope()

    window.localStorage.clear()
    const targetVault = new CredentialVault()
    const currentSeeds = {
      credentialSeed: 'current-cred',
      nullifierSeed: 'current-null',
    }
    await targetVault.setup('CurrentPass#11', currentSeeds)
    const currentEnvelopeRaw = window.localStorage.getItem('harpocrates:credential-vault')

    await expect(
      targetVault.importEnvelope(exportedCandidate, { password: 'WrongImportPassword!' }),
    ).rejects.toThrow('Unable to verify imported vault envelope with provided passphrase')

    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(currentEnvelopeRaw)
    expect(targetVault.getSeeds()).toEqual(currentSeeds)
  })

  it('rejects tampered oversized localStorage payloads in unlock() before running PBKDF2', async () => {
    window.localStorage.setItem(
      'harpocrates:credential-vault',
      'x'.repeat(MAX_VAULT_ENVELOPE_BYTES + 128),
    )

    const importKeySpy = vi.spyOn(crypto.subtle, 'importKey')
    const deriveKeySpy = vi.spyOn(crypto.subtle, 'deriveKey')

    const vault = new CredentialVault()
    await expect(vault.unlock('secret')).rejects.toMatchObject({
      name: 'VaultEnvelopeSizeError',
      code: 'OVERSIZED_VAULT_ENVELOPE',
    })

    expect(importKeySpy).not.toHaveBeenCalled()
    expect(deriveKeySpy).not.toHaveBeenCalled()
  })
})
