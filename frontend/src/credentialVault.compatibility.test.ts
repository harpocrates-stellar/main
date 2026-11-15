import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CredentialVault,
  VAULT_FORMAT_DESCRIPTOR,
  VaultCompatibilityError,
  assertVaultCompatibility,
  checkVaultCompatibility,
  getVaultFormatDescriptor,
} from './credentialVault'

const VALID_ENVELOPE = {
  v: 1,
  salt: '00112233445566778899aabbccddeeff',
  iv: '00112233445566778899aabb',
  ct: '00112233445566778899aabbccddeeff00112233',
}

describe('CredentialVault compatibility descriptor (#1153)', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('exposes supported envelope and key-derivation versions as frozen machine-readable data', () => {
    const descriptor = getVaultFormatDescriptor()

    expect(descriptor).toBe(VAULT_FORMAT_DESCRIPTOR)
    expect(descriptor).toEqual({
      schema: 'harpocrates.credential-vault.compatibility/v1',
      currentEnvelopeVersion: 1,
      supportedEnvelopeVersions: [1],
      currentKdfVersion: 1,
      supportedKdfVersions: [1],
      cipher: {
        algorithm: 'AES-GCM',
        keyLengthBits: 256,
        ivBytes: 12,
        saltBytes: 16,
      },
      kdf: {
        version: 1,
        algorithm: 'PBKDF2',
        hash: 'SHA-256',
        iterations: 600000,
      },
      requiredEnvelopeFields: ['v', 'salt', 'iv', 'ct'],
    })

    expect(Object.isFrozen(descriptor)).toBe(true)
    expect(Object.isFrozen(descriptor.supportedEnvelopeVersions)).toBe(true)
    expect(Object.isFrozen(descriptor.supportedKdfVersions)).toBe(true)
    expect(Object.isFrozen(descriptor.cipher)).toBe(true)
    expect(Object.isFrozen(descriptor.kdf)).toBe(true)
    expect(JSON.stringify(descriptor)).not.toMatch(/seed|secret|witness|password/i)
  })

  it('accepts supported v1 envelopes with implicit or explicit matching KDF and cipher parameters', () => {
    expect(checkVaultCompatibility(VALID_ENVELOPE)).toEqual({
      compatible: true,
      envelopeVersion: 1,
      kdfVersion: 1,
    })

    const explicitEnvelope = {
      ...VALID_ENVELOPE,
      kdfVersion: 1,
      kdf: {
        v: 1,
        algorithm: 'PBKDF2',
        hash: 'SHA-256',
        iterations: 600000,
      },
      cipher: {
        algorithm: 'AES-GCM',
        keyLengthBits: 256,
      },
      requiredParams: ['v', 'salt', 'iv', 'ct', 'kdfVersion'],
    }

    expect(checkVaultCompatibility(explicitEnvelope)).toEqual({
      compatible: true,
      envelopeVersion: 1,
      kdfVersion: 1,
    })
    expect(assertVaultCompatibility(explicitEnvelope)).toEqual(explicitEnvelope)
  })

  it('consistently rejects unsupported envelope and KDF versions', () => {
    const unsupportedEnvelope = checkVaultCompatibility({ ...VALID_ENVELOPE, v: 2 })
    expect(unsupportedEnvelope).toEqual({
      compatible: false,
      code: 'UNSUPPORTED_ENVELOPE_VERSION',
      parameter: 'v',
      message: 'Unsupported vault version: 2',
    })

    const unsupportedKdfTopLevel = checkVaultCompatibility({ ...VALID_ENVELOPE, kdfVersion: 2 })
    expect(unsupportedKdfTopLevel).toEqual({
      compatible: false,
      code: 'UNSUPPORTED_KDF_VERSION',
      parameter: 'kdfVersion',
      message: 'Unsupported vault KDF version: 2',
    })

    const unsupportedKdfNested = checkVaultCompatibility({
      ...VALID_ENVELOPE,
      kdf: { v: 99 },
    })
    expect(unsupportedKdfNested).toEqual({
      compatible: false,
      code: 'UNSUPPORTED_KDF_VERSION',
      parameter: 'kdf.v',
      message: 'Unsupported vault KDF version: 99',
    })
  })

  it('consistently rejects unsupported or malformed required cryptographic parameters', () => {
    const badKdfAlgo = checkVaultCompatibility({
      ...VALID_ENVELOPE,
      kdf: { algorithm: 'Argon2id' },
    })
    expect(badKdfAlgo).toEqual({
      compatible: false,
      code: 'UNSUPPORTED_REQUIRED_PARAMETER',
      parameter: 'kdf.algorithm',
      message: 'Unsupported required vault parameter: kdf.algorithm',
    })

    const badIterations = checkVaultCompatibility({
      ...VALID_ENVELOPE,
      kdf: { iterations: 1000 },
    })
    expect(badIterations).toEqual({
      compatible: false,
      code: 'UNSUPPORTED_REQUIRED_PARAMETER',
      parameter: 'kdf.iterations',
      message: 'Unsupported required vault parameter: kdf.iterations',
    })

    const badCipher = checkVaultCompatibility({
      ...VALID_ENVELOPE,
      cipher: { algorithm: 'AES-CBC' },
    })
    expect(badCipher).toEqual({
      compatible: false,
      code: 'UNSUPPORTED_REQUIRED_PARAMETER',
      parameter: 'cipher.algorithm',
      message: 'Unsupported required vault parameter: cipher.algorithm',
    })

    const unknownCriticalExtension = checkVaultCompatibility({
      ...VALID_ENVELOPE,
      hardwareKeyWrap: true,
    })
    expect(unknownCriticalExtension).toEqual({
      compatible: false,
      code: 'UNSUPPORTED_REQUIRED_PARAMETER',
      parameter: 'hardwareKeyWrap',
      message: 'Unsupported required vault parameter: hardwareKeyWrap',
    })

    const missingRequiredParam = checkVaultCompatibility({
      ...VALID_ENVELOPE,
      requiredParams: ['v', 'kdfVersion'],
    })
    expect(missingRequiredParam).toEqual({
      compatible: false,
      code: 'UNSUPPORTED_REQUIRED_PARAMETER',
      parameter: 'kdfVersion',
      message: 'Unsupported required vault parameter: kdfVersion',
    })

    const shortIv = checkVaultCompatibility({
      ...VALID_ENVELOPE,
      iv: '001122',
    })
    expect(shortIv).toEqual({
      compatible: false,
      code: 'INVALID_REQUIRED_PARAMETER',
      parameter: 'iv',
      message: 'Invalid required vault parameter: iv',
    })
  })

  it('fails closed during CredentialVault.unlock before deriving keys when parameters are unsupported', async () => {
    const importKeySpy = vi.spyOn(crypto.subtle, 'importKey')

    window.localStorage.setItem(
      'harpocrates:credential-vault',
      JSON.stringify({
        ...VALID_ENVELOPE,
        kdf: { v: 1, algorithm: 'Argon2id' },
      }),
    )

    const vault = new CredentialVault()
    await expect(vault.unlock('synthetic-passphrase')).rejects.toBeInstanceOf(VaultCompatibilityError)
    expect(importKeySpy).not.toHaveBeenCalled()
    expect(vault.isLocked()).toBe(true)
  })
})
