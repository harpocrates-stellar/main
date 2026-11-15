import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CredentialVault,
  CredentialVaultError,
  serializeVaultError,
} from './credentialVault'
import { SafeStorageError, safeLocalStorage } from './safeStorage'

const SYNTHETIC_PASSPHRASE = 'synth-passphrase-never-serialize-9012'
const SYNTHETIC_CREDENTIAL_SEED = 'synth-cred-seed-private-778899'
const SYNTHETIC_NULLIFIER_SEED = 'synth-null-seed-private-112233'
const SYNTHETIC_WITNESS_HEX = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899'

function expectNoLeakedSecrets(serializedText: string) {
  expect(serializedText).not.toContain(SYNTHETIC_PASSPHRASE)
  expect(serializedText).not.toContain(SYNTHETIC_CREDENTIAL_SEED)
  expect(serializedText).not.toContain(SYNTHETIC_NULLIFIER_SEED)
  expect(serializedText).not.toContain(SYNTHETIC_WITNESS_HEX)
}

describe('CredentialVault & SafeStorage error serialization redaction (#1152)', () => {
  beforeEach(() => {
    window.localStorage.clear()
    window.sessionStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
    window.sessionStorage.clear()
  })

  it('serializes nested storage and decryption failure causes using stable field names and redacted reason codes', () => {
    const leafJsonError = new SyntaxError(
      `Unexpected token in JSON: {"credentialSeed":"${SYNTHETIC_CREDENTIAL_SEED}","nullifierSeed":"${SYNTHETIC_NULLIFIER_SEED}"}`,
    )
    const middleCryptoError = new DOMException(
      `AES-GCM decrypt failed for key derived from ${SYNTHETIC_PASSPHRASE} witness=${SYNTHETIC_WITNESS_HEX}`,
      'OperationError',
    )
    Object.defineProperty(middleCryptoError, 'cause', { value: leafJsonError })

    const outerStorageError = new DOMException(
      `Quota exceeded writing envelope ct=${SYNTHETIC_WITNESS_HEX}`,
      'QuotaExceededError',
    )
    Object.defineProperty(outerStorageError, 'cause', { value: middleCryptoError })

    const serialized = serializeVaultError(outerStorageError, 'STORAGE_WRITE_FAILED', 'setup')

    expect(Object.keys(serialized)).toEqual([
      'name',
      'reasonCode',
      'message',
      'operation',
      'retryable',
      'cause',
    ])
    expect(serialized).toEqual({
      name: 'CredentialVaultError',
      reasonCode: 'STORAGE_QUOTA_EXCEEDED',
      message: 'Vault storage quota exceeded',
      operation: 'setup',
      retryable: true,
      cause: {
        reasonCode: 'STORAGE_QUOTA_EXCEEDED',
        errorType: 'QuotaExceededError',
        cause: {
          reasonCode: 'DECRYPTION_FAILED',
          errorType: 'OperationError',
          cause: {
            reasonCode: 'VAULT_CORRUPTED',
            errorType: 'SyntaxError',
          },
        },
      },
    })

    const json = JSON.stringify(serialized)
    expectNoLeakedSecrets(json)
  })

  it('keeps private seeds and passphrases out of thrown CredentialVaultError during setup and unlock failures', async () => {
    const vault = new CredentialVault()

    const innerCause = new Error(`Raw seed leak: ${SYNTHETIC_CREDENTIAL_SEED} / ${SYNTHETIC_NULLIFIER_SEED}`)
    const storageFailure = new DOMException(
      `Blocked persistence for ${SYNTHETIC_PASSPHRASE} (${SYNTHETIC_WITNESS_HEX})`,
      'SecurityError',
    )
    Object.defineProperty(storageFailure, 'cause', { value: innerCause })

    vi.spyOn(window.localStorage, 'setItem').mockImplementationOnce(() => {
      throw storageFailure
    })

    let caughtSetupError: unknown
    try {
      await vault.setup(SYNTHETIC_PASSPHRASE, {
        credentialSeed: SYNTHETIC_CREDENTIAL_SEED,
        nullifierSeed: SYNTHETIC_NULLIFIER_SEED,
      })
    } catch (err) {
      caughtSetupError = err
    }

    expect(caughtSetupError).toBeInstanceOf(CredentialVaultError)
    const vaultErr = caughtSetupError as CredentialVaultError
    expect('cause' in vaultErr).toBe(false)
    expectNoLeakedSecrets(JSON.stringify(vaultErr))
    expectNoLeakedSecrets(String(vaultErr))
    expectNoLeakedSecrets(vaultErr.stack ?? '')
    expect(vaultErr.toJSON()).toEqual({
      name: 'CredentialVaultError',
      reasonCode: 'STORAGE_ACCESS_DENIED',
      message: 'Vault storage access denied',
      operation: 'setup',
      retryable: false,
      cause: {
        reasonCode: 'STORAGE_ACCESS_DENIED',
        errorType: 'SecurityError',
        cause: {
          reasonCode: 'STORAGE_ACCESS_DENIED',
          errorType: 'Error',
        },
      },
    })
  })

  it('redacts SyntaxError input snippets when unlocking corrupted stored JSON or invalid version strings', async () => {
    window.localStorage.setItem(
      'harpocrates:credential-vault',
      `{"credentialSeed":"${SYNTHETIC_CREDENTIAL_SEED}","broken":`,
    )
    const vault = new CredentialVault()

    let corruptedErr: unknown
    try {
      await vault.unlock(SYNTHETIC_PASSPHRASE)
    } catch (err) {
      corruptedErr = err
    }

    expect(corruptedErr).toBeInstanceOf(CredentialVaultError)
    expectNoLeakedSecrets(JSON.stringify(corruptedErr))
    expect((corruptedErr as CredentialVaultError).toJSON()).toEqual({
      name: 'CredentialVaultError',
      reasonCode: 'VAULT_CORRUPTED',
      message: 'Vault corrupted: unable to parse envelope',
      operation: 'unlock',
      retryable: false,
      cause: {
        reasonCode: 'VAULT_CORRUPTED',
        errorType: 'SyntaxError',
      },
    })

    // String-typed version carrying a secret must not echo into the error message
    window.localStorage.setItem(
      'harpocrates:credential-vault',
      JSON.stringify({
        v: SYNTHETIC_CREDENTIAL_SEED,
        salt: '00',
        iv: '00',
        ct: '00',
      }),
    )

    let badVersionErr: unknown
    try {
      await vault.unlock(SYNTHETIC_PASSPHRASE)
    } catch (err) {
      badVersionErr = err
    }

    expect(badVersionErr).toBeInstanceOf(CredentialVaultError)
    expectNoLeakedSecrets(JSON.stringify(badVersionErr))
    expectNoLeakedSecrets((badVersionErr as Error).message)
    expect((badVersionErr as CredentialVaultError).reasonCode).toBe('UNSUPPORTED_VAULT_VERSION')
  })

  it('bounds cyclic cause chains safely and redacts SafeStorageError serialization', () => {
    const cycleA = new Error(`cycle-a ${SYNTHETIC_CREDENTIAL_SEED}`)
    const cycleB = new Error(`cycle-b ${SYNTHETIC_PASSPHRASE}`)
    Object.defineProperty(cycleA, 'cause', { value: cycleB })
    Object.defineProperty(cycleB, 'cause', { value: cycleA })

    const serializedCycle = serializeVaultError(cycleA, 'DECRYPTION_FAILED', 'unlock')
    expectNoLeakedSecrets(JSON.stringify(serializedCycle))
    expect(serializedCycle.reasonCode).toBe('DECRYPTION_FAILED')

    vi.spyOn(window.localStorage, 'setItem').mockImplementationOnce((_k, val) => {
      const inner = new Error(`inner leak ${val} ${SYNTHETIC_WITNESS_HEX}`)
      const quota = new DOMException(`quota leak ${val}`, 'QuotaExceededError')
      Object.defineProperty(quota, 'cause', { value: inner })
      throw quota
    })

    let storageErr: unknown
    try {
      safeLocalStorage.setItem('harpocrates:credential-vault', SYNTHETIC_CREDENTIAL_SEED)
    } catch (err) {
      storageErr = err
    }

    expect(storageErr).toBeInstanceOf(SafeStorageError)
    expectNoLeakedSecrets(JSON.stringify(storageErr))
    expect((storageErr as SafeStorageError).toJSON()).toEqual({
      name: 'SafeStorageError',
      reasonCode: 'STORAGE_QUOTA_EXCEEDED',
      message: 'Browser storage quota exceeded',
      storage: 'localStorage',
      cause: {
        reasonCode: 'STORAGE_QUOTA_EXCEEDED',
        errorType: 'QuotaExceededError',
        cause: {
          reasonCode: 'STORAGE_QUOTA_EXCEEDED',
          errorType: 'Error',
        },
      },
    })
  })
})
