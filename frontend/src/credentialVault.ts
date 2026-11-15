import type { SeedPair } from './seedVault'
import {
  BrowserStorageAccessError,
  type BrowserStorageFailureCode,
  readStorageKeyChecked,
  removeStorageKeyChecked,
  writeStorageKeyChecked,
} from './safeStorage'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

export type VaultFailureCode =
  | BrowserStorageFailureCode
  | 'INCORRECT_PASSPHRASE'
  | 'VAULT_EMPTY'
  | 'VAULT_CORRUPTED'
  | 'UNSUPPORTED_VAULT_VERSION'

export const VAULT_RECOVERY_GUIDANCE: Readonly<Record<VaultFailureCode, string>> = Object.freeze({
  STORAGE_PERMISSION_DENIED:
    'Allow site data and local storage access for this origin in your browser privacy settings, then retry without resetting your encrypted vault.',
  STORAGE_QUOTA_EXCEEDED:
    'Free browser storage space for this origin without clearing harpocrates:credential-vault, then retry the vault operation.',
  STORAGE_UNAVAILABLE:
    'Open Harpocrates in a standard browser context with Web Storage enabled before accessing local vault persistence.',
  INCORRECT_PASSPHRASE:
    'Re-enter the exact passphrase used to encrypt this vault, or import a verified encrypted backup if you rotated passphrases.',
  VAULT_EMPTY:
    'Set up a new encrypted credential vault or import an existing VaultEnvelope backup before unlocking.',
  VAULT_CORRUPTED:
    'Do not overwrite storage yet; inspect or restore a verified encrypted VaultEnvelope backup.',
  UNSUPPORTED_VAULT_VERSION:
    'Reload the latest Harpocrates application build that supports this VaultEnvelope format version.',
})

export class VaultAccessError extends Error {
  readonly code: VaultFailureCode
  readonly recoveryGuidance: string

  constructor(code: VaultFailureCode, message: string, recoveryGuidance?: string) {
    super(message)
    this.name = 'VaultAccessError'
    this.code = code
    this.recoveryGuidance = recoveryGuidance ?? VAULT_RECOVERY_GUIDANCE[code]
  }

  toJSON(): Record<string, string> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      recoveryGuidance: this.recoveryGuidance,
    }
  }
}

export interface VaultFailureDiagnostic {
  ok: false
  code: VaultFailureCode
  message: string
  recoveryGuidance: string
}

export type VaultUnlockOutcome = { ok: true } | VaultFailureDiagnostic

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

function toVaultAccessError(err: unknown): VaultAccessError {
  if (err instanceof VaultAccessError) {
    return err
  }
  if (err instanceof BrowserStorageAccessError) {
    return new VaultAccessError(err.code, err.message, err.recoveryGuidance)
  }
  return new VaultAccessError(
    'STORAGE_UNAVAILABLE',
    'Browser localStorage is unavailable',
  )
}

function bufToHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function hexToBuf(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(Math.ceil(hex.length / 2))
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

async function deriveKey(password: string, salt: ArrayBuffer): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  )
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // extractable
    ['encrypt', 'decrypt']
  )
}

export class CredentialVault {
  private memoryKey: CryptoKey | null = null
  private seeds: SeedPair | null = null
  private timeoutId: ReturnType<typeof setTimeout> | null = null
  private inactivityTimeoutMs: number
  private lastFailure: VaultFailureDiagnostic | null = null

  constructor(inactivityTimeoutMs = DEFAULT_TIMEOUT_MS) {
    this.inactivityTimeoutMs = inactivityTimeoutMs
  }

  isLocked(): boolean {
    return this.memoryKey === null || this.seeds === null
  }

  getSeeds(): SeedPair | null {
    this.resetTimeout()
    return this.seeds
  }

  getLastFailure(): VaultFailureDiagnostic | null {
    return this.lastFailure ? { ...this.lastFailure } : null
  }

  hasVault(): boolean {
    try {
      return !!readStorageKeyChecked('localStorage', VAULT_STORAGE_KEY)
    } catch (err) {
      const accessErr = toVaultAccessError(err)
      this.recordFailure(accessErr)
      throw accessErr
    }
  }

  async setup(password: string, seeds: SeedPair): Promise<void> {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveKey(password, salt as unknown as ArrayBuffer)

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const enc = new TextEncoder()
    const pt = enc.encode(JSON.stringify(seeds))

    const ct = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as unknown as ArrayBuffer,
      },
      key,
      pt
    )

    const envelope: VaultEnvelope = {
      v: VAULT_VERSION,
      salt: bufToHex(salt as unknown as ArrayBuffer),
      iv: bufToHex(iv as unknown as ArrayBuffer),
      ct: bufToHex(ct),
    }

    try {
      // Never erase an existing encrypted vault if write permission or quota fails.
      writeStorageKeyChecked('localStorage', VAULT_STORAGE_KEY, JSON.stringify(envelope))
    } catch (err) {
      const accessErr = toVaultAccessError(err)
      this.recordFailure(accessErr)
      throw accessErr
    }

    this.lastFailure = null
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  /**
   * Returns structured unlock outcome distinguishing unavailable/blocked browser
   * storage from an incorrect passphrase, never erasing stored ciphertext on failure.
   */
  async unlockWithDiagnostics(password: string): Promise<VaultUnlockOutcome> {
    try {
      const unlocked = await this.unlock(password)
      if (unlocked) {
        return { ok: true }
      }
      return (
        this.getLastFailure() ?? {
          ok: false,
          code: 'INCORRECT_PASSPHRASE',
          message: 'Incorrect vault passphrase',
          recoveryGuidance: VAULT_RECOVERY_GUIDANCE.INCORRECT_PASSPHRASE,
        }
      )
    } catch (err) {
      const accessErr = toVaultAccessError(err)
      return {
        ok: false,
        code: accessErr.code,
        message: accessErr.message,
        recoveryGuidance: accessErr.recoveryGuidance,
      }
    }
  }

  async unlock(password: string): Promise<boolean> {
    let stored: string | null
    try {
      stored = readStorageKeyChecked('localStorage', VAULT_STORAGE_KEY)
    } catch (err) {
      const accessErr = toVaultAccessError(err)
      this.recordFailure(accessErr)
      throw accessErr
    }

    if (!stored) {
      const emptyErr = new VaultAccessError('VAULT_EMPTY', 'Vault is empty')
      this.recordFailure(emptyErr)
      throw emptyErr
    }

    let envelope: VaultEnvelope
    try {
      envelope = JSON.parse(stored)
    } catch {
      const corruptErr = new VaultAccessError(
        'VAULT_CORRUPTED',
        'Vault corrupted: unable to parse envelope',
      )
      this.recordFailure(corruptErr)
      throw corruptErr
    }

    if (envelope.v !== VAULT_VERSION) {
      const versionErr = new VaultAccessError(
        'UNSUPPORTED_VAULT_VERSION',
        `Unsupported vault version: ${envelope.v}`,
      )
      this.recordFailure(versionErr)
      throw versionErr
    }

    const salt = hexToBuf(envelope.salt)
    const iv = hexToBuf(envelope.iv)
    const ct = hexToBuf(envelope.ct)

    try {
      const key = await deriveKey(password, salt as unknown as ArrayBuffer)
      const pt = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv as unknown as ArrayBuffer,
        },
        key,
        ct as unknown as ArrayBuffer
      )

      const dec = new TextDecoder()
      const seedsRaw = JSON.parse(dec.decode(pt))

      this.lastFailure = null
      this.memoryKey = key
      this.seeds = {
        credentialSeed: seedsRaw.credentialSeed,
        nullifierSeed: seedsRaw.nullifierSeed,
      }
      this.resetTimeout()
      return true
    } catch {
      const passphraseErr = new VaultAccessError(
        'INCORRECT_PASSPHRASE',
        'Incorrect vault passphrase',
      )
      this.recordFailure(passphraseErr)
      return false
    }
  }

  lock(): void {
    this.memoryKey = null
    // Zero out references
    if (this.seeds) {
      this.seeds.credentialSeed = ''
      this.seeds.nullifierSeed = ''
    }
    this.seeds = null
    this.clearTimeout()
  }

  destroy(): void {
    this.lock()
    try {
      removeStorageKeyChecked('localStorage', VAULT_STORAGE_KEY)
    } catch (err) {
      const accessErr = toVaultAccessError(err)
      this.recordFailure(accessErr)
      throw accessErr
    }
  }

  private recordFailure(err: VaultAccessError): void {
    this.lastFailure = {
      ok: false,
      code: err.code,
      message: err.message,
      recoveryGuidance: err.recoveryGuidance,
    }
  }

  private resetTimeout(): void {
    this.clearTimeout()
    if (!this.isLocked() && this.inactivityTimeoutMs > 0) {
      this.timeoutId = setTimeout(() => {
        this.lock()
      }, this.inactivityTimeoutMs)
    }
  }

  private clearTimeout(): void {
    if (this.timeoutId !== null) {
      clearTimeout(this.timeoutId)
      this.timeoutId = null
    }
  }
}
