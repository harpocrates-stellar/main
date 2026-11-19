import type { SeedPair } from './seedVault'
import { VaultStorageError, classifyErrorCode } from './safeStorage'

export { VaultStorageError }

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
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

  hasVault(): boolean {
    try {
      return !!window.localStorage.getItem(VAULT_STORAGE_KEY)
    } catch (err) {
      throw new VaultStorageError(classifyErrorCode(err, 'VAULT_STORAGE_READ_FAILED'), 'hasVault', {
        cause: err,
      })
    }
  }

  async setup(password: string, seeds: SeedPair): Promise<void> {
    let key: CryptoKey
    let envelope: VaultEnvelope
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16))
      key = await deriveKey(password, salt as unknown as ArrayBuffer)

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

      envelope = {
        v: VAULT_VERSION,
        salt: bufToHex(salt as unknown as ArrayBuffer),
        iv: bufToHex(iv as unknown as ArrayBuffer),
        ct: bufToHex(ct),
      }
    } catch (err) {
      throw new VaultStorageError('VAULT_ENCRYPTION_FAILED', 'setup', { cause: err })
    }

    try {
      window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
    } catch (err) {
      throw new VaultStorageError(classifyErrorCode(err, 'VAULT_STORAGE_WRITE_FAILED'), 'setup', {
        cause: err,
      })
    }

    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  async unlock(password: string): Promise<boolean> {
    let stored: string | null
    try {
      stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    } catch (err) {
      throw new VaultStorageError(classifyErrorCode(err, 'VAULT_STORAGE_READ_FAILED'), 'unlock', {
        cause: err,
      })
    }
    if (!stored) {
      throw new VaultStorageError('VAULT_EMPTY', 'unlock', { message: 'Vault is empty' })
    }

    let envelope: VaultEnvelope
    try {
      envelope = JSON.parse(stored)
    } catch (err) {
      throw new VaultStorageError('VAULT_CORRUPTED', 'unlock', {
        message: 'Vault corrupted: unable to parse envelope',
        cause: err,
      })
    }

    if (envelope.v !== VAULT_VERSION) {
      throw new VaultStorageError('VAULT_UNSUPPORTED_VERSION', 'unlock', {
        message: `Unsupported vault version: ${envelope.v}`,
      })
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
      
      this.memoryKey = key
      this.seeds = {
        credentialSeed: seedsRaw.credentialSeed,
        nullifierSeed: seedsRaw.nullifierSeed,
      }
      this.resetTimeout()
      return true
    } catch {
      // Typically an OperationError if decryption fails due to bad password
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
      window.localStorage.removeItem(VAULT_STORAGE_KEY)
    } catch (err) {
      throw new VaultStorageError(classifyErrorCode(err, 'VAULT_STORAGE_REMOVE_FAILED'), 'destroy', {
        cause: err,
      })
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
