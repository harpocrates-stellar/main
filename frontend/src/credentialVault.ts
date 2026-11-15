import type { SeedPair } from './seedVault'
import {
  createBrowserVaultLockTransport,
  sanitizeVaultLockBroadcastPayload,
  type VaultLockBroadcastPayload,
  type VaultLockTransport,
} from './safeStorage'

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

export interface CredentialVaultOptions {
  lockTransport?: VaultLockTransport
  initialSessionGeneration?: number
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
  private issuedSeedRefs = new Set<SeedPair>()
  private timeoutId: ReturnType<typeof setTimeout> | null = null
  private inactivityTimeoutMs: number
  private sessionGeneration: number
  private lockTransport: VaultLockTransport
  private unsubscribeLock: (() => void) | null = null

  constructor(
    inactivityTimeoutMs = DEFAULT_TIMEOUT_MS,
    options: CredentialVaultOptions = {},
  ) {
    this.inactivityTimeoutMs = inactivityTimeoutMs
    this.sessionGeneration = options.initialSessionGeneration ?? 0
    this.lockTransport = options.lockTransport ?? createBrowserVaultLockTransport()
    this.unsubscribeLock = this.lockTransport.subscribeLock((payload) => {
      this.handleRemoteLockBroadcast(payload)
    })
  }

  isLocked(): boolean {
    return this.memoryKey === null || this.seeds === null
  }

  getSessionGeneration(): number {
    return this.sessionGeneration
  }

  getSeeds(): SeedPair | null {
    this.resetTimeout()
    if (!this.seeds) return null
    this.issuedSeedRefs.add(this.seeds)
    return this.seeds
  }

  hasVault(): boolean {
    return !!window.localStorage.getItem(VAULT_STORAGE_KEY)
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

    window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
    this.clearDecryptedReferences()
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.sessionGeneration += 1
    this.resetTimeout()
  }

  async unlock(password: string): Promise<boolean> {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    let envelope: VaultEnvelope
    try {
      envelope = JSON.parse(stored)
    } catch {
      throw new Error('Vault corrupted: unable to parse envelope')
    }

    if (envelope.v !== VAULT_VERSION) {
      throw new Error(`Unsupported vault version: ${envelope.v}`)
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

      this.clearDecryptedReferences()
      this.memoryKey = key
      this.seeds = {
        credentialSeed: seedsRaw.credentialSeed,
        nullifierSeed: seedsRaw.nullifierSeed,
      }
      this.sessionGeneration += 1
      this.resetTimeout()
      return true
    } catch {
      // Typically an OperationError if decryption fails due to bad password
      return false
    }
  }

  /**
   * Explicitly locks the vault in the current tab and broadcasts a non-secret
   * lock event (`{ type: 'VAULT_EXPLICIT_LOCK', sessionGeneration }`) to clear
   * decrypted references across all other open tabs.
   */
  lock(): void {
    this.clearDecryptedReferences()
    this.sessionGeneration += 1
    const payload: VaultLockBroadcastPayload = Object.freeze({
      type: 'VAULT_EXPLICIT_LOCK',
      sessionGeneration: this.sessionGeneration,
    })
    this.lockTransport.publishLock(payload)
  }

  destroy(): void {
    this.lock()
    window.localStorage.removeItem(VAULT_STORAGE_KEY)
  }

  dispose(): void {
    if (this.unsubscribeLock) {
      this.unsubscribeLock()
      this.unsubscribeLock = null
    }
    this.lockTransport.close()
    this.clearTimeout()
  }

  private handleRemoteLockBroadcast(rawPayload: VaultLockBroadcastPayload): void {
    const safePayload = sanitizeVaultLockBroadcastPayload(rawPayload)
    if (!safePayload) return

    // Reject replayed/stale lock generations older than the active session generation
    if (safePayload.sessionGeneration < this.sessionGeneration) {
      return
    }

    this.sessionGeneration = Math.max(this.sessionGeneration, safePayload.sessionGeneration)
    this.clearDecryptedReferences()
  }

  private clearDecryptedReferences(): void {
    this.memoryKey = null
    if (this.seeds) {
      this.seeds.credentialSeed = ''
      this.seeds.nullifierSeed = ''
    }
    for (const ref of this.issuedSeedRefs) {
      ref.credentialSeed = ''
      ref.nullifierSeed = ''
    }
    this.issuedSeedRefs.clear()
    this.seeds = null
    this.clearTimeout()
  }

  private lockFromInactivityTimeout(): void {
    this.clearDecryptedReferences()
  }

  private resetTimeout(): void {
    this.clearTimeout()
    if (!this.isLocked() && this.inactivityTimeoutMs > 0) {
      this.timeoutId = setTimeout(() => {
        this.lockFromInactivityTimeout()
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
