import type { SeedPair } from './seedVault'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

const SALT_HEX_LENGTH = 32 // 16 bytes
const IV_HEX_LENGTH = 24 // 12 bytes
const MIN_CIPHERTEXT_HEX_LENGTH = 32 // 16-byte AES-GCM authentication tag

/**
 * Maximum serialized UTF-8 byte size accepted for an encrypted vault envelope.
 * Rejects oversized payloads before JSON parsing, hex decoding, or PBKDF2 key derivation.
 */
export const MAX_VAULT_ENVELOPE_BYTES = 16 * 1024 // 16 KiB

/**
 * Maximum decoded ciphertext size in bytes for a vault envelope.
 * Checked against the hex length before decoding ciphertext or deriving keys.
 */
export const MAX_VAULT_CIPHERTEXT_BYTES = 4 * 1024 // 4 KiB
const MAX_CIPHERTEXT_HEX_LENGTH = MAX_VAULT_CIPHERTEXT_BYTES * 2
const HEX_PATTERN = /^[0-9a-fA-F]+$/

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export class VaultEnvelopeSizeError extends Error {
  readonly actualBytes: number
  readonly maxBytes: number

  constructor(message: string, actualBytes: number, maxBytes: number) {
    super(message)
    this.name = 'VaultEnvelopeSizeError'
    this.actualBytes = actualBytes
    this.maxBytes = maxBytes
  }
}

/**
 * Validates a parsed vault envelope object and enforces ciphertext size bounds
 * before hex decoding or key derivation.
 */
export function validateVaultEnvelope(candidate: unknown): VaultEnvelope {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  const record = candidate as Record<string, unknown>
  if (record.v !== VAULT_VERSION) {
    throw new Error(`Unsupported vault version: ${String(record.v)}`)
  }

  if (
    typeof record.salt !== 'string' ||
    typeof record.iv !== 'string' ||
    typeof record.ct !== 'string'
  ) {
    throw new Error('Vault corrupted: malformed envelope fields')
  }

  if (record.ct.length > MAX_CIPHERTEXT_HEX_LENGTH) {
    const actualCiphertextBytes = Math.ceil(record.ct.length / 2)
    throw new VaultEnvelopeSizeError(
      `Vault ciphertext exceeds maximum size of ${MAX_VAULT_CIPHERTEXT_BYTES} bytes (got ${actualCiphertextBytes} bytes)`,
      actualCiphertextBytes,
      MAX_VAULT_CIPHERTEXT_BYTES
    )
  }

  if (record.salt.length !== SALT_HEX_LENGTH || !HEX_PATTERN.test(record.salt)) {
    throw new Error('Vault corrupted: invalid salt encoding')
  }

  if (record.iv.length !== IV_HEX_LENGTH || !HEX_PATTERN.test(record.iv)) {
    throw new Error('Vault corrupted: invalid iv encoding')
  }

  if (
    record.ct.length < MIN_CIPHERTEXT_HEX_LENGTH ||
    record.ct.length % 2 !== 0 ||
    !HEX_PATTERN.test(record.ct)
  ) {
    throw new Error('Vault corrupted: invalid ciphertext encoding')
  }

  return {
    v: VAULT_VERSION,
    salt: record.salt,
    iv: record.iv,
    ct: record.ct,
  }
}

/**
 * Parses and validates a serialized vault envelope, rejecting oversized inputs
 * before JSON parsing, ciphertext decoding, or PBKDF2 key derivation.
 */
export function parseVaultEnvelope(
  serialized: string,
  maxEnvelopeBytes = MAX_VAULT_ENVELOPE_BYTES
): VaultEnvelope {
  if (typeof serialized !== 'string') {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  // Fast-path lower bound: UTF-8 byte length is always >= UTF-16 code-unit length.
  if (serialized.length > maxEnvelopeBytes) {
    throw new VaultEnvelopeSizeError(
      `Vault envelope exceeds maximum size of ${maxEnvelopeBytes} bytes`,
      serialized.length,
      maxEnvelopeBytes
    )
  }

  const byteLength = new TextEncoder().encode(serialized).byteLength
  if (byteLength > maxEnvelopeBytes) {
    throw new VaultEnvelopeSizeError(
      `Vault envelope exceeds maximum size of ${maxEnvelopeBytes} bytes (got ${byteLength} bytes)`,
      byteLength,
      maxEnvelopeBytes
    )
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(serialized)
  } catch {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  return validateVaultEnvelope(parsed)
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

async function decryptEnvelope(
  envelope: VaultEnvelope,
  password: string
): Promise<{ key: CryptoKey; seeds: SeedPair } | null> {
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
    const seedsRaw = JSON.parse(dec.decode(pt)) as Partial<SeedPair> | null
    if (
      !seedsRaw ||
      typeof seedsRaw !== 'object' ||
      typeof seedsRaw.credentialSeed !== 'string' ||
      typeof seedsRaw.nullifierSeed !== 'string'
    ) {
      return null
    }

    return {
      key,
      seeds: {
        credentialSeed: seedsRaw.credentialSeed,
        nullifierSeed: seedsRaw.nullifierSeed,
      },
    }
  } catch {
    // Typically an OperationError if decryption fails due to bad password
    return null
  }
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
    return !!window.localStorage.getItem(VAULT_STORAGE_KEY)
  }

  async setup(password: string, seeds: SeedPair): Promise<void> {
    const enc = new TextEncoder()
    const pt = enc.encode(JSON.stringify(seeds))
    const projectedCiphertextBytes = pt.byteLength + 16 // AES-GCM 128-bit auth tag
    if (projectedCiphertextBytes > MAX_VAULT_CIPHERTEXT_BYTES) {
      throw new VaultEnvelopeSizeError(
        `Vault ciphertext exceeds maximum size of ${MAX_VAULT_CIPHERTEXT_BYTES} bytes (got ${projectedCiphertextBytes} bytes)`,
        projectedCiphertextBytes,
        MAX_VAULT_CIPHERTEXT_BYTES
      )
    }

    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveKey(password, salt as unknown as ArrayBuffer)

    const iv = crypto.getRandomValues(new Uint8Array(12))
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

    const serialized = JSON.stringify(envelope)
    parseVaultEnvelope(serialized)

    window.localStorage.setItem(VAULT_STORAGE_KEY, serialized)
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  /**
   * Exports the currently stored encrypted vault envelope as a canonical JSON string,
   * or `null` if no vault is stored.
   */
  exportEnvelope(): string | null {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) return null
    const envelope = parseVaultEnvelope(stored)
    return JSON.stringify(envelope)
  }

  /**
   * Imports a serialized encrypted vault envelope after enforcing size and format bounds
   * before ciphertext decoding or PBKDF2 key derivation.
   *
   * On any validation, size, or decryption failure, the existing encrypted vault in
   * storage and the current in-memory vault state are preserved unchanged.
   */
  async importEnvelope(serializedEnvelope: string, password: string): Promise<boolean> {
    const envelope = parseVaultEnvelope(serializedEnvelope)
    const canonical = JSON.stringify(envelope)
    const decrypted = await decryptEnvelope(envelope, password)
    if (!decrypted) {
      return false
    }

    window.localStorage.setItem(VAULT_STORAGE_KEY, canonical)
    this.memoryKey = decrypted.key
    this.seeds = decrypted.seeds
    this.resetTimeout()
    return true
  }

  async unlock(password: string): Promise<boolean> {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    const envelope = parseVaultEnvelope(stored)
    const decrypted = await decryptEnvelope(envelope, password)
    if (!decrypted) return false

    this.memoryKey = decrypted.key
    this.seeds = decrypted.seeds
    this.resetTimeout()
    return true
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
    window.localStorage.removeItem(VAULT_STORAGE_KEY)
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
