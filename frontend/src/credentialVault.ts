import type { SeedPair } from './seedVault'
import { MAX_SAFE_VAULT_ENVELOPE_BYTES, measureBoundedUtf8Bytes } from './safeStorage'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

export const MAX_VAULT_ENVELOPE_BYTES = MAX_SAFE_VAULT_ENVELOPE_BYTES
export const MAX_VAULT_CIPHERTEXT_BYTES = 4 * 1024
export const EXPECTED_VAULT_SALT_BYTES = 16
export const EXPECTED_VAULT_IV_BYTES = 12

const HEX_PATTERN = /^[0-9a-fA-F]*$/

export type VaultEnvelopeSizeErrorCode =
  | 'OVERSIZED_VAULT_ENVELOPE'
  | 'OVERSIZED_VAULT_CIPHERTEXT'
  | 'INVALID_VAULT_HEX_ENCODING'

export interface VaultEnvelopeSizeLimits {
  maxEnvelopeBytes?: number
  maxCiphertextBytes?: number
}

export class VaultEnvelopeSizeError extends Error {
  readonly code: VaultEnvelopeSizeErrorCode
  readonly actualBytes: number
  readonly maxBytes: number

  constructor(
    code: VaultEnvelopeSizeErrorCode,
    message: string,
    actualBytes: number,
    maxBytes: number,
  ) {
    super(message)
    this.name = 'VaultEnvelopeSizeError'
    this.code = code
    this.actualBytes = actualBytes
    this.maxBytes = maxBytes
  }

  toJSON(): Record<string, string | number> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      actualBytes: this.actualBytes,
      maxBytes: this.maxBytes,
    }
  }
}

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export interface ImportVaultEnvelopeOptions {
  password?: string
  limits?: VaultEnvelopeSizeLimits
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

function validateHexField(
  fieldName: 'salt' | 'iv' | 'ct',
  value: unknown,
  options: { exactBytes?: number; maxBytes?: number; minBytes?: number },
): string {
  if (typeof value !== 'string') {
    throw new Error(`Vault corrupted: invalid ${fieldName} field`)
  }

  const decodedByteEstimate = Math.ceil(value.length / 2)
  if (options.maxBytes !== undefined && decodedByteEstimate > options.maxBytes) {
    throw new VaultEnvelopeSizeError(
      'OVERSIZED_VAULT_CIPHERTEXT',
      `Vault ${fieldName} exceeds maximum allowed size (${decodedByteEstimate} bytes > ${options.maxBytes} bytes)`,
      decodedByteEstimate,
      options.maxBytes,
    )
  }

  if (value.length === 0 || value.length % 2 !== 0 || !HEX_PATTERN.test(value)) {
    throw new VaultEnvelopeSizeError(
      'INVALID_VAULT_HEX_ENCODING',
      `Vault corrupted: ${fieldName} must be non-empty even-length hexadecimal`,
      decodedByteEstimate,
      options.maxBytes ?? options.exactBytes ?? 0,
    )
  }

  if (options.exactBytes !== undefined && decodedByteEstimate !== options.exactBytes) {
    throw new Error(
      `Vault corrupted: invalid ${fieldName} length (${decodedByteEstimate} bytes, expected ${options.exactBytes})`,
    )
  }

  if (options.minBytes !== undefined && decodedByteEstimate < options.minBytes) {
    throw new Error(`Vault corrupted: ${fieldName} shorter than minimum authentication tag size`)
  }

  return value.toLowerCase()
}

/**
 * Validates raw envelope size and ciphertext bounds before allocating decoded
 * binary buffers or executing expensive PBKDF2 key derivation.
 */
export function parseBoundedVaultEnvelope(
  rawInput: string,
  limits?: VaultEnvelopeSizeLimits,
): VaultEnvelope {
  const maxEnvelopeBytes = limits?.maxEnvelopeBytes ?? MAX_VAULT_ENVELOPE_BYTES
  const maxCiphertextBytes = limits?.maxCiphertextBytes ?? MAX_VAULT_CIPHERTEXT_BYTES

  const envelopeBytes = measureBoundedUtf8Bytes(rawInput, maxEnvelopeBytes)
  if (envelopeBytes > maxEnvelopeBytes) {
    throw new VaultEnvelopeSizeError(
      'OVERSIZED_VAULT_ENVELOPE',
      `Vault envelope exceeds maximum allowed size (${envelopeBytes} bytes > ${maxEnvelopeBytes} bytes)`,
      envelopeBytes,
      maxEnvelopeBytes,
    )
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(rawInput)
  } catch {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  const candidate = parsed as Partial<VaultEnvelope>
  if (candidate.v !== VAULT_VERSION) {
    throw new Error(`Unsupported vault version: ${String(candidate.v)}`)
  }

  const salt = validateHexField('salt', candidate.salt, {
    exactBytes: EXPECTED_VAULT_SALT_BYTES,
  })
  const iv = validateHexField('iv', candidate.iv, {
    exactBytes: EXPECTED_VAULT_IV_BYTES,
  })
  const ct = validateHexField('ct', candidate.ct, {
    maxBytes: maxCiphertextBytes,
    minBytes: 17, // at least 1 plaintext byte + 16-byte AES-GCM tag
  })

  return {
    v: VAULT_VERSION,
    salt,
    iv,
    ct,
  }
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

async function decryptBoundedEnvelope(
  envelope: VaultEnvelope,
  password: string,
): Promise<{ key: CryptoKey; seeds: SeedPair }> {
  const salt = hexToBuf(envelope.salt)
  const iv = hexToBuf(envelope.iv)
  const ct = hexToBuf(envelope.ct)

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
  const seedsRaw = JSON.parse(dec.decode(pt)) as Partial<SeedPair>
  if (
    typeof seedsRaw.credentialSeed !== 'string' ||
    typeof seedsRaw.nullifierSeed !== 'string'
  ) {
    throw new Error('Vault corrupted: invalid seed payload')
  }

  return {
    key,
    seeds: {
      credentialSeed: seedsRaw.credentialSeed,
      nullifierSeed: seedsRaw.nullifierSeed,
    },
  }
}

export class CredentialVault {
  private memoryKey: CryptoKey | null = null
  private seeds: SeedPair | null = null
  private timeoutId: ReturnType<typeof setTimeout> | null = null
  private inactivityTimeoutMs: number
  private sizeLimits: VaultEnvelopeSizeLimits

  constructor(inactivityTimeoutMs = DEFAULT_TIMEOUT_MS, sizeLimits: VaultEnvelopeSizeLimits = {}) {
    this.inactivityTimeoutMs = inactivityTimeoutMs
    this.sizeLimits = sizeLimits
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

  exportEnvelope(): string {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')
    const bounded = parseBoundedVaultEnvelope(stored, this.sizeLimits)
    return JSON.stringify(bounded)
  }

  async importEnvelope(rawInput: string, options?: ImportVaultEnvelopeOptions): Promise<void> {
    const effectiveLimits: VaultEnvelopeSizeLimits = {
      maxEnvelopeBytes: options?.limits?.maxEnvelopeBytes ?? this.sizeLimits.maxEnvelopeBytes,
      maxCiphertextBytes:
        options?.limits?.maxCiphertextBytes ?? this.sizeLimits.maxCiphertextBytes,
    }

    // Reject oversized or malformed envelopes BEFORE key derivation or touching storage.
    const boundedEnvelope = parseBoundedVaultEnvelope(rawInput, effectiveLimits)

    if (options?.password !== undefined) {
      let verified: { key: CryptoKey; seeds: SeedPair }
      try {
        verified = await decryptBoundedEnvelope(boundedEnvelope, options.password)
      } catch {
        throw new Error('Unable to verify imported vault envelope with provided passphrase')
      }

      window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(boundedEnvelope))
      this.memoryKey = verified.key
      this.seeds = verified.seeds
      this.resetTimeout()
      return
    }

    window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(boundedEnvelope))
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

    const boundedEnvelope = parseBoundedVaultEnvelope(JSON.stringify(envelope), this.sizeLimits)
    window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(boundedEnvelope))
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  async unlock(password: string): Promise<boolean> {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    const envelope = parseBoundedVaultEnvelope(stored, this.sizeLimits)

    try {
      const unlocked = await decryptBoundedEnvelope(envelope, password)
      this.memoryKey = unlocked.key
      this.seeds = unlocked.seeds
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
