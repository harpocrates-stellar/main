import type { SeedPair } from './seedVault'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const KDF_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const SALT_BYTES = 16
const IV_BYTES = 12
const MIN_CIPHERTEXT_BYTES = 16 // AES-GCM authentication tag floor
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

export const VAULT_FORMAT_DESCRIPTOR = Object.freeze({
  schema: 'harpocrates.credential-vault.compatibility/v1',
  currentEnvelopeVersion: VAULT_VERSION,
  supportedEnvelopeVersions: Object.freeze([VAULT_VERSION] as const),
  currentKdfVersion: KDF_VERSION,
  supportedKdfVersions: Object.freeze([KDF_VERSION] as const),
  cipher: Object.freeze({
    algorithm: 'AES-GCM',
    keyLengthBits: 256,
    ivBytes: IV_BYTES,
    saltBytes: SALT_BYTES,
  }),
  kdf: Object.freeze({
    version: KDF_VERSION,
    algorithm: 'PBKDF2',
    hash: 'SHA-256',
    iterations: PBKDF2_ITERATIONS,
  }),
  requiredEnvelopeFields: Object.freeze(['v', 'salt', 'iv', 'ct'] as const),
} as const)

export type VaultFormatDescriptor = typeof VAULT_FORMAT_DESCRIPTOR

export function getVaultFormatDescriptor(): VaultFormatDescriptor {
  return VAULT_FORMAT_DESCRIPTOR
}

export interface VaultKdfParameters {
  v?: number
  algorithm?: string
  hash?: string
  iterations?: number
}

export interface VaultCipherParameters {
  algorithm?: string
  keyLengthBits?: number
}

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
  kdfVersion?: number
  kdf?: VaultKdfParameters
  cipher?: VaultCipherParameters
  requiredParams?: readonly string[]
}

export type VaultCompatibilityErrorCode =
  | 'MALFORMED_ENVELOPE'
  | 'UNSUPPORTED_ENVELOPE_VERSION'
  | 'UNSUPPORTED_KDF_VERSION'
  | 'UNSUPPORTED_REQUIRED_PARAMETER'
  | 'INVALID_REQUIRED_PARAMETER'

export class VaultCompatibilityError extends Error {
  readonly code: VaultCompatibilityErrorCode
  readonly parameter?: string

  constructor(code: VaultCompatibilityErrorCode, message: string, parameter?: string) {
    super(message)
    this.name = 'VaultCompatibilityError'
    this.code = code
    this.parameter = parameter
  }
}

export type VaultCompatibilityResult =
  | {
      compatible: true
      envelopeVersion: number
      kdfVersion: number
    }
  | {
      compatible: false
      code: VaultCompatibilityErrorCode
      parameter?: string
      message: string
    }

const KNOWN_ENVELOPE_PARAMS = new Set([
  'v',
  'salt',
  'iv',
  'ct',
  'kdfVersion',
  'kdf',
  'cipher',
  'requiredParams',
])

function isEvenHex(value: unknown, minBytes: number, exactBytes?: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0) {
    return false
  }
  const byteLength = value.length / 2
  if (byteLength < minBytes) return false
  if (exactBytes !== undefined && byteLength !== exactBytes) return false
  return /^[0-9a-fA-F]+$/.test(value)
}

export function checkVaultCompatibility(candidate: unknown): VaultCompatibilityResult {
  if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) {
    return {
      compatible: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'Vault corrupted: unable to parse envelope',
    }
  }

  const raw = candidate as Record<string, unknown>

  if (
    typeof raw.v !== 'number' ||
    !Number.isInteger(raw.v) ||
    !(VAULT_FORMAT_DESCRIPTOR.supportedEnvelopeVersions as readonly number[]).includes(raw.v)
  ) {
    return {
      compatible: false,
      code: 'UNSUPPORTED_ENVELOPE_VERSION',
      parameter: 'v',
      message: `Unsupported vault version: ${String(raw.v)}`,
    }
  }

  const explicitKdfVersion = raw.kdfVersion
  if (explicitKdfVersion !== undefined) {
    if (
      typeof explicitKdfVersion !== 'number' ||
      !Number.isInteger(explicitKdfVersion) ||
      !(VAULT_FORMAT_DESCRIPTOR.supportedKdfVersions as readonly number[]).includes(explicitKdfVersion)
    ) {
      return {
        compatible: false,
        code: 'UNSUPPORTED_KDF_VERSION',
        parameter: 'kdfVersion',
        message: `Unsupported vault KDF version: ${String(explicitKdfVersion)}`,
      }
    }
  }

  let resolvedKdfVersion = explicitKdfVersion ?? VAULT_FORMAT_DESCRIPTOR.currentKdfVersion

  if (raw.kdf !== undefined) {
    if (typeof raw.kdf !== 'object' || raw.kdf === null || Array.isArray(raw.kdf)) {
      return {
        compatible: false,
        code: 'INVALID_REQUIRED_PARAMETER',
        parameter: 'kdf',
        message: 'Invalid required vault parameter: kdf',
      }
    }
    const kdf = raw.kdf as Record<string, unknown>
    for (const key of Object.keys(kdf)) {
      if (!['v', 'algorithm', 'hash', 'iterations'].includes(key)) {
        return {
          compatible: false,
          code: 'UNSUPPORTED_REQUIRED_PARAMETER',
          parameter: `kdf.${key}`,
          message: `Unsupported required vault parameter: kdf.${key}`,
        }
      }
    }
    if (kdf.v !== undefined) {
      if (
        typeof kdf.v !== 'number' ||
        !Number.isInteger(kdf.v) ||
        !(VAULT_FORMAT_DESCRIPTOR.supportedKdfVersions as readonly number[]).includes(kdf.v)
      ) {
        return {
          compatible: false,
          code: 'UNSUPPORTED_KDF_VERSION',
          parameter: 'kdf.v',
          message: `Unsupported vault KDF version: ${String(kdf.v)}`,
        }
      }
      if (explicitKdfVersion !== undefined && explicitKdfVersion !== kdf.v) {
        return {
          compatible: false,
          code: 'INVALID_REQUIRED_PARAMETER',
          parameter: 'kdf.v',
          message: 'Conflicting vault KDF version parameters',
        }
      }
      resolvedKdfVersion = kdf.v
    }
    if (kdf.algorithm !== undefined && kdf.algorithm !== VAULT_FORMAT_DESCRIPTOR.kdf.algorithm) {
      return {
        compatible: false,
        code: 'UNSUPPORTED_REQUIRED_PARAMETER',
        parameter: 'kdf.algorithm',
        message: `Unsupported required vault parameter: kdf.algorithm`,
      }
    }
    if (kdf.hash !== undefined && kdf.hash !== VAULT_FORMAT_DESCRIPTOR.kdf.hash) {
      return {
        compatible: false,
        code: 'UNSUPPORTED_REQUIRED_PARAMETER',
        parameter: 'kdf.hash',
        message: `Unsupported required vault parameter: kdf.hash`,
      }
    }
    if (kdf.iterations !== undefined && kdf.iterations !== VAULT_FORMAT_DESCRIPTOR.kdf.iterations) {
      return {
        compatible: false,
        code: 'UNSUPPORTED_REQUIRED_PARAMETER',
        parameter: 'kdf.iterations',
        message: `Unsupported required vault parameter: kdf.iterations`,
      }
    }
  }

  if (raw.cipher !== undefined) {
    if (typeof raw.cipher !== 'object' || raw.cipher === null || Array.isArray(raw.cipher)) {
      return {
        compatible: false,
        code: 'INVALID_REQUIRED_PARAMETER',
        parameter: 'cipher',
        message: 'Invalid required vault parameter: cipher',
      }
    }
    const cipher = raw.cipher as Record<string, unknown>
    for (const key of Object.keys(cipher)) {
      if (!['algorithm', 'keyLengthBits'].includes(key)) {
        return {
          compatible: false,
          code: 'UNSUPPORTED_REQUIRED_PARAMETER',
          parameter: `cipher.${key}`,
          message: `Unsupported required vault parameter: cipher.${key}`,
        }
      }
    }
    if (cipher.algorithm !== undefined && cipher.algorithm !== VAULT_FORMAT_DESCRIPTOR.cipher.algorithm) {
      return {
        compatible: false,
        code: 'UNSUPPORTED_REQUIRED_PARAMETER',
        parameter: 'cipher.algorithm',
        message: `Unsupported required vault parameter: cipher.algorithm`,
      }
    }
    if (
      cipher.keyLengthBits !== undefined &&
      cipher.keyLengthBits !== VAULT_FORMAT_DESCRIPTOR.cipher.keyLengthBits
    ) {
      return {
        compatible: false,
        code: 'UNSUPPORTED_REQUIRED_PARAMETER',
        parameter: 'cipher.keyLengthBits',
        message: `Unsupported required vault parameter: cipher.keyLengthBits`,
      }
    }
  }

  if (raw.requiredParams !== undefined) {
    if (!Array.isArray(raw.requiredParams) || !raw.requiredParams.every((item) => typeof item === 'string')) {
      return {
        compatible: false,
        code: 'INVALID_REQUIRED_PARAMETER',
        parameter: 'requiredParams',
        message: 'Invalid required vault parameter: requiredParams',
      }
    }
    for (const param of raw.requiredParams) {
      if (!KNOWN_ENVELOPE_PARAMS.has(param) || !(param in raw)) {
        return {
          compatible: false,
          code: 'UNSUPPORTED_REQUIRED_PARAMETER',
          parameter: param,
          message: `Unsupported required vault parameter: ${param}`,
        }
      }
    }
  }

  for (const key of Object.keys(raw)) {
    if (!KNOWN_ENVELOPE_PARAMS.has(key)) {
      return {
        compatible: false,
        code: 'UNSUPPORTED_REQUIRED_PARAMETER',
        parameter: key,
        message: `Unsupported required vault parameter: ${key}`,
      }
    }
  }

  if (!isEvenHex(raw.salt, SALT_BYTES, SALT_BYTES)) {
    return {
      compatible: false,
      code: 'INVALID_REQUIRED_PARAMETER',
      parameter: 'salt',
      message: 'Invalid required vault parameter: salt',
    }
  }
  if (!isEvenHex(raw.iv, IV_BYTES, IV_BYTES)) {
    return {
      compatible: false,
      code: 'INVALID_REQUIRED_PARAMETER',
      parameter: 'iv',
      message: 'Invalid required vault parameter: iv',
    }
  }
  if (!isEvenHex(raw.ct, MIN_CIPHERTEXT_BYTES)) {
    return {
      compatible: false,
      code: 'INVALID_REQUIRED_PARAMETER',
      parameter: 'ct',
      message: 'Invalid required vault parameter: ct',
    }
  }

  return {
    compatible: true,
    envelopeVersion: raw.v,
    kdfVersion: resolvedKdfVersion,
  }
}

export function assertVaultCompatibility(candidate: unknown): VaultEnvelope {
  const result = checkVaultCompatibility(candidate)
  if (!result.compatible) {
    throw new VaultCompatibilityError(result.code, result.message, result.parameter)
  }
  return candidate as VaultEnvelope
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
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  async unlock(password: string): Promise<boolean> {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    let parsed: unknown
    try {
      parsed = JSON.parse(stored)
    } catch {
      throw new VaultCompatibilityError('MALFORMED_ENVELOPE', 'Vault corrupted: unable to parse envelope')
    }

    const envelope = assertVaultCompatibility(parsed)

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
