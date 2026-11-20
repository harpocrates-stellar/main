import type { SeedPair } from './seedVault'

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

export const VAULT_EXPORT_DESTINATIONS = ['file-download', 'encrypted-clipboard'] as const
export type VaultExportDestination = (typeof VAULT_EXPORT_DESTINATIONS)[number]

export interface VaultBackupCompatibilityMetadata {
  envelopeVersion: number
  compatible: boolean
  compatibilityNote: string
  kdf: 'PBKDF2-SHA256'
  kdfIterations: number
  cipher: 'AES-256-GCM'
  saltBytes: number
  ivBytes: number
  ciphertextBytes: number
  encryptedPayloadBytes: number
  containsSecretsInPreview: false
}

export type VaultBackupPreviewErrorCode =
  | 'NO_VAULT'
  | 'CORRUPTED_ENVELOPE'
  | 'UNSUPPORTED_VERSION'
  | 'INVALID_ENVELOPE_FIELDS'

export type VaultBackupPreviewResult =
  | {
      ok: true
      metadata: VaultBackupCompatibilityMetadata
      requiresDestinationSelection: true
    }
  | {
      ok: false
      code: VaultBackupPreviewErrorCode
      message: string
      envelopeVersion?: number
    }

export type VaultExportErrorCode =
  | VaultBackupPreviewErrorCode
  | 'DESTINATION_REQUIRED'
  | 'INVALID_DESTINATION'

export type VaultExportResult =
  | {
      ok: true
      destination: VaultExportDestination
      serializedEnvelope: string
      metadata: VaultBackupCompatibilityMetadata
    }
  | {
      ok: false
      code: VaultExportErrorCode
      message: string
    }

const EVEN_HEX_RE = /^[0-9a-fA-F]+$/

function isValidHexField(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length % 2 === 0 && EVEN_HEX_RE.test(value)
}

export function isVaultExportDestination(value: unknown): value is VaultExportDestination {
  return (
    typeof value === 'string' &&
    (VAULT_EXPORT_DESTINATIONS as readonly string[]).includes(value)
  )
}

/**
 * Builds a nonsecret backup export preview from a serialized `VaultEnvelope`.
 * Never decrypts or exposes `salt`, `iv`, `ct`, passphrases, or credential seeds.
 */
export function buildVaultBackupPreview(rawEnvelope: string | null): VaultBackupPreviewResult {
  if (!rawEnvelope) {
    return {
      ok: false,
      code: 'NO_VAULT',
      message: 'No encrypted credential vault is stored on this device.',
    }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(rawEnvelope)
  } catch {
    return {
      ok: false,
      code: 'CORRUPTED_ENVELOPE',
      message: 'Vault corrupted: unable to parse envelope.',
    }
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      ok: false,
      code: 'CORRUPTED_ENVELOPE',
      message: 'Vault corrupted: envelope must be a JSON object.',
    }
  }

  const candidate = parsed as Record<string, unknown>
  if (typeof candidate.v !== 'number' || !Number.isInteger(candidate.v)) {
    return {
      ok: false,
      code: 'INVALID_ENVELOPE_FIELDS',
      message: 'Vault envelope is missing a valid integer version.',
    }
  }

  if (candidate.v !== VAULT_VERSION) {
    return {
      ok: false,
      code: 'UNSUPPORTED_VERSION',
      message: `Unsupported vault version: ${candidate.v}. Supported version: ${VAULT_VERSION}.`,
      envelopeVersion: candidate.v,
    }
  }

  if (
    !isValidHexField(candidate.salt) ||
    !isValidHexField(candidate.iv) ||
    !isValidHexField(candidate.ct)
  ) {
    return {
      ok: false,
      code: 'INVALID_ENVELOPE_FIELDS',
      message: 'Vault envelope contains missing or malformed encrypted fields.',
      envelopeVersion: candidate.v,
    }
  }

  const encryptedPayloadBytes = new TextEncoder().encode(rawEnvelope).byteLength

  return {
    ok: true,
    requiresDestinationSelection: true,
    metadata: {
      envelopeVersion: candidate.v,
      compatible: true,
      compatibilityNote: `Compatible with Harpocrates Credential Vault v${VAULT_VERSION} (PBKDF2-SHA256 + AES-256-GCM).`,
      kdf: 'PBKDF2-SHA256',
      kdfIterations: PBKDF2_ITERATIONS,
      cipher: 'AES-256-GCM',
      saltBytes: candidate.salt.length / 2,
      ivBytes: candidate.iv.length / 2,
      ciphertextBytes: candidate.ct.length / 2,
      encryptedPayloadBytes,
      containsSecretsInPreview: false,
    },
  }
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

  /**
   * Returns envelope version and nonsecret compatibility metadata for the
   * currently stored encrypted vault without decrypting or unlocking it.
   */
  getBackupExportPreview(): VaultBackupPreviewResult {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    return buildVaultBackupPreview(stored)
  }

  /**
   * Prepares the encrypted vault envelope for export only after an explicit
   * destination has been selected by the user.
   */
  prepareEncryptedBackupExport(destination: VaultExportDestination | null | undefined): VaultExportResult {
    if (destination === null || destination === undefined || (destination as string) === '') {
      return {
        ok: false,
        code: 'DESTINATION_REQUIRED',
        message: 'Explicit user selection of an encrypted export destination is required.',
      }
    }

    if (!isVaultExportDestination(destination)) {
      return {
        ok: false,
        code: 'INVALID_DESTINATION',
        message: `Unsupported encrypted export destination: ${String(destination)}.`,
      }
    }

    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    const preview = buildVaultBackupPreview(stored)
    if (!preview.ok) {
      return {
        ok: false,
        code: preview.code,
        message: preview.message,
      }
    }

    return {
      ok: true,
      destination,
      serializedEnvelope: stored as string,
      metadata: preview.metadata,
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

    window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
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
