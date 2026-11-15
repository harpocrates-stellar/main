import type { SeedPair } from './seedVault'
import {
  isAllowedBackupExportDestination,
  sanitizeVaultBackupFileName,
  type VaultBackupDestinationKind,
} from './safeStorage'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

const HEX_REGEX = /^[0-9a-fA-F]+$/

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export interface VaultBackupCompatibilityMetadata {
  kdfAlgorithm: 'PBKDF2-HMAC-SHA-256'
  kdfIterations: number
  cipherAlgorithm: 'AES-256-GCM'
  saltByteLength: number
  ivByteLength: number
  ciphertextByteLength: number
  encoding: 'hex'
}

export interface VaultBackupExportPreview {
  envelopeVersion: number
  supportedVersion: boolean
  serializedByteLength: number
  suggestedFileName: string
  compatibility: VaultBackupCompatibilityMetadata
}

export interface VaultBackupExportSelection {
  destination: VaultBackupDestinationKind | string | null | undefined
  explicitlySelectedByUser: boolean
  fileName?: string
}

export interface VaultBackupExportPayload {
  destination: VaultBackupDestinationKind
  fileName: string
  mimeType: 'application/json'
  encryptedEnvelopeJson: string
  preview: VaultBackupExportPreview
}

function parseEnvelopeForBackup(stored: string): VaultEnvelope {
  let parsed: unknown
  try {
    parsed = JSON.parse(stored)
  } catch {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  const envelope = parsed as Partial<VaultEnvelope>
  if (typeof envelope.v !== 'number' || !Number.isInteger(envelope.v)) {
    throw new Error('Vault corrupted: invalid envelope version')
  }

  for (const field of ['salt', 'iv', 'ct'] as const) {
    const val = envelope[field]
    if (typeof val !== 'string' || val.length === 0 || val.length % 2 !== 0 || !HEX_REGEX.test(val)) {
      throw new Error(`Vault corrupted: invalid ${field} encoding`)
    }
  }

  return {
    v: envelope.v,
    salt: envelope.salt!.toLowerCase(),
    iv: envelope.iv!.toLowerCase(),
    ct: envelope.ct!.toLowerCase(),
  }
}

export function buildVaultBackupExportPreview(
  rawEnvelopeJson: string,
  proposedFileName?: string,
): VaultBackupExportPreview {
  const envelope = parseEnvelopeForBackup(rawEnvelopeJson)
  const canonicalJson = JSON.stringify(envelope)
  const serializedByteLength = new TextEncoder().encode(canonicalJson).byteLength
  const compatibility: VaultBackupCompatibilityMetadata = Object.freeze({
    kdfAlgorithm: 'PBKDF2-HMAC-SHA-256',
    kdfIterations: PBKDF2_ITERATIONS,
    cipherAlgorithm: 'AES-256-GCM',
    saltByteLength: envelope.salt.length / 2,
    ivByteLength: envelope.iv.length / 2,
    ciphertextByteLength: envelope.ct.length / 2,
    encoding: 'hex',
  })

  return Object.freeze({
    envelopeVersion: envelope.v,
    supportedVersion: envelope.v === VAULT_VERSION,
    serializedByteLength,
    suggestedFileName: sanitizeVaultBackupFileName(proposedFileName, envelope.v),
    compatibility,
  })
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

  getBackupExportPreview(proposedFileName?: string): VaultBackupExportPreview {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')
    return buildVaultBackupExportPreview(stored, proposedFileName)
  }

  exportEncryptedBackup(
    selection: VaultBackupExportSelection | null | undefined,
  ): VaultBackupExportPayload {
    if (
      !selection ||
      !selection.explicitlySelectedByUser ||
      !isAllowedBackupExportDestination(selection.destination)
    ) {
      throw new Error(
        'Explicit user selection of an encrypted export destination is required',
      )
    }

    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    const envelope = parseEnvelopeForBackup(stored)
    if (envelope.v !== VAULT_VERSION) {
      throw new Error(`Unsupported vault version: ${envelope.v}`)
    }

    const encryptedEnvelopeJson = JSON.stringify(envelope)
    const preview = buildVaultBackupExportPreview(encryptedEnvelopeJson, selection.fileName)

    return Object.freeze({
      destination: selection.destination,
      fileName: preview.suggestedFileName,
      mimeType: 'application/json',
      encryptedEnvelopeJson,
      preview,
    })
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
