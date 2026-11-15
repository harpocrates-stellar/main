import type { SeedPair } from './seedVault'
import {
  clearVaultBackupPresence,
  probeLocalStorageAvailability,
  readVaultBackupPresence,
  type StorageAvailabilityStatus,
  writeVaultBackupPresence,
} from './safeStorage'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

const HEX_FIELD_PATTERN = /^[0-9a-fA-F]+$/

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export type VaultEnvelopeHealthStatus =
  | 'supported'
  | 'unsupported-version'
  | 'corrupted'
  | 'missing'
  | 'unreadable'

export interface VaultRecoveryReadinessReport {
  readonly ready: boolean
  readonly overallStatus: 'ready' | 'attention-needed' | 'unavailable'
  readonly formatVersion: number | null
  readonly supportedFormatVersion: number
  readonly envelopeStatus: VaultEnvelopeHealthStatus
  readonly storageAvailable: boolean
  readonly storageStatus: StorageAvailabilityStatus
  readonly backupPresent: boolean
  readonly backupMatchesCurrentVersion: boolean
  readonly lastBackupRecordedAt: string | null
  readonly actionItems: readonly string[]
}

function inspectStoredEnvelopeStructure(rawStored: string | null): {
  envelopeStatus: VaultEnvelopeHealthStatus
  formatVersion: number | null
} {
  if (!rawStored) {
    return { envelopeStatus: 'missing', formatVersion: null }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(rawStored)
  } catch {
    return { envelopeStatus: 'corrupted', formatVersion: null }
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { envelopeStatus: 'corrupted', formatVersion: null }
  }

  const candidate = parsed as Partial<VaultEnvelope>
  if (typeof candidate.v !== 'number' || !Number.isInteger(candidate.v)) {
    return { envelopeStatus: 'corrupted', formatVersion: null }
  }

  for (const field of ['salt', 'iv', 'ct'] as const) {
    const val = candidate[field]
    if (
      typeof val !== 'string' ||
      val.length === 0 ||
      val.length % 2 !== 0 ||
      !HEX_FIELD_PATTERN.test(val)
    ) {
      return { envelopeStatus: 'corrupted', formatVersion: candidate.v }
    }
  }

  if (candidate.v !== VAULT_VERSION) {
    return { envelopeStatus: 'unsupported-version', formatVersion: candidate.v }
  }

  return { envelopeStatus: 'supported', formatVersion: candidate.v }
}

/**
 * Produces a strictly non-secret local recovery readiness summary without ever
 * accessing decrypted witness seeds, passphrases, or WebCrypto key handles.
 */
export function buildVaultRecoveryReadinessReport(): VaultRecoveryReadinessReport {
  const storageProbe = probeLocalStorageAvailability()
  const actionItems: string[] = []

  if (storageProbe.status === 'unavailable') {
    actionItems.push(
      'Enable browser local storage permissions for this origin to inspect or persist encrypted vault state.',
    )
    return Object.freeze({
      ready: false,
      overallStatus: 'unavailable',
      formatVersion: null,
      supportedFormatVersion: VAULT_VERSION,
      envelopeStatus: 'unreadable',
      storageAvailable: false,
      storageStatus: 'unavailable',
      backupPresent: false,
      backupMatchesCurrentVersion: false,
      lastBackupRecordedAt: null,
      actionItems: Object.freeze(actionItems),
    })
  }

  if (storageProbe.status === 'read-only') {
    actionItems.push(
      'Free browser storage quota or restore write access before rotating or replacing your vault.',
    )
  }

  let rawStored: string | null = null
  let unreadable = false
  try {
    rawStored = window.localStorage.getItem(VAULT_STORAGE_KEY)
  } catch {
    unreadable = true
  }

  if (unreadable) {
    actionItems.push('Browser storage blocked reading harpocrates:credential-vault.')
    return Object.freeze({
      ready: false,
      overallStatus: 'unavailable',
      formatVersion: null,
      supportedFormatVersion: VAULT_VERSION,
      envelopeStatus: 'unreadable',
      storageAvailable: false,
      storageStatus: 'unavailable',
      backupPresent: false,
      backupMatchesCurrentVersion: false,
      lastBackupRecordedAt: null,
      actionItems: Object.freeze(actionItems),
    })
  }

  const { envelopeStatus, formatVersion } = inspectStoredEnvelopeStructure(rawStored)
  const backupRecord = readVaultBackupPresence()
  const backupPresent = backupRecord.backupPresent
  const backupMatchesCurrentVersion =
    backupPresent &&
    formatVersion !== null &&
    backupRecord.recordedFormatVersion === formatVersion

  if (envelopeStatus === 'missing') {
    actionItems.push('Set up an encrypted credential vault or import an encrypted backup.')
  } else if (envelopeStatus === 'corrupted') {
    actionItems.push(
      'Stored vault envelope is malformed; restore from a verified encrypted backup.',
    )
  } else if (envelopeStatus === 'unsupported-version') {
    actionItems.push(
      `Stored vault format version v${String(formatVersion)} does not match supported version v${VAULT_VERSION}.`,
    )
  }

  if (envelopeStatus === 'supported' && !backupPresent) {
    actionItems.push('Export an encrypted vault backup so credentials can be recovered offline.')
  } else if (envelopeStatus === 'supported' && !backupMatchesCurrentVersion) {
    actionItems.push(
      'Export a fresh encrypted backup matching the active vault format version.',
    )
  }

  const ready =
    storageProbe.available &&
    envelopeStatus === 'supported' &&
    formatVersion === VAULT_VERSION &&
    backupPresent &&
    backupMatchesCurrentVersion

  return Object.freeze({
    ready,
    overallStatus: ready ? 'ready' : 'attention-needed',
    formatVersion,
    supportedFormatVersion: VAULT_VERSION,
    envelopeStatus,
    storageAvailable: storageProbe.available,
    storageStatus: storageProbe.status,
    backupPresent,
    backupMatchesCurrentVersion,
    lastBackupRecordedAt: backupRecord.recordedAtIso,
    actionItems: Object.freeze(actionItems),
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

  getRecoveryReadinessReport(): VaultRecoveryReadinessReport {
    return buildVaultRecoveryReadinessReport()
  }

  markBackupCompleted(recordedAt = new Date()): void {
    const rawStored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    const { envelopeStatus, formatVersion } = inspectStoredEnvelopeStructure(rawStored)
    if (envelopeStatus !== 'supported' || formatVersion === null) {
      throw new Error('Cannot record backup presence without a valid supported vault envelope')
    }
    writeVaultBackupPresence({
      backupPresent: true,
      recordedFormatVersion: formatVersion,
      recordedAtIso: recordedAt.toISOString(),
    })
  }

  clearBackupRecord(): void {
    clearVaultBackupPresence()
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
    // Freshly created or replaced vault requires its own encrypted backup
    clearVaultBackupPresence()
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
    clearVaultBackupPresence()
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
