import type { SeedPair } from './seedVault'
import { createIsolatedVaultStateContainer } from './safeStorage'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

export interface VaultStorageBackend {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export type VaultRehearsalFailureCode =
  | 'SETUP_FAILED'
  | 'EXPORT_FAILED'
  | 'IMPORT_FAILED'
  | 'UNLOCK_FAILED'
  | 'MISMATCH'

export interface VaultRecoveryRehearsalSteps {
  readonly setup: boolean
  readonly exported: boolean
  readonly imported: boolean
  readonly unlocked: boolean
  readonly roundTripVerified: boolean
  readonly cleanedUp: boolean
}

export interface VaultRecoveryRehearsalReport {
  readonly ok: boolean
  readonly envelopeVersion: number
  readonly steps: VaultRecoveryRehearsalSteps
  readonly failureCode?: VaultRehearsalFailureCode
  readonly message: string
}

export interface VaultRecoveryRehearsalOptions {
  /**
   * Optional isolated hook for testing corrupted or modified backup payloads
   * across the export->import boundary. Never receives plaintext secrets.
   */
  transformExportedEnvelope?: (serializedEnvelope: string) => string
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

function validateEnvelopeShape(parsed: unknown): VaultEnvelope {
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Vault corrupted: unable to parse envelope')
  }
  const candidate = parsed as Record<string, unknown>
  if (candidate.v !== VAULT_VERSION) {
    throw new Error(`Unsupported vault version: ${String(candidate.v)}`)
  }
  if (
    typeof candidate.salt !== 'string' ||
    !/^[0-9a-fA-F]{32}$/.test(candidate.salt) ||
    typeof candidate.iv !== 'string' ||
    !/^[0-9a-fA-F]{24}$/.test(candidate.iv) ||
    typeof candidate.ct !== 'string' ||
    candidate.ct.length < 32 ||
    candidate.ct.length % 2 !== 0 ||
    !/^[0-9a-fA-F]+$/.test(candidate.ct)
  ) {
    throw new Error('Vault corrupted: invalid envelope fields')
  }
  return {
    v: VAULT_VERSION,
    salt: candidate.salt.toLowerCase(),
    iv: candidate.iv.toLowerCase(),
    ct: candidate.ct.toLowerCase(),
  }
}

export class CredentialVault {
  private memoryKey: CryptoKey | null = null
  private seeds: SeedPair | null = null
  private timeoutId: ReturnType<typeof setTimeout> | null = null
  private inactivityTimeoutMs: number
  private readonly storageOverride?: VaultStorageBackend

  constructor(inactivityTimeoutMs = DEFAULT_TIMEOUT_MS, storage?: VaultStorageBackend) {
    this.inactivityTimeoutMs = inactivityTimeoutMs
    this.storageOverride = storage
  }

  private storage(): VaultStorageBackend {
    return this.storageOverride ?? window.localStorage
  }

  isLocked(): boolean {
    return this.memoryKey === null || this.seeds === null
  }

  getSeeds(): SeedPair | null {
    this.resetTimeout()
    return this.seeds
  }

  hasVault(): boolean {
    return !!this.storage().getItem(VAULT_STORAGE_KEY)
  }

  exportEnvelope(): string {
    const stored = this.storage().getItem(VAULT_STORAGE_KEY)
    if (!stored) {
      throw new Error('Vault is empty')
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(stored)
    } catch {
      throw new Error('Vault corrupted: unable to parse envelope')
    }
    const validated = validateEnvelopeShape(parsed)
    return JSON.stringify(validated)
  }

  importEnvelope(serializedEnvelope: string): void {
    if (typeof serializedEnvelope !== 'string' || serializedEnvelope.trim().length === 0) {
      throw new Error('Vault corrupted: unable to parse envelope')
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(serializedEnvelope)
    } catch {
      throw new Error('Vault corrupted: unable to parse envelope')
    }
    const validated = validateEnvelopeShape(parsed)
    this.storage().setItem(VAULT_STORAGE_KEY, JSON.stringify(validated))
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

    this.storage().setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  async unlock(password: string): Promise<boolean> {
    const stored = this.storage().getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    let parsed: unknown
    try {
      parsed = JSON.parse(stored)
    } catch {
      throw new Error('Vault corrupted: unable to parse envelope')
    }

    const envelope = validateEnvelopeShape(parsed)

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
    this.storage().removeItem(VAULT_STORAGE_KEY)
  }

  async rehearseRecovery(
    options?: VaultRecoveryRehearsalOptions
  ): Promise<VaultRecoveryRehearsalReport> {
    return runVaultRecoveryRehearsal(options)
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

function generateOneTimeSyntheticHex(byteCount: number): string {
  const random = crypto.getRandomValues(new Uint8Array(byteCount))
  const hex = bufToHex(random.buffer)
  random.fill(0)
  return hex
}

/**
 * Execute a one-time vault export/import/unlock recovery rehearsal using
 * freshly generated synthetic material inside isolated in-memory containers.
 * Never reads, mutates, or locks the user's live `localStorage` vault or
 * decrypted credentials.
 */
export async function runVaultRecoveryRehearsal(
  options?: VaultRecoveryRehearsalOptions
): Promise<VaultRecoveryRehearsalReport> {
  const sourceContainer = createIsolatedVaultStateContainer()
  const targetContainer = createIsolatedVaultStateContainer()
  const sourceVault = new CredentialVault(0, sourceContainer)
  const targetVault = new CredentialVault(0, targetContainer)

  const syntheticMaterial = {
    passphrase: `rehearsal-${generateOneTimeSyntheticHex(16)}`,
    credentialSeed: `rehearsal-cred-${generateOneTimeSyntheticHex(16)}`,
    nullifierSeed: `rehearsal-null-${generateOneTimeSyntheticHex(16)}`,
  }

  let setupOk = false
  let exportedOk = false
  let importedOk = false
  let unlockedOk = false
  let roundTripOk = false
  let failureCode: VaultRehearsalFailureCode | undefined

  try {
    try {
      await sourceVault.setup(syntheticMaterial.passphrase, {
        credentialSeed: syntheticMaterial.credentialSeed,
        nullifierSeed: syntheticMaterial.nullifierSeed,
      })
      setupOk = sourceVault.hasVault() && !sourceVault.isLocked()
      if (!setupOk) {
        failureCode = 'SETUP_FAILED'
      }
    } catch {
      failureCode = 'SETUP_FAILED'
    }

    let wireEnvelope = ''
    if (!failureCode) {
      try {
        const exported = sourceVault.exportEnvelope()
        sourceVault.lock()
        if (
          exported.includes(syntheticMaterial.credentialSeed) ||
          exported.includes(syntheticMaterial.nullifierSeed) ||
          exported.includes(syntheticMaterial.passphrase)
        ) {
          failureCode = 'EXPORT_FAILED'
        } else {
          wireEnvelope = options?.transformExportedEnvelope
            ? options.transformExportedEnvelope(exported)
            : exported
          exportedOk = true
        }
      } catch {
        failureCode = 'EXPORT_FAILED'
      }
    }

    if (!failureCode) {
      try {
        targetVault.importEnvelope(wireEnvelope)
        importedOk = targetVault.hasVault() && targetVault.isLocked()
        if (!importedOk) {
          failureCode = 'IMPORT_FAILED'
        }
      } catch {
        failureCode = 'IMPORT_FAILED'
      }
    }

    if (!failureCode) {
      try {
        unlockedOk = await targetVault.unlock(syntheticMaterial.passphrase)
        if (!unlockedOk) {
          failureCode = 'UNLOCK_FAILED'
        }
      } catch {
        failureCode = 'UNLOCK_FAILED'
      }
    }

    if (!failureCode) {
      const recovered = targetVault.getSeeds()
      roundTripOk =
        recovered !== null &&
        recovered.credentialSeed === syntheticMaterial.credentialSeed &&
        recovered.nullifierSeed === syntheticMaterial.nullifierSeed
      if (!roundTripOk) {
        failureCode = 'MISMATCH'
      }
    }
  } finally {
    sourceVault.destroy()
    targetVault.destroy()
    sourceContainer.clear()
    targetContainer.clear()
    syntheticMaterial.passphrase = ''
    syntheticMaterial.credentialSeed = ''
    syntheticMaterial.nullifierSeed = ''
  }

  const cleanedUp =
    sourceVault.isLocked() &&
    targetVault.isLocked() &&
    sourceContainer.size() === 0 &&
    targetContainer.size() === 0

  const steps: VaultRecoveryRehearsalSteps = Object.freeze({
    setup: setupOk,
    exported: exportedOk,
    imported: importedOk,
    unlocked: unlockedOk,
    roundTripVerified: roundTripOk,
    cleanedUp,
  })

  if (failureCode || !roundTripOk || !cleanedUp) {
    const resolvedCode = failureCode ?? 'MISMATCH'
    return Object.freeze({
      ok: false,
      envelopeVersion: VAULT_VERSION,
      steps,
      failureCode: resolvedCode,
      message: `Synthetic vault recovery rehearsal failed (${resolvedCode}). Live credentials were not touched.`,
    })
  }

  return Object.freeze({
    ok: true,
    envelopeVersion: VAULT_VERSION,
    steps,
    message: 'Synthetic vault recovery rehearsal succeeded in isolated memory.',
  })
}
