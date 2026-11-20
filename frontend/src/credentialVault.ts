import type { SeedPair } from './seedVault'
import { safeLocalStorage, type SafeStorageLike } from './safeStorage'

export const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
export const VAULT_BACKUP_STORAGE_KEY = 'harpocrates:credential-vault:backup'
export const VAULT_VERSION_V1 = 1
export const VAULT_VERSION = 2

const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes
const V2_AAD_TEXT = 'harpocrates:credential-vault:v2|PBKDF2-SHA256|AES-GCM-256'

export interface VaultEnvelopeV1 {
  v: 1
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export interface VaultEnvelopeV2 {
  v: 2
  kdf: 'PBKDF2-SHA256'
  iterations: number
  cipher: 'AES-GCM-256'
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export type VaultEnvelope = VaultEnvelopeV1 | VaultEnvelopeV2

export interface VaultMigrationResult {
  migrated: boolean
  fromVersion: number
  toVersion: number
}

export interface CredentialVaultOptions {
  inactivityTimeoutMs?: number
  storage?: SafeStorageLike
}

export interface VaultMigrateOptions {
  verifyEnvelope?: (
    serialized: string,
    password: string,
    expectedSeeds: SeedPair
  ) => Promise<void>
}

class VaultDecryptionError extends Error {
  constructor(message = 'Unable to decrypt credential vault') {
    super(message)
    this.name = 'VaultDecryptionError'
  }
}

export class VaultValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VaultValidationError'
  }
}

export class VaultMigrationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VaultMigrationError'
  }
}

function bufToHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function isValidHex(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(value)
}

function hexToBuf(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(Math.ceil(hex.length / 2))
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function v2AdditionalData(): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(V2_AAD_TEXT) as Uint8Array<ArrayBuffer>
}

function zeroSeeds(seeds: SeedPair | null): void {
  if (!seeds) return
  seeds.credentialSeed = ''
  seeds.nullifierSeed = ''
}

function validateSeedPair(value: unknown): SeedPair {
  if (!value || typeof value !== 'object') {
    throw new VaultValidationError('Vault payload is not a valid seed object')
  }

  const candidate = value as Record<string, unknown>
  if (typeof candidate.credentialSeed !== 'string' || typeof candidate.nullifierSeed !== 'string') {
    throw new VaultValidationError('Vault payload is missing required seed strings')
  }

  const credentialSeed = candidate.credentialSeed
  const nullifierSeed = candidate.nullifierSeed

  if (
    credentialSeed.trim().length === 0 ||
    nullifierSeed.trim().length === 0 ||
    credentialSeed.trim().length > 256 ||
    nullifierSeed.trim().length > 256
  ) {
    throw new VaultValidationError('Vault payload contains invalid or empty seeds')
  }

  return {
    credentialSeed,
    nullifierSeed,
  }
}

function parseEnvelope(raw: string): VaultEnvelope {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  const candidate = parsed as Record<string, unknown>
  if (typeof candidate.v !== 'number') {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  if (candidate.v !== VAULT_VERSION_V1 && candidate.v !== VAULT_VERSION) {
    throw new Error(`Unsupported vault version: ${candidate.v}`)
  }

  if (!isValidHex(candidate.salt) || !isValidHex(candidate.iv) || !isValidHex(candidate.ct)) {
    throw new Error('Vault corrupted: invalid envelope encoding')
  }

  if (candidate.v === VAULT_VERSION_V1) {
    return {
      v: VAULT_VERSION_V1,
      salt: candidate.salt,
      iv: candidate.iv,
      ct: candidate.ct,
    }
  }

  if (
    candidate.kdf !== 'PBKDF2-SHA256' ||
    candidate.cipher !== 'AES-GCM-256' ||
    typeof candidate.iterations !== 'number' ||
    !Number.isInteger(candidate.iterations) ||
    candidate.iterations <= 0
  ) {
    throw new Error('Vault corrupted: invalid v2 envelope metadata')
  }

  return {
    v: VAULT_VERSION,
    kdf: 'PBKDF2-SHA256',
    iterations: candidate.iterations,
    cipher: 'AES-GCM-256',
    salt: candidate.salt,
    iv: candidate.iv,
    ct: candidate.ct,
  }
}

async function deriveKey(
  password: string,
  salt: ArrayBuffer,
  iterations = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
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
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // extractable
    ['encrypt', 'decrypt']
  )
}

async function decryptEnvelopeIsolated(
  envelope: VaultEnvelope,
  password: string
): Promise<{ key: CryptoKey; seeds: SeedPair }> {
  const salt = hexToBuf(envelope.salt)
  const iv = hexToBuf(envelope.iv)
  const ct = hexToBuf(envelope.ct)
  const iterations = envelope.v === VAULT_VERSION ? envelope.iterations : PBKDF2_ITERATIONS

  let key: CryptoKey
  let pt: ArrayBuffer
  try {
    key = await deriveKey(password, salt as unknown as ArrayBuffer, iterations)
    const algorithm: AesGcmParams =
      envelope.v === VAULT_VERSION
        ? {
            name: 'AES-GCM',
            iv: iv as unknown as ArrayBuffer,
            additionalData: v2AdditionalData() as unknown as ArrayBuffer,
          }
        : {
            name: 'AES-GCM',
            iv: iv as unknown as ArrayBuffer,
          }
    pt = await crypto.subtle.decrypt(algorithm, key, ct as unknown as ArrayBuffer)
  } catch {
    throw new VaultDecryptionError()
  }

  let parsedPayload: unknown
  try {
    const dec = new TextDecoder()
    parsedPayload = JSON.parse(dec.decode(pt))
  } catch {
    throw new VaultValidationError('Vault payload is not valid JSON')
  }

  const seeds = validateSeedPair(parsedPayload)
  return { key, seeds }
}

async function encryptEnvelopeV2(
  password: string,
  seeds: SeedPair
): Promise<{ key: CryptoKey; envelope: VaultEnvelopeV2; serialized: string }> {
  const validated = validateSeedPair(seeds)
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await deriveKey(password, salt as unknown as ArrayBuffer, PBKDF2_ITERATIONS)

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const enc = new TextEncoder()
  const pt = enc.encode(JSON.stringify(validated))

  const ct = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as ArrayBuffer,
      additionalData: v2AdditionalData() as unknown as ArrayBuffer,
    },
    key,
    pt
  )

  const envelope: VaultEnvelopeV2 = {
    v: VAULT_VERSION,
    kdf: 'PBKDF2-SHA256',
    iterations: PBKDF2_ITERATIONS,
    cipher: 'AES-GCM-256',
    salt: bufToHex(salt as unknown as ArrayBuffer),
    iv: bufToHex(iv as unknown as ArrayBuffer),
    ct: bufToHex(ct),
  }

  return {
    key,
    envelope,
    serialized: JSON.stringify(envelope),
  }
}

async function verifyStagedEnvelope(
  serialized: string,
  password: string,
  expectedSeeds: SeedPair
): Promise<void> {
  const stagedEnvelope = parseEnvelope(serialized)
  if (stagedEnvelope.v !== VAULT_VERSION) {
    throw new VaultMigrationError(`Expected staged vault version ${VAULT_VERSION}, got ${stagedEnvelope.v}`)
  }

  const verified = await decryptEnvelopeIsolated(stagedEnvelope, password)
  try {
    if (
      verified.seeds.credentialSeed !== expectedSeeds.credentialSeed ||
      verified.seeds.nullifierSeed !== expectedSeeds.nullifierSeed
    ) {
      throw new VaultMigrationError('Staged vault envelope failed round-trip verification')
    }
  } finally {
    zeroSeeds(verified.seeds)
  }
}

export class CredentialVault {
  private memoryKey: CryptoKey | null = null
  private seeds: SeedPair | null = null
  private timeoutId: ReturnType<typeof setTimeout> | null = null
  private inactivityTimeoutMs: number
  private storage: SafeStorageLike

  constructor(optionsOrTimeout: number | CredentialVaultOptions = DEFAULT_TIMEOUT_MS) {
    if (typeof optionsOrTimeout === 'number') {
      this.inactivityTimeoutMs = optionsOrTimeout
      this.storage = safeLocalStorage
    } else {
      this.inactivityTimeoutMs = optionsOrTimeout.inactivityTimeoutMs ?? DEFAULT_TIMEOUT_MS
      this.storage = optionsOrTimeout.storage ?? safeLocalStorage
    }
  }

  isLocked(): boolean {
    return this.memoryKey === null || this.seeds === null
  }

  getSeeds(): SeedPair | null {
    this.resetTimeout()
    return this.seeds
  }

  hasVault(): boolean {
    return !!this.storage.getItem(VAULT_STORAGE_KEY)
  }

  hasBackup(): boolean {
    return !!this.storage.getItem(VAULT_BACKUP_STORAGE_KEY)
  }

  getVaultVersion(): number | null {
    const stored = this.storage.getItem(VAULT_STORAGE_KEY)
    if (!stored) return null
    return parseEnvelope(stored).v
  }

  needsMigration(): boolean {
    const version = this.getVaultVersion()
    return version !== null && version < VAULT_VERSION
  }

  async setup(password: string, seeds: SeedPair): Promise<void> {
    const { key, serialized } = await encryptEnvelopeV2(password, seeds)

    this.storage.setItem(VAULT_STORAGE_KEY, serialized)
    this.storage.removeItem(VAULT_BACKUP_STORAGE_KEY)
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  /**
   * Staged format migration:
   * 1. Decrypts and validates the existing envelope into isolated memory without mutating storage or unlocked state.
   * 2. Encrypts a new v2 envelope in isolated memory and verifies it via round-trip decryption.
   * 3. Preserves the previous encrypted envelope until the new envelope verifies and primary storage readback succeeds.
   */
  async migrate(
    password: string,
    options: VaultMigrateOptions = {}
  ): Promise<VaultMigrationResult> {
    const previousRaw = this.storage.getItem(VAULT_STORAGE_KEY)
    if (!previousRaw) throw new Error('Vault is empty')

    const previousEnvelope = parseEnvelope(previousRaw)
    if (previousEnvelope.v === VAULT_VERSION) {
      return {
        migrated: false,
        fromVersion: VAULT_VERSION,
        toVersion: VAULT_VERSION,
      }
    }

    const isolated = await decryptEnvelopeIsolated(previousEnvelope, password)
    try {
      const staged = await encryptEnvelopeV2(password, isolated.seeds)
      const verifyFn = options.verifyEnvelope ?? verifyStagedEnvelope
      await verifyFn(staged.serialized, password, isolated.seeds)

      // Preserve the previous encrypted envelope in backup storage before replacing primary storage.
      this.storage.setItem(VAULT_BACKUP_STORAGE_KEY, previousRaw)

      try {
        this.storage.setItem(VAULT_STORAGE_KEY, staged.serialized)
        const persisted = this.storage.getItem(VAULT_STORAGE_KEY)
        if (persisted !== staged.serialized) {
          throw new VaultMigrationError('Primary vault storage readback mismatch after migration')
        }
      } catch (err) {
        try {
          this.storage.setItem(VAULT_STORAGE_KEY, previousRaw)
        } catch {
          // Previous envelope remains preserved in VAULT_BACKUP_STORAGE_KEY.
        }
        throw err instanceof VaultMigrationError
          ? err
          : new VaultMigrationError('Failed to persist verified vault envelope; previous envelope preserved')
      }

      this.storage.removeItem(VAULT_BACKUP_STORAGE_KEY)
      return {
        migrated: true,
        fromVersion: previousEnvelope.v,
        toVersion: VAULT_VERSION,
      }
    } finally {
      zeroSeeds(isolated.seeds)
    }
  }

  async unlock(password: string): Promise<boolean> {
    const stored = this.storage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    const envelope = parseEnvelope(stored)

    if (envelope.v < VAULT_VERSION) {
      try {
        await this.migrate(password)
      } catch (err) {
        if (err instanceof VaultDecryptionError) {
          return false
        }
        throw err
      }
    }

    const currentRaw = this.storage.getItem(VAULT_STORAGE_KEY)
    if (!currentRaw) throw new Error('Vault is empty')
    const currentEnvelope = parseEnvelope(currentRaw)

    try {
      const decrypted = await decryptEnvelopeIsolated(currentEnvelope, password)
      this.memoryKey = decrypted.key
      this.seeds = decrypted.seeds
      this.resetTimeout()
      return true
    } catch (err) {
      if (err instanceof VaultDecryptionError) {
        return false
      }
      throw err
    }
  }

  lock(): void {
    this.memoryKey = null
    zeroSeeds(this.seeds)
    this.seeds = null
    this.clearTimeout()
  }

  destroy(): void {
    this.lock()
    this.storage.removeItem(VAULT_STORAGE_KEY)
    this.storage.removeItem(VAULT_BACKUP_STORAGE_KEY)
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
