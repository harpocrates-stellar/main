import type { SeedPair } from './seedVault'
import { createIsolatedStateContainer, createSafeStorage } from './safeStorage'

const PBKDF2_ITERATIONS = 600000
const PBKDF2_HASH = 'SHA-256' as const
const SALT_BYTES = 16
const AES_KEY_LENGTH_BITS = 256
const AES_IV_BYTES = 12
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes
const V2_AAD_TEXT = 'harpocrates:credential-vault:v2|PBKDF2-SHA256|AES-GCM-256'

export interface VaultEnvelopeV1 {
  v: 1
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
  kdf?: string
  cipher?: string
  iterations?: number
  hash?: string
  keyLengthBits?: number
}

function assertHexField(value: unknown, fieldName: string, expectedBytes?: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || !HEX_PATTERN.test(value)) {
    throw new Error(`Unsupported vault parameter: ${fieldName} must be a non-empty hex string`)
  }
  if (expectedBytes !== undefined && value.length !== expectedBytes * 2) {
    throw new Error(
      `Unsupported vault parameter: ${fieldName} must be ${expectedBytes} bytes (${expectedBytes * 2} hex chars)`
    )
  }
  return value
}

/**
 * Validate a parsed vault envelope against `VAULT_FORMAT_COMPATIBILITY`.
 * Fails closed on unsupported envelope versions, invalid required parameters,
 * or incompatible KDF/cipher parameter overrides.
 */
export function validateVaultEnvelope(candidate: unknown): VaultEnvelope {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new Error('Vault corrupted: envelope must be an object')
  }

  const record = candidate as Record<string, unknown>

  if (
    typeof record.v !== 'number' ||
    !(VAULT_FORMAT_COMPATIBILITY.supportedEnvelopeVersions as readonly number[]).includes(record.v)
  ) {
    throw new Error(`Unsupported vault version: ${String(record.v)}`)
  }

  if (
    record.kdf !== undefined &&
    (typeof record.kdf !== 'string' ||
      !(VAULT_FORMAT_COMPATIBILITY.supportedKdfVersions as readonly string[]).includes(record.kdf))
  ) {
    throw new Error(`Unsupported vault parameter: kdf "${String(record.kdf)}"`)
  }

  if (record.cipher !== undefined && record.cipher !== VAULT_FORMAT_COMPATIBILITY.cipher.algorithm) {
    throw new Error(`Unsupported vault parameter: cipher "${String(record.cipher)}"`)
  }

  if (record.iterations !== undefined && record.iterations !== VAULT_FORMAT_COMPATIBILITY.kdf.iterations) {
    throw new Error(`Unsupported vault parameter: iterations "${String(record.iterations)}"`)
  }

  if (record.hash !== undefined && record.hash !== VAULT_FORMAT_COMPATIBILITY.kdf.hash) {
    throw new Error(`Unsupported vault parameter: hash "${String(record.hash)}"`)
  }

  if (record.keyLengthBits !== undefined && record.keyLengthBits !== VAULT_FORMAT_COMPATIBILITY.cipher.keyLengthBits) {
    throw new Error(`Unsupported vault parameter: keyLengthBits "${String(record.keyLengthBits)}"`)
  }

  const salt = assertHexField(record.salt, 'salt', VAULT_FORMAT_COMPATIBILITY.kdf.saltBytes)
  const iv = assertHexField(record.iv, 'iv', VAULT_FORMAT_COMPATIBILITY.cipher.ivBytes)
  const ct = assertHexField(record.ct, 'ct')

  return {
    v: record.v,
    salt,
    iv,
    ct,
    ...(record.kdf !== undefined ? { kdf: record.kdf as string } : {}),
    ...(record.cipher !== undefined ? { cipher: record.cipher as string } : {}),
    ...(record.iterations !== undefined ? { iterations: record.iterations as number } : {}),
    ...(record.hash !== undefined ? { hash: record.hash as string } : {}),
    ...(record.keyLengthBits !== undefined ? { keyLengthBits: record.keyLengthBits as number } : {}),
  }
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

export interface VaultEnvelopeV2 {
  v: 2
  kdf: 'PBKDF2-SHA256'
  iterations: number
  cipher: 'AES-GCM-256'
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export type VaultStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>

export interface CredentialVaultOptions {
  inactivityTimeoutMs?: number
  storage?: VaultStorage
}

export function validateVaultEnvelope(candidate: unknown): VaultEnvelope {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new Error('Vault corrupted: envelope must be an object')
  }

  const record = candidate as Record<string, unknown>

  if (typeof record.v !== 'number' || record.v !== VAULT_VERSION) {
    throw new Error(`Unsupported vault version: ${String(record.v)}`)
  }

  const isHex = (val: unknown): val is string =>
    typeof val === 'string' && val.length > 0 && val.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(val)

  if (!isHex(record.salt)) {
    throw new Error('Unsupported vault parameter: salt must be a non-empty hex string with even length')
  }

  if (!isHex(record.iv)) {
    throw new Error('Unsupported vault parameter: iv must be a non-empty hex string with even length')
  }

  if (!isHex(record.ct)) {
    throw new Error('Unsupported vault parameter: ct must be a non-empty hex string with even length')
  }

  return {
    v: record.v,
    salt: record.salt,
    iv: record.iv,
    ct: record.ct,
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

export class StorageUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StorageUnavailableError';
  }
}

// BroadcastChannel for vault lock events
export const VAULT_LOCK_CHANNEL = new BroadcastChannel('credential-vault-lock');

// BroadcastChannel for vault lock events
export const VAULT_LOCK_CHANNEL = new BroadcastChannel('credential-vault-lock');

export class CredentialVault {
  private memoryKey: CryptoKey | null = null
  private seeds: SeedPair | null = null
  private timeoutId: ReturnType<typeof setTimeout> | null = null
  private inactivityTimeoutMs: number
  private storage: VaultStorage

  constructor(
    inactivityTimeoutMsOrOptions?: number | CredentialVaultOptions,
    storage?: VaultStorage
  ) {
    if (typeof inactivityTimeoutMsOrOptions === 'object' && inactivityTimeoutMsOrOptions !== null) {
      this.inactivityTimeoutMs = inactivityTimeoutMsOrOptions.inactivityTimeoutMs ?? DEFAULT_TIMEOUT_MS
      this.storage = inactivityTimeoutMsOrOptions.storage ?? this.getDefaultStorage()
    } else {
      this.inactivityTimeoutMs = inactivityTimeoutMsOrOptions ?? DEFAULT_TIMEOUT_MS
      this.storage = storage ?? this.getDefaultStorage()
    }
  }

  private getDefaultStorage(): VaultStorage {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage
    }
    return createIsolatedStateContainer()
  }

  getStorage(): VaultStorage {
    return this.storage
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

  async setup(password: string, seeds: SeedPair): Promise<void> {
    const { key, serialized } = await encryptEnvelopeV2(password, seeds)

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

    this.storage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
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

    let parsed: unknown
    try {
      parsed = JSON.parse(stored)
    } catch {
      throw new Error('Vault corrupted: unable to parse envelope')
    }

    const envelope = validateVaultEnvelope(parsed)

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

  exportVault(): VaultEnvelope {
    const stored = this.storage.getItem(VAULT_STORAGE_KEY)
    if (!stored) {
      throw new Error('Vault is empty')
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(stored)
    } catch {
      throw new Error('Vault corrupted: unable to parse envelope')
    }

    return validateVaultEnvelope(parsed)
  }

  importVault(envelopeOrJson: VaultEnvelope | string): void {
    let parsed: unknown
    if (typeof envelopeOrJson === 'string') {
      try {
        parsed = JSON.parse(envelopeOrJson)
      } catch {
        throw new Error('Vault corrupted: unable to parse envelope')
      }
    } else {
      parsed = envelopeOrJson
    }

    const envelope = validateVaultEnvelope(parsed)
    this.storage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
    this.lock()
  }

  lock(): void {
    // Broadcast lock event to other tabs
    try {
      VAULT_LOCK_CHANNEL.postMessage('lock');
    } catch (e) {
      // ignore if broadcast fails
    }
    this.memoryKey = null;
    // Zero out references
    if (this.seeds) {
      this.seeds.credentialSeed = '';
      this.seeds.nullifierSeed = '';
    }
    this.seeds = null;
    this.clearTimeout();
  }
    this.memoryKey = null
    // Zero out references
    if (this.seeds) {
      this.seeds.credentialSeed = '';
      this.seeds.nullifierSeed = '';
    }
    this.seeds = null;
    this.clearTimeout();
  }
    this.memoryKey = null
    zeroSeeds(this.seeds)
    this.seeds = null
    this.clearTimeout()
  }

  destroy(): void {
    this.lock()
    this.storage.removeItem(VAULT_STORAGE_KEY)
  }

  async rehearseRecovery(
    options?: VaultRecoveryRehearsalOptions
  ): Promise<VaultRecoveryRehearsalResult> {
    return rehearseVaultRecovery(options)
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

export interface VaultRecoveryRehearsalOptions {
  /** Optional custom synthetic seeds to use for rehearsal. If omitted, random synthetic seeds are generated. */
  syntheticMaterial?: SeedPair
  /** Optional custom passphrase to use for rehearsal. If omitted, a strong synthetic passphrase is used. */
  passphrase?: string
  /** Optional custom isolated container to act as initial source. If omitted, an isolated container is created. */
  isolatedContainer?: VaultStorage
  /** Optional custom isolated container to act as recovery destination. If omitted, an isolated container is created. */
  targetContainer?: VaultStorage
  /** Whether to record completion in safe storage preferences. Defaults to true. */
  markCompleted?: boolean
  /** Storage container for UI preferences if marking completion. Defaults to browser localStorage if available. */
  preferencesStorage?: Storage
}

export interface VaultRecoveryRehearsalResult {
  success: boolean
  syntheticSeedsVerified: boolean
  isolatedExportVerified: boolean
  isolatedImportVerified: boolean
  originalCredentialsUntouched: boolean
  rehearsalCompleted: boolean
  exportedEnvelope: VaultEnvelope
  timestamp: number
}

/**
 * Perform a one-time vault recovery rehearsal with synthetic material in an isolated
 * state container, verifying export and import without touching the user's active private credentials.
 */
export async function rehearseVaultRecovery(
  options?: VaultRecoveryRehearsalOptions
): Promise<VaultRecoveryRehearsalResult> {
  // Capture current state of the user's live storage to verify safety boundary
  const originalLiveStorage = (typeof window !== 'undefined' && window.localStorage)
    ? window.localStorage.getItem(VAULT_STORAGE_KEY)
    : null

  // Guarantee isolated local state containers - NEVER touch user's active private credentials
  const sourceContainer = options?.isolatedContainer ?? createIsolatedStateContainer()
  const targetContainer = options?.targetContainer ?? createIsolatedStateContainer()

  // Generate or use synthetic material
  const syntheticMaterial: SeedPair = options?.syntheticMaterial ?? {
    credentialSeed: `synth_cred_${bufToHex(crypto.getRandomValues(new Uint8Array(16)) as unknown as ArrayBuffer)}`,
    nullifierSeed: `synth_null_${bufToHex(crypto.getRandomValues(new Uint8Array(16)) as unknown as ArrayBuffer)}`,
  }

  const rehearsalPassphrase = options?.passphrase ?? 'SyntheticRehearsal#Vault2026!'

  // 1. Setup the rehearsal vault in the isolated source container
  const sourceVault = new CredentialVault(DEFAULT_TIMEOUT_MS, sourceContainer)
  await sourceVault.setup(rehearsalPassphrase, syntheticMaterial)

  // 2. Verify export through isolated local state container
  const exportedEnvelope = sourceVault.exportVault()
  const serializedExport = JSON.stringify(exportedEnvelope)

  // Fail-closed privacy check: synthetic seeds must never be present in plaintext in the exported envelope
  if (
    serializedExport.includes(syntheticMaterial.credentialSeed) ||
    serializedExport.includes(syntheticMaterial.nullifierSeed)
  ) {
    throw new Error('Recovery rehearsal failed: exported envelope contains unencrypted private witness material')
  }

  const isolatedExportVerified = exportedEnvelope.v === VAULT_VERSION &&
    !!exportedEnvelope.salt &&
    !!exportedEnvelope.iv &&
    !!exportedEnvelope.ct

  // 3. Verify import through isolated target state container
  const destVault = new CredentialVault(DEFAULT_TIMEOUT_MS, targetContainer)
  destVault.importVault(exportedEnvelope)

  const isolatedImportVerified = destVault.hasVault() && destVault.isLocked()

  // 4. Unlock with rehearsal passphrase and verify recovered seeds
  const unlocked = await destVault.unlock(rehearsalPassphrase)
  if (!unlocked) {
    throw new Error('Recovery rehearsal failed: unable to unlock imported vault with rehearsal passphrase')
  }

  const recoveredSeeds = destVault.getSeeds()
  const syntheticSeedsVerified = !!recoveredSeeds &&
    recoveredSeeds.credentialSeed === syntheticMaterial.credentialSeed &&
    recoveredSeeds.nullifierSeed === syntheticMaterial.nullifierSeed

  if (!syntheticSeedsVerified) {
    throw new Error('Recovery rehearsal failed: recovered seeds do not match synthetic material')
  }

  // 5. Clean up rehearsal state in memory and isolated storage
  sourceVault.destroy()
  destVault.destroy()

  // 6. Verify the user's actual credentials were completely untouched
  const finalLiveStorage = (typeof window !== 'undefined' && window.localStorage)
    ? window.localStorage.getItem(VAULT_STORAGE_KEY)
    : null
  const originalCredentialsUntouched = originalLiveStorage === finalLiveStorage

  if (!originalCredentialsUntouched) {
    throw new Error('Safety boundary violated: live credentials storage was modified during recovery rehearsal')
  }

  // 7. Mark rehearsal completed in safe UI preferences if enabled
  const markCompleted = options?.markCompleted ?? true
  let rehearsalCompleted = false
  if (markCompleted) {
    const prefStorage = options?.preferencesStorage ??
      ((typeof window !== 'undefined' && window.localStorage) ? window.localStorage : undefined)
    if (prefStorage) {
      const safe = createSafeStorage(prefStorage)
      const currentPrefs = safe.getUiPreferences()
      safe.setUiPreferences({ ...currentPrefs, vaultRecoveryRehearsed: true })
      rehearsalCompleted = true
    } else {
      rehearsalCompleted = true
    }
  }

  return {
    success: true,
    syntheticSeedsVerified,
    isolatedExportVerified,
    isolatedImportVerified,
    originalCredentialsUntouched,
    rehearsalCompleted,
    exportedEnvelope,
    timestamp: Date.now(),
  }
}

export function hasVaultRecoveryRehearsed(preferencesStorage?: Storage): boolean {
  const prefStorage = preferencesStorage ??
    ((typeof window !== 'undefined' && window.localStorage) ? window.localStorage : undefined)
  if (!prefStorage) return false
  const safe = createSafeStorage(prefStorage)
  return safe.getUiPreferences().vaultRecoveryRehearsed === true
}

export function resetVaultRecoveryRehearsal(preferencesStorage?: Storage): void {
  const prefStorage = preferencesStorage ??
    ((typeof window !== 'undefined' && window.localStorage) ? window.localStorage : undefined)
  if (!prefStorage) return
  const safe = createSafeStorage(prefStorage)
  const currentPrefs = safe.getUiPreferences()
  safe.setUiPreferences({ ...currentPrefs, vaultRecoveryRehearsed: false })
}
