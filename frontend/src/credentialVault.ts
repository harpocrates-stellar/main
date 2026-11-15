import type { SeedPair } from './seedVault'
import {
  commitVerifiedStorageReplacement,
  createIsolatedMigrationWorkspace,
} from './safeStorage'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
export const LEGACY_VAULT_VERSION_V0 = 0
export const VAULT_VERSION = 1
export const VAULT_VERSION_V2 = 2

const PBKDF2_ITERATIONS_V0 = 100000
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

const HEX_PATTERN = /^[0-9a-fA-F]+$/

export type SupportedUnlockVaultVersion = typeof VAULT_VERSION | typeof VAULT_VERSION_V2
export type MigratableVaultVersion =
  | typeof LEGACY_VAULT_VERSION_V0
  | SupportedUnlockVaultVersion

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
  kdfIterations?: number
}

export type VaultMigrationStage =
  | 'snapshot'
  | 'isolated-decrypt-and-validate'
  | 'isolated-encrypt-and-verify'
  | 'atomic-storage-commit'

export class VaultMigrationError extends Error {
  readonly stage: VaultMigrationStage

  constructor(stage: VaultMigrationStage, message: string) {
    super(message)
    this.name = 'VaultMigrationError'
    this.stage = stage
  }
}

export interface VaultFormatMigrationOptions {
  targetVersion?: SupportedUnlockVaultVersion
  newPassword?: string
  unlockAfterMigration?: boolean
  /**
   * Deterministic test/audit hook allowing callers to inspect or perturb the
   * staged candidate envelope before Stage 3 verification runs.
   */
  transformCandidateBeforeVerify?: (candidateJson: string) => string
}

export interface VaultFormatMigrationResult {
  readonly status: 'migrated' | 'noop-already-at-target'
  readonly fromVersion: number
  readonly toVersion: SupportedUnlockVaultVersion
  readonly stagesCompleted: readonly VaultMigrationStage[]
  readonly isolatedWorkspaceDisposed: boolean
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

function buildAdditionalDataForVersion(
  version: number,
  kdfIterations: number,
): Uint8Array<ArrayBuffer> | undefined {
  if (version === VAULT_VERSION_V2) {
    return new TextEncoder().encode(
      `harpocrates:credential-vault:v2:pbkdf2:${kdfIterations}`,
    ) as Uint8Array<ArrayBuffer>
  }
  return undefined
}

function resolveIterationsForEnvelope(envelope: VaultEnvelope): number {
  if (envelope.v === LEGACY_VAULT_VERSION_V0) {
    return PBKDF2_ITERATIONS_V0
  }
  if (envelope.v === VAULT_VERSION) {
    return PBKDF2_ITERATIONS
  }
  if (envelope.v === VAULT_VERSION_V2) {
    const iters = envelope.kdfIterations ?? PBKDF2_ITERATIONS
    if (!Number.isSafeInteger(iters) || iters < PBKDF2_ITERATIONS) {
      throw new Error(`Invalid PBKDF2 iteration parameter for v2 envelope: ${String(iters)}`)
    }
    return iters
  }
  throw new Error(`Unsupported vault version: ${envelope.v}`)
}

function parseStoredEnvelope(raw: string): VaultEnvelope {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  const candidate = parsed as Partial<VaultEnvelope>
  if (typeof candidate.v !== 'number' || !Number.isInteger(candidate.v)) {
    throw new Error('Vault corrupted: unable to parse envelope')
  }

  for (const field of ['salt', 'iv', 'ct'] as const) {
    const val = candidate[field]
    if (typeof val !== 'string' || val.length === 0 || val.length % 2 !== 0 || !HEX_PATTERN.test(val)) {
      throw new Error(`Vault corrupted: invalid ${field} field`)
    }
  }

  const normalized: VaultEnvelope = {
    v: candidate.v,
    salt: candidate.salt!.toLowerCase(),
    iv: candidate.iv!.toLowerCase(),
    ct: candidate.ct!.toLowerCase(),
  }
  if (candidate.kdfIterations !== undefined) {
    normalized.kdfIterations = candidate.kdfIterations
  }
  return normalized
}

async function deriveKeyWithIterations(
  password: string,
  salt: ArrayBuffer,
  iterations: number,
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

function parseValidatedSeedPair(plaintextBytes: Uint8Array): SeedPair {
  const dec = new TextDecoder()
  let parsed: unknown
  try {
    parsed = JSON.parse(dec.decode(plaintextBytes))
  } catch {
    throw new Error('Decrypted vault payload is not valid JSON')
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Decrypted vault payload must be an object')
  }

  const record = parsed as Partial<SeedPair>
  if (
    typeof record.credentialSeed !== 'string' ||
    record.credentialSeed.length === 0 ||
    typeof record.nullifierSeed !== 'string' ||
    record.nullifierSeed.length === 0
  ) {
    throw new Error('Decrypted vault payload is missing required non-empty witness seeds')
  }

  return {
    credentialSeed: record.credentialSeed,
    nullifierSeed: record.nullifierSeed,
  }
}

async function encryptSeedsForVersion(
  password: string,
  seeds: SeedPair,
  version: MigratableVaultVersion,
): Promise<{ envelope: VaultEnvelope; key: CryptoKey }> {
  const iterations =
    version === LEGACY_VAULT_VERSION_V0 ? PBKDF2_ITERATIONS_V0 : PBKDF2_ITERATIONS
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await deriveKeyWithIterations(password, salt as unknown as ArrayBuffer, iterations)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const aad = buildAdditionalDataForVersion(version, iterations)

  const pt = new TextEncoder().encode(
    JSON.stringify({
      credentialSeed: seeds.credentialSeed,
      nullifierSeed: seeds.nullifierSeed,
    }),
  )
  try {
    const ct = await crypto.subtle.encrypt(
      aad
        ? {
            name: 'AES-GCM',
            iv: iv as unknown as ArrayBuffer,
            additionalData: aad as unknown as ArrayBuffer,
          }
        : {
            name: 'AES-GCM',
            iv: iv as unknown as ArrayBuffer,
          },
      key,
      pt,
    )

    const envelope: VaultEnvelope = {
      v: version,
      salt: bufToHex(salt as unknown as ArrayBuffer),
      iv: bufToHex(iv as unknown as ArrayBuffer),
      ct: bufToHex(ct),
    }
    if (version === VAULT_VERSION_V2) {
      envelope.kdfIterations = iterations
    }

    return { envelope, key }
  } finally {
    pt.fill(0)
  }
}

/**
 * Helper to construct a legacy v0 (`100,000` PBKDF2 iterations) encrypted
 * envelope for migration testing and compatibility validation.
 */
export async function createLegacyV0VaultEnvelope(
  password: string,
  seeds: SeedPair,
): Promise<VaultEnvelope> {
  const { envelope } = await encryptSeedsForVersion(
    password,
    seeds,
    LEGACY_VAULT_VERSION_V0,
  )
  return envelope
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

  getStoredFormatVersion(): number | null {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) return null
    const envelope = parseStoredEnvelope(stored)
    return envelope.v
  }

  needsMigration(
    targetVersion: SupportedUnlockVaultVersion = VAULT_VERSION_V2,
  ): boolean {
    const currentVersion = this.getStoredFormatVersion()
    if (currentVersion === null) return false
    return currentVersion < targetVersion
  }

  /**
   * Performs a four-stage credential vault format migration:
   *  1. Snapshot previous encrypted envelope from storage without modifying it.
   *  2. Decrypt and validate `SeedPair` inside an isolated ephemeral workspace.
   *  3. Encrypt into the target format in isolated memory and verify round-trip
   *     decryption + seed equality before touching browser storage.
   *  4. Atomically replace storage only after Stage 3 verification passes.
   */
  async migrateFormat(
    password: string,
    options: VaultFormatMigrationOptions = {},
  ): Promise<VaultFormatMigrationResult> {
    const targetVersion = options.targetVersion ?? VAULT_VERSION_V2
    if (targetVersion !== VAULT_VERSION && targetVersion !== VAULT_VERSION_V2) {
      throw new VaultMigrationError(
        'snapshot',
        `Unsupported migration target version: ${String(targetVersion)}`,
      )
    }

    // Stage 1: Snapshot stored envelope without modifying browser storage
    const previousRaw = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!previousRaw) {
      throw new VaultMigrationError('snapshot', 'Vault is empty')
    }

    let sourceEnvelope: VaultEnvelope
    let sourceIterations: number
    try {
      sourceEnvelope = parseStoredEnvelope(previousRaw)
      sourceIterations = resolveIterationsForEnvelope(sourceEnvelope)
    } catch (err) {
      throw new VaultMigrationError(
        'snapshot',
        err instanceof Error ? err.message : 'Invalid source vault envelope',
      )
    }

    const stagesCompleted: VaultMigrationStage[] = ['snapshot']
    const effectiveTargetPassword = options.newPassword ?? password

    if (
      sourceEnvelope.v === targetVersion &&
      options.newPassword === undefined &&
      options.transformCandidateBeforeVerify === undefined
    ) {
      return Object.freeze({
        status: 'noop-already-at-target',
        fromVersion: sourceEnvelope.v,
        toVersion: targetVersion,
        stagesCompleted: Object.freeze(stagesCompleted),
        isolatedWorkspaceDisposed: true,
      })
    }

    const workspace = createIsolatedMigrationWorkspace()
    const isolatedSecrets: { credentialSeed: string; nullifierSeed: string } = {
      credentialSeed: '',
      nullifierSeed: '',
    }

    try {
      // Stage 2: Decrypt and validate into isolated memory
      let decryptedBuffer: ArrayBuffer
      try {
        const salt = hexToBuf(sourceEnvelope.salt)
        const iv = hexToBuf(sourceEnvelope.iv)
        const ct = hexToBuf(sourceEnvelope.ct)
        const sourceAad = buildAdditionalDataForVersion(
          sourceEnvelope.v,
          sourceIterations,
        )
        const sourceKey = await deriveKeyWithIterations(
          password,
          salt as unknown as ArrayBuffer,
          sourceIterations,
        )
        decryptedBuffer = await crypto.subtle.decrypt(
          sourceAad
            ? {
                name: 'AES-GCM',
                iv: iv as unknown as ArrayBuffer,
                additionalData: sourceAad as unknown as ArrayBuffer,
              }
            : {
                name: 'AES-GCM',
                iv: iv as unknown as ArrayBuffer,
              },
          sourceKey,
          ct as unknown as ArrayBuffer,
        )
      } catch {
        throw new VaultMigrationError(
          'isolated-decrypt-and-validate',
          'Failed to decrypt existing vault envelope with provided passphrase',
        )
      }

      const isolatedPlaintext = workspace.stagePlaintextBuffer(decryptedBuffer)
      let validatedSeeds: SeedPair
      try {
        validatedSeeds = parseValidatedSeedPair(isolatedPlaintext)
      } catch (err) {
        throw new VaultMigrationError(
          'isolated-decrypt-and-validate',
          err instanceof Error ? err.message : 'Invalid decrypted seed payload',
        )
      }

      isolatedSecrets.credentialSeed = validatedSeeds.credentialSeed
      isolatedSecrets.nullifierSeed = validatedSeeds.nullifierSeed
      stagesCompleted.push('isolated-decrypt-and-validate')

      // Stage 3: Encrypt candidate envelope in isolated memory and verify round-trip
      let candidateKey: CryptoKey
      try {
        const created = await encryptSeedsForVersion(
          effectiveTargetPassword,
          isolatedSecrets,
          targetVersion,
        )
        candidateKey = created.key
        const rawCandidate = JSON.stringify(created.envelope)
        const stagedCandidate = options.transformCandidateBeforeVerify
          ? options.transformCandidateBeforeVerify(rawCandidate)
          : rawCandidate
        workspace.stageCandidateEnvelope(stagedCandidate)
      } catch (err) {
        throw new VaultMigrationError(
          'isolated-encrypt-and-verify',
          err instanceof Error
            ? err.message
            : 'Failed to encrypt candidate target vault envelope',
        )
      }

      const stagedRawToVerify = workspace.readCandidateEnvelope()
      if (!stagedRawToVerify) {
        throw new VaultMigrationError(
          'isolated-encrypt-and-verify',
          'Missing staged candidate envelope in isolated workspace',
        )
      }

      try {
        const parsedCandidate = parseStoredEnvelope(stagedRawToVerify)
        if (parsedCandidate.v !== targetVersion) {
          throw new Error(
            `Candidate envelope version mismatch: expected v${targetVersion}, got v${parsedCandidate.v}`,
          )
        }
        const verifyIterations = resolveIterationsForEnvelope(parsedCandidate)
        const verifySalt = hexToBuf(parsedCandidate.salt)
        const verifyIv = hexToBuf(parsedCandidate.iv)
        const verifyCt = hexToBuf(parsedCandidate.ct)
        const verifyAad = buildAdditionalDataForVersion(
          parsedCandidate.v,
          verifyIterations,
        )
        const verifyKey = await deriveKeyWithIterations(
          effectiveTargetPassword,
          verifySalt as unknown as ArrayBuffer,
          verifyIterations,
        )
        const verifiedPlaintextBuf = await crypto.subtle.decrypt(
          verifyAad
            ? {
                name: 'AES-GCM',
                iv: verifyIv as unknown as ArrayBuffer,
                additionalData: verifyAad as unknown as ArrayBuffer,
              }
            : {
                name: 'AES-GCM',
                iv: verifyIv as unknown as ArrayBuffer,
              },
          verifyKey,
          verifyCt as unknown as ArrayBuffer,
        )
        const verifiedPlaintext = workspace.stagePlaintextBuffer(verifiedPlaintextBuf)
        const verifiedSeeds = parseValidatedSeedPair(verifiedPlaintext)
        if (
          verifiedSeeds.credentialSeed !== isolatedSecrets.credentialSeed ||
          verifiedSeeds.nullifierSeed !== isolatedSecrets.nullifierSeed
        ) {
          throw new Error('Verified candidate seeds did not match source seeds')
        }
      } catch (err) {
        throw new VaultMigrationError(
          'isolated-encrypt-and-verify',
          err instanceof Error
            ? `Candidate vault envelope verification failed: ${err.message}`
            : 'Candidate vault envelope verification failed',
        )
      }

      stagesCompleted.push('isolated-encrypt-and-verify')

      // Stage 4: Atomically commit verified candidate envelope to storage
      try {
        commitVerifiedStorageReplacement(
          'localStorage',
          VAULT_STORAGE_KEY,
          previousRaw,
          stagedRawToVerify,
        )
      } catch (err) {
        throw new VaultMigrationError(
          'atomic-storage-commit',
          err instanceof Error
            ? err.message
            : 'Failed to commit verified vault envelope to storage',
        )
      }

      stagesCompleted.push('atomic-storage-commit')

      const shouldUpdateMemory = options.unlockAfterMigration ?? !this.isLocked()
      if (shouldUpdateMemory) {
        this.memoryKey = candidateKey
        this.seeds = {
          credentialSeed: isolatedSecrets.credentialSeed,
          nullifierSeed: isolatedSecrets.nullifierSeed,
        }
        this.resetTimeout()
      }

      return Object.freeze({
        status: 'migrated',
        fromVersion: sourceEnvelope.v,
        toVersion: targetVersion,
        stagesCompleted: Object.freeze(stagesCompleted),
        isolatedWorkspaceDisposed: true,
      })
    } finally {
      isolatedSecrets.credentialSeed = ''
      isolatedSecrets.nullifierSeed = ''
      workspace.disposeAndZero()
    }
  }

  async setup(password: string, seeds: SeedPair): Promise<void> {
    const { envelope, key } = await encryptSeedsForVersion(password, seeds, VAULT_VERSION)
    window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  async unlock(password: string): Promise<boolean> {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    const envelope = parseStoredEnvelope(stored)

    if (envelope.v === LEGACY_VAULT_VERSION_V0) {
      throw new Error(
        'Legacy vault version 0 requires staged format migration before unlocking',
      )
    }

    if (envelope.v !== VAULT_VERSION && envelope.v !== VAULT_VERSION_V2) {
      throw new Error(`Unsupported vault version: ${envelope.v}`)
    }

    const iterations = resolveIterationsForEnvelope(envelope)
    const salt = hexToBuf(envelope.salt)
    const iv = hexToBuf(envelope.iv)
    const ct = hexToBuf(envelope.ct)
    const aad = buildAdditionalDataForVersion(envelope.v, iterations)

    try {
      const key = await deriveKeyWithIterations(
        password,
        salt as unknown as ArrayBuffer,
        iterations,
      )
      const pt = await crypto.subtle.decrypt(
        aad
          ? {
              name: 'AES-GCM',
              iv: iv as unknown as ArrayBuffer,
              additionalData: aad as unknown as ArrayBuffer,
            }
          : {
              name: 'AES-GCM',
              iv: iv as unknown as ArrayBuffer,
            },
        key,
        ct as unknown as ArrayBuffer
      )

      const seedsRaw = parseValidatedSeedPair(new Uint8Array(pt))

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
