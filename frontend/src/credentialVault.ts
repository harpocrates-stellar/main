import type { SeedPair } from './seedVault'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes
const MAX_CAUSE_DEPTH = 5

export type VaultErrorReasonCode =
  | 'VAULT_EMPTY'
  | 'VAULT_CORRUPTED'
  | 'UNSUPPORTED_VAULT_VERSION'
  | 'STORAGE_READ_FAILED'
  | 'STORAGE_WRITE_FAILED'
  | 'STORAGE_REMOVE_FAILED'
  | 'STORAGE_QUOTA_EXCEEDED'
  | 'STORAGE_ACCESS_DENIED'
  | 'DECRYPTION_FAILED'
  | 'ENCRYPTION_FAILED'
  | 'KEY_DERIVATION_FAILED'
  | 'INVALID_PAYLOAD'
  | 'UNKNOWN_VAULT_ERROR'

export type VaultOperation = 'setup' | 'unlock' | 'destroy' | 'hasVault' | 'storage' | 'unknown'

export interface SerializedVaultCause {
  readonly reasonCode: VaultErrorReasonCode
  readonly errorType: string
  readonly cause?: SerializedVaultCause
}

export interface SerializedVaultError {
  readonly name: 'CredentialVaultError'
  readonly reasonCode: VaultErrorReasonCode
  readonly message: string
  readonly operation: VaultOperation
  readonly retryable: boolean
  readonly cause?: SerializedVaultCause
}

const SAFE_VAULT_MESSAGES: Record<VaultErrorReasonCode, string> = {
  VAULT_EMPTY: 'Vault is empty',
  VAULT_CORRUPTED: 'Vault corrupted: unable to parse envelope',
  UNSUPPORTED_VAULT_VERSION: 'Unsupported vault version',
  STORAGE_READ_FAILED: 'Vault storage read failed',
  STORAGE_WRITE_FAILED: 'Vault storage write failed',
  STORAGE_REMOVE_FAILED: 'Vault storage clear failed',
  STORAGE_QUOTA_EXCEEDED: 'Vault storage quota exceeded',
  STORAGE_ACCESS_DENIED: 'Vault storage access denied',
  DECRYPTION_FAILED: 'Vault decryption failed',
  ENCRYPTION_FAILED: 'Vault encryption failed',
  KEY_DERIVATION_FAILED: 'Vault key derivation failed',
  INVALID_PAYLOAD: 'Vault payload is invalid',
  UNKNOWN_VAULT_ERROR: 'Vault operation failed',
}

const RETRYABLE_REASONS = new Set<VaultErrorReasonCode>([
  'STORAGE_READ_FAILED',
  'STORAGE_WRITE_FAILED',
  'STORAGE_REMOVE_FAILED',
  'STORAGE_QUOTA_EXCEEDED',
])

const ALLOWED_ERROR_TYPES = new Set([
  'CredentialVaultError',
  'DOMException',
  'QuotaExceededError',
  'SecurityError',
  'OperationError',
  'DataError',
  'InvalidAccessError',
  'NotSupportedError',
  'SyntaxError',
  'TypeError',
  'RangeError',
  'Error',
])

function safeErrorType(err: unknown): string {
  if (typeof err !== 'object' || err === null) return 'UnknownError'
  const rawName = (err as { name?: unknown }).name
  if (typeof rawName === 'string' && ALLOWED_ERROR_TYPES.has(rawName)) {
    return rawName
  }
  return 'Error'
}

function classifyCauseReason(err: unknown, fallback: VaultErrorReasonCode): VaultErrorReasonCode {
  if (err instanceof CredentialVaultError) {
    return err.reasonCode
  }
  if (typeof err === 'object' && err !== null) {
    const name = (err as { name?: unknown }).name
    if (name === 'QuotaExceededError') return 'STORAGE_QUOTA_EXCEEDED'
    if (name === 'SecurityError') return 'STORAGE_ACCESS_DENIED'
    if (name === 'OperationError' || name === 'DataError') {
      if (fallback === 'ENCRYPTION_FAILED' || fallback === 'KEY_DERIVATION_FAILED') {
        return fallback
      }
      return 'DECRYPTION_FAILED'
    }
    if (name === 'SyntaxError') return 'VAULT_CORRUPTED'
    const code = (err as { reasonCode?: unknown }).reasonCode
    if (typeof code === 'string' && code in SAFE_VAULT_MESSAGES) {
      return code as VaultErrorReasonCode
    }
  }
  return fallback
}

function extractNestedCause(err: unknown): unknown {
  if (typeof err !== 'object' || err === null) return undefined
  if ('cause' in err && (err as { cause?: unknown }).cause !== undefined) {
    return (err as { cause?: unknown }).cause
  }
  if ('errors' in err && Array.isArray((err as { errors?: unknown[] }).errors)) {
    return (err as { errors: unknown[] }).errors[0]
  }
  return undefined
}

function buildRedactedCauseChain(
  rawCause: unknown,
  fallbackReason: VaultErrorReasonCode,
  seen = new Set<object>(),
  depth = 0
): SerializedVaultCause | undefined {
  if (rawCause === undefined || rawCause === null || depth >= MAX_CAUSE_DEPTH) {
    return undefined
  }
  if (typeof rawCause === 'object') {
    if (seen.has(rawCause)) return undefined
    seen.add(rawCause)
  }

  const reasonCode = classifyCauseReason(rawCause, fallbackReason)
  const errorType = safeErrorType(rawCause)
  const deeper =
    rawCause instanceof CredentialVaultError
      ? rawCause.serializedCause
      : buildRedactedCauseChain(extractNestedCause(rawCause), reasonCode, seen, depth + 1)

  return deeper
    ? Object.freeze({ reasonCode, errorType, cause: deeper })
    : Object.freeze({ reasonCode, errorType })
}

export class CredentialVaultError extends Error {
  readonly reasonCode: VaultErrorReasonCode
  readonly operation: VaultOperation
  readonly retryable: boolean
  readonly serializedCause?: SerializedVaultCause

  constructor(options: {
    reasonCode: VaultErrorReasonCode
    operation?: VaultOperation
    safeMessage?: string
    cause?: unknown
  }) {
    const safeMessage = options.safeMessage ?? SAFE_VAULT_MESSAGES[options.reasonCode]
    // Deliberately omit `{ cause }` on super() so browser error serializers and
    // devtools cannot traverse unredacted Error.cause graphs holding private inputs.
    super(safeMessage)
    this.name = 'CredentialVaultError'
    this.reasonCode = options.reasonCode
    this.operation = options.operation ?? 'unknown'
    this.retryable = RETRYABLE_REASONS.has(options.reasonCode)
    const redactedCause = buildRedactedCauseChain(options.cause, options.reasonCode)
    if (redactedCause !== undefined) {
      this.serializedCause = redactedCause
    }
    Object.defineProperty(this, 'stack', {
      value: `${this.name} [${this.reasonCode}]: ${safeMessage}`,
      enumerable: false,
      configurable: true,
      writable: false,
    })
  }

  toJSON(): SerializedVaultError {
    return this.serializedCause
      ? {
          name: 'CredentialVaultError',
          reasonCode: this.reasonCode,
          message: this.message,
          operation: this.operation,
          retryable: this.retryable,
          cause: this.serializedCause,
        }
      : {
          name: 'CredentialVaultError',
          reasonCode: this.reasonCode,
          message: this.message,
          operation: this.operation,
          retryable: this.retryable,
        }
  }
}

export function serializeVaultError(
  error: unknown,
  fallbackReason: VaultErrorReasonCode = 'UNKNOWN_VAULT_ERROR',
  operation: VaultOperation = 'unknown'
): SerializedVaultError {
  if (error instanceof CredentialVaultError) {
    return error.toJSON()
  }
  const reasonCode = classifyCauseReason(error, fallbackReason)
  const wrapped = new CredentialVaultError({
    reasonCode,
    operation,
    cause: error,
  })
  return wrapped.toJSON()
}

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
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
    try {
      return !!window.localStorage.getItem(VAULT_STORAGE_KEY)
    } catch (cause) {
      throw new CredentialVaultError({
        reasonCode: classifyCauseReason(cause, 'STORAGE_READ_FAILED'),
        operation: 'hasVault',
        cause,
      })
    }
  }

  async setup(password: string, seeds: SeedPair): Promise<void> {
    if (
      !seeds ||
      typeof seeds.credentialSeed !== 'string' ||
      typeof seeds.nullifierSeed !== 'string'
    ) {
      throw new CredentialVaultError({
        reasonCode: 'INVALID_PAYLOAD',
        operation: 'setup',
      })
    }

    const salt = crypto.getRandomValues(new Uint8Array(16))
    let key: CryptoKey
    try {
      key = await deriveKey(password, salt as unknown as ArrayBuffer)
    } catch (cause) {
      throw new CredentialVaultError({
        reasonCode: 'KEY_DERIVATION_FAILED',
        operation: 'setup',
        cause,
      })
    }

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const enc = new TextEncoder()
    const pt = enc.encode(
      JSON.stringify({
        credentialSeed: seeds.credentialSeed,
        nullifierSeed: seeds.nullifierSeed,
      })
    )

    let ct: ArrayBuffer
    try {
      ct = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv as unknown as ArrayBuffer,
        },
        key,
        pt
      )
    } catch (cause) {
      pt.fill(0)
      throw new CredentialVaultError({
        reasonCode: 'ENCRYPTION_FAILED',
        operation: 'setup',
        cause,
      })
    } finally {
      pt.fill(0)
    }

    const envelope: VaultEnvelope = {
      v: VAULT_VERSION,
      salt: bufToHex(salt as unknown as ArrayBuffer),
      iv: bufToHex(iv as unknown as ArrayBuffer),
      ct: bufToHex(ct),
    }

    try {
      window.localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
    } catch (cause) {
      throw new CredentialVaultError({
        reasonCode: classifyCauseReason(cause, 'STORAGE_WRITE_FAILED'),
        operation: 'setup',
        cause,
      })
    }
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  async unlock(password: string): Promise<boolean> {
    let stored: string | null
    try {
      stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    } catch (cause) {
      throw new CredentialVaultError({
        reasonCode: classifyCauseReason(cause, 'STORAGE_READ_FAILED'),
        operation: 'unlock',
        cause,
      })
    }
    if (!stored) {
      throw new CredentialVaultError({
        reasonCode: 'VAULT_EMPTY',
        operation: 'unlock',
      })
    }

    let envelope: VaultEnvelope
    try {
      const parsed: unknown = JSON.parse(stored)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new SyntaxError('Envelope must be a JSON object')
      }
      envelope = parsed as VaultEnvelope
    } catch (cause) {
      throw new CredentialVaultError({
        reasonCode: 'VAULT_CORRUPTED',
        operation: 'unlock',
        cause,
      })
    }

    if (envelope.v !== VAULT_VERSION) {
      const safeVersionLabel =
        typeof envelope.v === 'number' && Number.isSafeInteger(envelope.v)
          ? String(envelope.v)
          : 'invalid'
      throw new CredentialVaultError({
        reasonCode: 'UNSUPPORTED_VAULT_VERSION',
        operation: 'unlock',
        safeMessage: `Unsupported vault version: ${safeVersionLabel}`,
      })
    }

    if (
      typeof envelope.salt !== 'string' ||
      typeof envelope.iv !== 'string' ||
      typeof envelope.ct !== 'string' ||
      !/^[0-9a-fA-F]+$/.test(envelope.salt) ||
      !/^[0-9a-fA-F]+$/.test(envelope.iv) ||
      !/^[0-9a-fA-F]+$/.test(envelope.ct)
    ) {
      throw new CredentialVaultError({
        reasonCode: 'VAULT_CORRUPTED',
        operation: 'unlock',
      })
    }

    const salt = hexToBuf(envelope.salt)
    const iv = hexToBuf(envelope.iv)
    const ct = hexToBuf(envelope.ct)

    let pt: ArrayBuffer
    let key: CryptoKey
    try {
      key = await deriveKey(password, salt as unknown as ArrayBuffer)
      pt = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv as unknown as ArrayBuffer,
        },
        key,
        ct as unknown as ArrayBuffer
      )
    } catch {
      // Typically an OperationError if decryption fails due to bad password
      return false
    }

    try {
      const dec = new TextDecoder()
      const seedsRaw = JSON.parse(dec.decode(pt)) as Record<string, unknown>
      if (
        typeof seedsRaw !== 'object' ||
        seedsRaw === null ||
        typeof seedsRaw.credentialSeed !== 'string' ||
        typeof seedsRaw.nullifierSeed !== 'string'
      ) {
        throw new SyntaxError('Invalid decrypted seed payload')
      }

      this.memoryKey = key
      this.seeds = {
        credentialSeed: seedsRaw.credentialSeed,
        nullifierSeed: seedsRaw.nullifierSeed,
      }
      this.resetTimeout()
      return true
    } catch (cause) {
      throw new CredentialVaultError({
        reasonCode: 'INVALID_PAYLOAD',
        operation: 'unlock',
        cause,
      })
    } finally {
      new Uint8Array(pt).fill(0)
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
    try {
      window.localStorage.removeItem(VAULT_STORAGE_KEY)
    } catch (cause) {
      throw new CredentialVaultError({
        reasonCode: classifyCauseReason(cause, 'STORAGE_REMOVE_FAILED'),
        operation: 'destroy',
        cause,
      })
    }
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
