import type { SeedPair } from './seedVault'
import {
  computeEnvelopeChangeFingerprint,
  subscribeToStorageKeyChanges,
} from './safeStorage'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

const FORBIDDEN_ACTIVE_WORK_KEYS = new Set([
  'credentialSeed',
  'nullifierSeed',
  'seeds',
  'password',
  'passphrase',
  'witness',
  'memoryKey',
])

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export type ActiveWorkScalar = string | number | boolean | null

export type ActiveVaultWorkSnapshot = Readonly<Record<string, ActiveWorkScalar>>

export type ExternalVaultChangeKind = 'updated' | 'removed'

export interface ExternalVaultChangeState {
  stale: boolean
  recoveryRequired: boolean
  kind: ExternalVaultChangeKind | null
  previousFingerprint: string | null
  currentFingerprint: string | null
  activeWorkPreserved: boolean
}

export type ExternalVaultRecoveryAction =
  | { type: 'reunlock-updated-vault'; password: string }
  | { type: 'continue-locked-preserve-work' }
  | { type: 'discard-active-work' }

export interface ExternalVaultRecoveryResult {
  resolved: boolean
  unlocked: boolean
  activeWork: ActiveVaultWorkSnapshot | null
  state: ExternalVaultChangeState
}

export type ExternalVaultChangeListener = (state: ExternalVaultChangeState) => void

function sanitizeActiveWork(
  work: Record<string, ActiveWorkScalar> | null,
): ActiveVaultWorkSnapshot | null {
  if (!work) return null
  const clean: Record<string, ActiveWorkScalar> = {}
  for (const [key, value] of Object.entries(work)) {
    if (FORBIDDEN_ACTIVE_WORK_KEYS.has(key)) {
      throw new Error(`Private vault field "${key}" cannot be stored in active work state`)
    }
    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      value === null
    ) {
      clean[key] = value
    }
  }
  return Object.freeze(clean)
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
  private observedEnvelopeRaw: string | null = null
  private activeWork: ActiveVaultWorkSnapshot | null = null
  private externalChangeState: ExternalVaultChangeState = {
    stale: false,
    recoveryRequired: false,
    kind: null,
    previousFingerprint: null,
    currentFingerprint: null,
    activeWorkPreserved: false,
  }
  private listeners = new Set<ExternalVaultChangeListener>()
  private unsubscribeStorage: (() => void) | null = null

  constructor(inactivityTimeoutMs = DEFAULT_TIMEOUT_MS) {
    this.inactivityTimeoutMs = inactivityTimeoutMs
    this.unsubscribeStorage = subscribeToStorageKeyChanges(VAULT_STORAGE_KEY, (event) => {
      this.handleExternalEnvelopeValue(event.newValue)
    })
  }

  isLocked(): boolean {
    return (
      this.memoryKey === null ||
      this.seeds === null ||
      this.externalChangeState.stale
    )
  }

  getSeeds(): SeedPair | null {
    if (this.externalChangeState.stale) {
      return null
    }
    this.resetTimeout()
    return this.seeds
  }

  hasVault(): boolean {
    return !!window.localStorage.getItem(VAULT_STORAGE_KEY)
  }

  setActiveWork(work: Record<string, ActiveWorkScalar> | null): void {
    this.activeWork = sanitizeActiveWork(work)
    if (this.externalChangeState.stale) {
      this.externalChangeState = {
        ...this.externalChangeState,
        activeWorkPreserved: this.activeWork !== null,
      }
      this.emitExternalChange()
    }
  }

  getActiveWork(): ActiveVaultWorkSnapshot | null {
    return this.activeWork
  }

  getExternalChangeState(): ExternalVaultChangeState {
    return { ...this.externalChangeState }
  }

  subscribeExternalChange(listener: ExternalVaultChangeListener): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  /**
   * Explicitly polls `localStorage` against the envelope observed when this
   * tab unlocked or configured the vault (useful on tab focus/visibilitychange).
   */
  checkExternalChange(): ExternalVaultChangeState {
    if (this.observedEnvelopeRaw !== null) {
      const currentRaw = window.localStorage.getItem(VAULT_STORAGE_KEY)
      this.handleExternalEnvelopeValue(currentRaw)
    }
    return this.getExternalChangeState()
  }

  async resolveExternalChange(
    action: ExternalVaultRecoveryAction,
  ): Promise<ExternalVaultRecoveryResult> {
    if (action.type === 'reunlock-updated-vault') {
      const currentRaw = window.localStorage.getItem(VAULT_STORAGE_KEY)
      if (!currentRaw) {
        return {
          resolved: false,
          unlocked: false,
          activeWork: this.activeWork,
          state: this.getExternalChangeState(),
        }
      }

      const unlocked = await this.performUnlockFromRaw(action.password, currentRaw)
      if (!unlocked) {
        return {
          resolved: false,
          unlocked: false,
          activeWork: this.activeWork,
          state: this.getExternalChangeState(),
        }
      }

      this.clearExternalChangeFlag(currentRaw)
      return {
        resolved: true,
        unlocked: true,
        activeWork: this.activeWork,
        state: this.getExternalChangeState(),
      }
    }

    if (action.type === 'continue-locked-preserve-work') {
      const currentRaw = window.localStorage.getItem(VAULT_STORAGE_KEY)
      this.zeroUnlockedCredentials()
      this.clearExternalChangeFlag(currentRaw)
      return {
        resolved: true,
        unlocked: false,
        activeWork: this.activeWork,
        state: this.getExternalChangeState(),
      }
    }

    // action.type === 'discard-active-work'
    const currentRaw = window.localStorage.getItem(VAULT_STORAGE_KEY)
    this.zeroUnlockedCredentials()
    this.activeWork = null
    this.clearExternalChangeFlag(currentRaw)
    return {
      resolved: true,
      unlocked: false,
      activeWork: null,
      state: this.getExternalChangeState(),
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

    const serialized = JSON.stringify(envelope)
    window.localStorage.setItem(VAULT_STORAGE_KEY, serialized)
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.clearExternalChangeFlag(serialized)
    this.resetTimeout()
  }

  async unlock(password: string): Promise<boolean> {
    if (this.externalChangeState.recoveryRequired) {
      throw new Error(
        'Vault envelope changed in another tab: choose an explicit recovery action before unlocking',
      )
    }

    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    const unlocked = await this.performUnlockFromRaw(password, stored)
    if (unlocked) {
      this.observedEnvelopeRaw = stored
    }
    return unlocked
  }

  lock(): void {
    this.zeroUnlockedCredentials()
  }

  destroy(): void {
    this.zeroUnlockedCredentials()
    this.observedEnvelopeRaw = null
    this.activeWork = null
    this.clearExternalChangeFlag(null)
    window.localStorage.removeItem(VAULT_STORAGE_KEY)
  }

  dispose(): void {
    if (this.unsubscribeStorage) {
      this.unsubscribeStorage()
      this.unsubscribeStorage = null
    }
    this.listeners.clear()
    this.clearTimeout()
  }

  private async performUnlockFromRaw(password: string, stored: string): Promise<boolean> {
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

  private handleExternalEnvelopeValue(newRawValue: string | null): void {
    // Only invalidate if this tab previously observed an active/unlocked envelope
    // and another tab actually modified or deleted it.
    if (this.observedEnvelopeRaw === null || newRawValue === this.observedEnvelopeRaw) {
      return
    }

    const previousFingerprint = computeEnvelopeChangeFingerprint(this.observedEnvelopeRaw)
    const currentFingerprint = computeEnvelopeChangeFingerprint(newRawValue)
    const kind: ExternalVaultChangeKind = newRawValue === null ? 'removed' : 'updated'

    // Invalidate unlocked stale view immediately while preserving `this.activeWork`.
    this.zeroUnlockedCredentials()

    this.externalChangeState = {
      stale: true,
      recoveryRequired: true,
      kind,
      previousFingerprint,
      currentFingerprint,
      activeWorkPreserved: this.activeWork !== null,
    }
    this.emitExternalChange()
  }

  private clearExternalChangeFlag(observedRaw: string | null): void {
    const wasStale = this.externalChangeState.stale
    this.observedEnvelopeRaw = observedRaw
    this.externalChangeState = {
      stale: false,
      recoveryRequired: false,
      kind: null,
      previousFingerprint: null,
      currentFingerprint: computeEnvelopeChangeFingerprint(observedRaw),
      activeWorkPreserved: false,
    }
    if (wasStale) {
      this.emitExternalChange()
    }
  }

  private zeroUnlockedCredentials(): void {
    this.memoryKey = null
    if (this.seeds) {
      this.seeds.credentialSeed = ''
      this.seeds.nullifierSeed = ''
    }
    this.seeds = null
    this.clearTimeout()
  }

  private emitExternalChange(): void {
    const snapshot = this.getExternalChangeState()
    for (const listener of this.listeners) {
      listener(snapshot)
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
