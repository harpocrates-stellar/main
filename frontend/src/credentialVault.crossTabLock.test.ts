import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { CredentialVault } from './credentialVault'
import {
  sanitizeVaultLockBroadcastPayload,
  type VaultLockBroadcastPayload,
  type VaultLockTransport,
} from './safeStorage'

function createSimulatedTabBus() {
  const wireLog: unknown[] = []
  const subscribers = new Set<{
    id: number
    handler: (payload: VaultLockBroadcastPayload) => void
  }>()
  let nextId = 1

  function createTabTransport(): VaultLockTransport {
    const tabId = nextId++
    let entry: {
      id: number
      handler: (payload: VaultLockBroadcastPayload) => void
    } | null = null

    return {
      publishLock(payload: VaultLockBroadcastPayload) {
        wireLog.push(structuredClone(payload))
        for (const sub of subscribers) {
          if (sub.id !== tabId) {
            sub.handler(payload)
          }
        }
      },
      subscribeLock(onLock: (payload: VaultLockBroadcastPayload) => void) {
        entry = { id: tabId, handler: onLock }
        subscribers.add(entry)
        return () => {
          if (entry) subscribers.delete(entry)
        }
      },
      close() {
        if (entry) subscribers.delete(entry)
      },
    }
  }

  return { wireLog, createTabTransport, subscribers }
}

describe('Cross-tab explicit vault lock propagation (#1146)', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('broadcasts only a non-secret lock event and session generation while zeroing decrypted references across open tabs', async () => {
    const bus = createSimulatedTabBus()
    const tabAVault = new CredentialVault(15 * 60 * 1000, {
      lockTransport: bus.createTabTransport(),
    })
    const tabBVault = new CredentialVault(15 * 60 * 1000, {
      lockTransport: bus.createTabTransport(),
    })
    const tabCVault = new CredentialVault(15 * 60 * 1000, {
      lockTransport: bus.createTabTransport(),
    })

    const secretSeeds = {
      credentialSeed: 'witness-credential-secret-abc',
      nullifierSeed: 'witness-nullifier-secret-xyz',
    }
    await tabAVault.setup('SharedPass#2026!', secretSeeds)
    expect(await tabBVault.unlock('SharedPass#2026!')).toBe(true)
    expect(await tabCVault.unlock('SharedPass#2026!')).toBe(true)

    const heldRefA = tabAVault.getSeeds()!
    const heldRefB = tabBVault.getSeeds()!
    const heldRefC = tabCVault.getSeeds()!
    expect(heldRefB.credentialSeed).toBe(secretSeeds.credentialSeed)
    expect(heldRefC.nullifierSeed).toBe(secretSeeds.nullifierSeed)

    const encryptedBeforeLock = window.localStorage.getItem('harpocrates:credential-vault')

    // Explicit lock in Tab A propagates to Tab B and Tab C without echo loops
    tabAVault.lock()

    expect(bus.wireLog).toHaveLength(1)
    expect(bus.wireLog[0]).toEqual({
      type: 'VAULT_EXPLICIT_LOCK',
      sessionGeneration: 2,
    })
    expect(Object.keys(bus.wireLog[0] as object).sort()).toEqual([
      'sessionGeneration',
      'type',
    ])
    const serializedWire = JSON.stringify(bus.wireLog)
    expect(serializedWire).not.toContain(secretSeeds.credentialSeed)
    expect(serializedWire).not.toContain(secretSeeds.nullifierSeed)
    expect(serializedWire).not.toContain('SharedPass#2026!')

    // All open tabs are now locked and all previously issued SeedPair references are zeroed
    expect(tabAVault.isLocked()).toBe(true)
    expect(tabBVault.isLocked()).toBe(true)
    expect(tabCVault.isLocked()).toBe(true)
    expect(tabBVault.getSeeds()).toBeNull()
    expect(tabCVault.getSeeds()).toBeNull()
    expect(heldRefA).toEqual({ credentialSeed: '', nullifierSeed: '' })
    expect(heldRefB).toEqual({ credentialSeed: '', nullifierSeed: '' })
    expect(heldRefC).toEqual({ credentialSeed: '', nullifierSeed: '' })
    expect(tabBVault.getSessionGeneration()).toBe(2)
    expect(tabCVault.getSessionGeneration()).toBe(2)

    // Encrypted VaultEnvelope in localStorage remains intact for subsequent unlock
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(
      encryptedBeforeLock,
    )

    tabAVault.dispose()
    tabBVault.dispose()
    tabCVault.dispose()
  })

  it('propagates over native BroadcastChannel across independent vault instances', async () => {
    const tab1 = new CredentialVault()
    const tab2 = new CredentialVault()

    await tab1.setup('NativeChannelPass#1', {
      credentialSeed: 'native-cred',
      nullifierSeed: 'native-null',
    })
    expect(await tab2.unlock('NativeChannelPass#1')).toBe(true)
    const tab2Ref = tab2.getSeeds()!

    tab1.lock()

    await vi.waitFor(() => {
      expect(tab2.isLocked()).toBe(true)
    })
    expect(tab2Ref).toEqual({ credentialSeed: '', nullifierSeed: '' })

    tab1.dispose()
    tab2.dispose()
  })

  it('rejects malformed or extra-field broadcast payloads and ignores stale session generations', async () => {
    expect(
      sanitizeVaultLockBroadcastPayload({
        type: 'VAULT_EXPLICIT_LOCK',
        sessionGeneration: 1,
        credentialSeed: 'leaked',
      }),
    ).toBeNull()
    expect(
      sanitizeVaultLockBroadcastPayload({
        type: 'VAULT_EXPLICIT_LOCK',
        sessionGeneration: 0,
      }),
    ).toBeNull()
    expect(sanitizeVaultLockBroadcastPayload('VAULT_EXPLICIT_LOCK')).toBeNull()

    let injectedListener: ((payload: VaultLockBroadcastPayload) => void) | null = null
    const customTransport: VaultLockTransport = {
      publishLock: () => {},
      subscribeLock: (cb) => {
        injectedListener = cb
        return () => {
          injectedListener = null
        }
      },
      close: () => {},
    }

    const vault = new CredentialVault(15 * 60 * 1000, {
      lockTransport: customTransport,
      initialSessionGeneration: 5,
    })
    await vault.setup('GenTestPass#1', {
      credentialSeed: 'active-cred',
      nullifierSeed: 'active-null',
    })
    expect(vault.getSessionGeneration()).toBe(6)

    // Stale generation (< 6) is ignored so replayed old messages cannot disrupt newer unlock
    injectedListener!({
      type: 'VAULT_EXPLICIT_LOCK',
      sessionGeneration: 3,
    })
    expect(vault.isLocked()).toBe(false)

    // Current/newer generation (>= 6) locks immediately
    injectedListener!({
      type: 'VAULT_EXPLICIT_LOCK',
      sessionGeneration: 6,
    })
    expect(vault.isLocked()).toBe(true)
    vault.dispose()
  })
})
