import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CredentialVault, runVaultRecoveryRehearsal } from './credentialVault'
import { createIsolatedVaultStateContainer } from './safeStorage'

describe('One-time synthetic vault recovery rehearsal (#1151)', () => {
  beforeEach(() => {
    window.localStorage.clear()
    window.sessionStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
    window.sessionStorage.clear()
  })

  it('verifies export and import in isolated containers without touching live user credentials or browser storage', async () => {
    const liveVault = new CredentialVault()
    const liveSeeds = {
      credentialSeed: 'user-private-credential-seed',
      nullifierSeed: 'user-private-nullifier-seed',
    }
    await liveVault.setup('user-live-passphrase-123!', liveSeeds)
    const snapshotBefore = window.localStorage.getItem('harpocrates:credential-vault')
    expect(snapshotBefore).toBeTruthy()

    const getSpy = vi.spyOn(window.localStorage, 'getItem')
    const setSpy = vi.spyOn(window.localStorage, 'setItem')
    const removeSpy = vi.spyOn(window.localStorage, 'removeItem')
    const clearSpy = vi.spyOn(window.localStorage, 'clear')
    const sessionSetSpy = vi.spyOn(window.sessionStorage, 'setItem')

    const report = await liveVault.rehearseRecovery()

    expect(report).toEqual({
      ok: true,
      envelopeVersion: 1,
      steps: {
        setup: true,
        exported: true,
        imported: true,
        unlocked: true,
        roundTripVerified: true,
        cleanedUp: true,
      },
      message: 'Synthetic vault recovery rehearsal succeeded in isolated memory.',
    })

    // Zero browser storage calls occurred during rehearsal
    expect(getSpy).not.toHaveBeenCalled()
    expect(setSpy).not.toHaveBeenCalled()
    expect(removeSpy).not.toHaveBeenCalled()
    expect(clearSpy).not.toHaveBeenCalled()
    expect(sessionSetSpy).not.toHaveBeenCalled()

    // Restore spy to inspect live state cleanly
    getSpy.mockRestore()
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(snapshotBefore)
    expect(liveVault.isLocked()).toBe(false)
    expect(liveVault.getSeeds()).toEqual(liveSeeds)

    // Report never leaks synthetic or user secret material
    const serializedReport = JSON.stringify(report)
    expect(serializedReport).not.toContain('rehearsal-')
    expect(serializedReport).not.toContain(liveSeeds.credentialSeed)
    expect(serializedReport).not.toContain(liveSeeds.nullifierSeed)
  })

  it('generates fresh one-time synthetic material per rehearsal run', async () => {
    const observedEnvelopes: string[] = []

    const first = await runVaultRecoveryRehearsal({
      transformExportedEnvelope: (serialized) => {
        observedEnvelopes.push(serialized)
        return serialized
      },
    })
    const second = await runVaultRecoveryRehearsal({
      transformExportedEnvelope: (serialized) => {
        observedEnvelopes.push(serialized)
        return serialized
      },
    })

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
    expect(observedEnvelopes).toHaveLength(2)
    const env1 = JSON.parse(observedEnvelopes[0])
    const env2 = JSON.parse(observedEnvelopes[1])
    expect(env1.salt).not.toBe(env2.salt)
    expect(env1.iv).not.toBe(env2.iv)
    expect(env1.ct).not.toBe(env2.ct)
  })

  it('reports IMPORT_FAILED and cleans up isolated state when exported envelope is malformed', async () => {
    const liveVault = new CredentialVault()
    const liveSeeds = { credentialSeed: 'keep-me-cred', nullifierSeed: 'keep-me-null' }
    await liveVault.setup('keep-me-passphrase', liveSeeds)
    const storedBefore = window.localStorage.getItem('harpocrates:credential-vault')

    const report = await runVaultRecoveryRehearsal({
      transformExportedEnvelope: () => '{"v":999,"salt":"00","iv":"00","ct":"00"}',
    })

    expect(report).toEqual({
      ok: false,
      envelopeVersion: 1,
      steps: {
        setup: true,
        exported: true,
        imported: false,
        unlocked: false,
        roundTripVerified: false,
        cleanedUp: true,
      },
      failureCode: 'IMPORT_FAILED',
      message: 'Synthetic vault recovery rehearsal failed (IMPORT_FAILED). Live credentials were not touched.',
    })

    expect(liveVault.isLocked()).toBe(false)
    expect(liveVault.getSeeds()).toEqual(liveSeeds)
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBe(storedBefore)
  })

  it('reports UNLOCK_FAILED when ciphertext authentication fails during rehearsal import', async () => {
    const report = await runVaultRecoveryRehearsal({
      transformExportedEnvelope: (serialized) => {
        const parsed = JSON.parse(serialized) as { v: number; salt: string; iv: string; ct: string }
        const flippedNibble = parsed.ct[0] === '0' ? '1' : '0'
        return JSON.stringify({
          ...parsed,
          ct: `${flippedNibble}${parsed.ct.slice(1)}`,
        })
      },
    })

    expect(report.ok).toBe(false)
    expect(report.failureCode).toBe('UNLOCK_FAILED')
    expect(report.steps).toEqual({
      setup: true,
      exported: true,
      imported: true,
      unlocked: false,
      roundTripVerified: false,
      cleanedUp: true,
    })
  })

  it('supports standalone isolated vault state container lifecycle', () => {
    const container = createIsolatedVaultStateContainer()
    expect(container.size()).toBe(0)
    expect(container.getItem('harpocrates:credential-vault')).toBeNull()

    container.setItem('harpocrates:credential-vault', '{"v":1}')
    expect(container.size()).toBe(1)
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBeNull()

    container.clear()
    expect(container.size()).toBe(0)
  })
})
