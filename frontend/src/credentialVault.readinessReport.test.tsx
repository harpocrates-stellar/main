import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { CredentialVault } from './credentialVault'
import { VaultRecoveryReadinessPanel } from './components/VaultRecoveryReadinessPanel'
import { expectNoA11yViolations, runAxe } from './test/axeA11y'

describe('Local vault recovery readiness report (#1145)', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('reports format version, storage availability, and backup presence without revealing witness values or keys', async () => {
    const vault = new CredentialVault()
    const secretSeeds = {
      credentialSeed: 'private-credential-witness-4455',
      nullifierSeed: 'private-nullifier-witness-6677',
    }
    const passphrase = 'SecretReadinessPass#2026!'
    await vault.setup(passphrase, secretSeeds)
    expect(vault.isLocked()).toBe(false)

    // Before backup is recorded -> attention-needed
    const beforeBackup = vault.getRecoveryReadinessReport()
    expect(beforeBackup).toMatchObject({
      ready: false,
      overallStatus: 'attention-needed',
      formatVersion: 1,
      supportedFormatVersion: 1,
      envelopeStatus: 'supported',
      storageAvailable: true,
      storageStatus: 'available',
      backupPresent: false,
      backupMatchesCurrentVersion: false,
    })

    // Record encrypted backup -> ready
    const recordedTime = new Date('2026-11-15T12:00:00.000Z')
    vault.markBackupCompleted(recordedTime)

    const readyReport = vault.getRecoveryReadinessReport()
    expect(readyReport).toEqual({
      ready: true,
      overallStatus: 'ready',
      formatVersion: 1,
      supportedFormatVersion: 1,
      envelopeStatus: 'supported',
      storageAvailable: true,
      storageStatus: 'available',
      backupPresent: true,
      backupMatchesCurrentVersion: true,
      lastBackupRecordedAt: '2026-11-15T12:00:00.000Z',
      actionItems: [],
    })

    // Verify zero secret leakage across report and storage
    const storedEnvelope = JSON.parse(
      window.localStorage.getItem('harpocrates:credential-vault')!,
    )
    const serializedReport = JSON.stringify(readyReport)
    expect(serializedReport).not.toContain(secretSeeds.credentialSeed)
    expect(serializedReport).not.toContain(secretSeeds.nullifierSeed)
    expect(serializedReport).not.toContain(passphrase)
    expect(serializedReport).not.toContain(storedEnvelope.ct)
    expect(serializedReport).not.toContain(storedEnvelope.salt)
    expect(serializedReport).not.toContain('CryptoKey')
  })

  it('detects unavailable/read-only storage and unsupported or corrupted vault versions', async () => {
    const vault = new CredentialVault()
    await vault.setup('Pass#1', {
      credentialSeed: 'cred-1',
      nullifierSeed: 'null-1',
    })
    vault.markBackupCompleted()

    // Mutate stored envelope version to unsupported v99
    const mutated = JSON.parse(
      window.localStorage.getItem('harpocrates:credential-vault')!,
    )
    mutated.v = 99
    window.localStorage.setItem('harpocrates:credential-vault', JSON.stringify(mutated))

    const unsupportedReport = vault.getRecoveryReadinessReport()
    expect(unsupportedReport.ready).toBe(false)
    expect(unsupportedReport.formatVersion).toBe(99)
    expect(unsupportedReport.envelopeStatus).toBe('unsupported-version')
    expect(unsupportedReport.backupMatchesCurrentVersion).toBe(false)

    // Simulate completely blocked localStorage read (`SecurityError`)
    vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => {
      const err = new Error('Blocked')
      err.name = 'SecurityError'
      throw err
    })

    const blockedReport = vault.getRecoveryReadinessReport()
    expect(blockedReport.ready).toBe(false)
    expect(blockedReport.overallStatus).toBe('unavailable')
    expect(blockedReport.storageAvailable).toBe(false)
    expect(blockedReport.storageStatus).toBe('unavailable')
  })

  it('renders an accessible readiness panel (WCAG 2.2 AA) and updates when refreshed', async () => {
    const vault = new CredentialVault()
    await vault.setup('UiReadinessPass#1', {
      credentialSeed: 'never-render-cred',
      nullifierSeed: 'never-render-null',
    })

    const { container } = render(<VaultRecoveryReadinessPanel vault={vault} />)

    expect(screen.getByText('v1 (supports v1)')).toBeTruthy()
    expect(screen.getByText('Available')).toBeTruthy()
    expect(screen.getByText('No encrypted backup recorded')).toBeTruthy()
    expect(container.textContent).not.toContain('never-render-cred')
    expect(container.textContent).not.toContain('never-render-null')

    expectNoA11yViolations(await runAxe(container), 'vault recovery readiness panel')

    vault.markBackupCompleted(new Date('2026-11-15T15:30:00.000Z'))
    fireEvent.click(screen.getByRole('button', { name: 'Refresh readiness check' }))

    expect(screen.getByText('Recorded for active format version')).toBeTruthy()
    expect(screen.getByText(/Ready for offline recovery/)).toBeTruthy()
  })
})
