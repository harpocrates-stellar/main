import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { CredentialVault } from './credentialVault'
import { VaultBackupExportPreviewCard } from './components/VaultBackupExportPreviewCard'
import { expectNoA11yViolations, runAxe } from './test/axeA11y'

describe('Vault backup export preview (#1147)', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('exposes envelope version and non-secret compatibility metadata without leaking witness values or raw hex fields', async () => {
    const vault = new CredentialVault()
    const secretSeeds = {
      credentialSeed: 'super-secret-credential-witness-999',
      nullifierSeed: 'super-secret-nullifier-witness-888',
    }
    await vault.setup('StrongBackupPass#2026!', secretSeeds)
    const rawStored = JSON.parse(window.localStorage.getItem('harpocrates:credential-vault')!)

    const preview = vault.getBackupExportPreview('my-witness-backup')
    expect(preview).toEqual({
      envelopeVersion: 1,
      supportedVersion: true,
      serializedByteLength: expect.any(Number),
      suggestedFileName: 'my-witness-backup.json',
      compatibility: {
        kdfAlgorithm: 'PBKDF2-HMAC-SHA-256',
        kdfIterations: 600000,
        cipherAlgorithm: 'AES-256-GCM',
        saltByteLength: 16,
        ivByteLength: 12,
        ciphertextByteLength: expect.any(Number),
        encoding: 'hex',
      },
    })

    const serializedPreview = JSON.stringify(preview)
    expect(serializedPreview).not.toContain(secretSeeds.credentialSeed)
    expect(serializedPreview).not.toContain(secretSeeds.nullifierSeed)
    expect(serializedPreview).not.toContain('StrongBackupPass#2026!')
    expect(serializedPreview).not.toContain(rawStored.ct)
    expect(serializedPreview).not.toContain(rawStored.salt)
  })

  it('requires explicit user selection of an allowed encrypted export destination', async () => {
    const vault = new CredentialVault()
    await vault.setup('Passphrase#2026!', {
      credentialSeed: 'cred-1',
      nullifierSeed: 'null-1',
    })

    expect(() => vault.exportEncryptedBackup(undefined)).toThrow(
      'Explicit user selection of an encrypted export destination is required',
    )
    expect(() =>
      vault.exportEncryptedBackup({
        destination: null,
        explicitlySelectedByUser: true,
      }),
    ).toThrow('Explicit user selection of an encrypted export destination is required')
    expect(() =>
      vault.exportEncryptedBackup({
        destination: 'download-file',
        explicitlySelectedByUser: false,
      }),
    ).toThrow('Explicit user selection of an encrypted export destination is required')
    expect(() =>
      vault.exportEncryptedBackup({
        destination: 'untrusted-remote-url',
        explicitlySelectedByUser: true,
      }),
    ).toThrow('Explicit user selection of an encrypted export destination is required')

    const validExport = vault.exportEncryptedBackup({
      destination: 'download-file',
      explicitlySelectedByUser: true,
      fileName: 'team backup 01',
    })
    expect(validExport.destination).toBe('download-file')
    expect(validExport.fileName).toBe('team-backup-01.json')
    expect(validExport.encryptedEnvelopeJson).not.toContain('cred-1')
    expect(JSON.parse(validExport.encryptedEnvelopeJson)).toMatchObject({ v: 1 })
  })

  it('renders an accessible preview card (WCAG 2.2 AA) and blocks export until user chooses a destination', async () => {
    const vault = new CredentialVault()
    await vault.setup('PreviewPass#2026!', {
      credentialSeed: 'hidden-seed-a',
      nullifierSeed: 'hidden-seed-b',
    })

    const onExport = vi.fn()
    const { container } = render(
      <VaultBackupExportPreviewCard vault={vault} onExport={onExport} />,
    )

    expect(screen.getByText('v1')).toBeTruthy()
    expect(screen.getByText(/PBKDF2-HMAC-SHA-256/)).toBeTruthy()
    expect(screen.getByText('AES-256-GCM')).toBeTruthy()
    expect(container.textContent).not.toContain('hidden-seed-a')

    expectNoA11yViolations(await runAxe(container), 'vault backup export preview card')

    // Attempt export before selecting destination -> blocked with alert
    fireEvent.click(screen.getByRole('button', { name: 'Export encrypted backup' }))
    expect(onExport).not.toHaveBeenCalled()
    expect(screen.getByRole('alert').textContent).toContain(
      'Select an encrypted export destination before exporting.',
    )

    // Explicitly select destination -> exports encrypted payload cleanly
    fireEvent.change(screen.getByLabelText('Encrypted export destination'), {
      target: { value: 'clipboard-encrypted-json' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Export encrypted backup' }))

    expect(onExport).toHaveBeenCalledTimes(1)
    expect(onExport.mock.calls[0][0].destination).toBe('clipboard-encrypted-json')
    expect(onExport.mock.calls[0][0].preview.envelopeVersion).toBe(1)
  })
})
