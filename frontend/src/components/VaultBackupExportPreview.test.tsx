import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { VaultBackupExportPreview } from './VaultBackupExportPreview'
import type { VaultBackupPreviewResult } from '../credentialVault'

const VALID_PREVIEW: VaultBackupPreviewResult = {
  ok: true,
  requiresDestinationSelection: true,
  metadata: {
    envelopeVersion: 1,
    compatible: true,
    compatibilityNote: 'Compatible with Harpocrates Credential Vault v1 (PBKDF2-SHA256 + AES-256-GCM).',
    kdf: 'PBKDF2-SHA256',
    kdfIterations: 600000,
    cipher: 'AES-256-GCM',
    saltBytes: 16,
    ivBytes: 12,
    ciphertextBytes: 64,
    encryptedPayloadBytes: 240,
    containsSecretsInPreview: false,
  },
}

describe('VaultBackupExportPreview', () => {
  it('displays envelope version and nonsecret compatibility metadata', () => {
    render(<VaultBackupExportPreview preview={VALID_PREVIEW} onExport={vi.fn()} />)

    expect(screen.getByTestId('vault-preview-version')).toHaveTextContent('v1')
    expect(screen.getByTestId('vault-preview-compatibility')).toHaveTextContent('Compatible')
    expect(screen.getByText('PBKDF2-SHA256')).toBeInTheDocument()
    expect(screen.getByText('AES-256-GCM')).toBeInTheDocument()
    expect(screen.getByText(/240 bytes/)).toBeInTheDocument()
  })

  it('requires explicit user selection of the encrypted export destination before exporting', () => {
    const onExport = vi.fn()
    render(<VaultBackupExportPreview preview={VALID_PREVIEW} onExport={onExport} />)

    // Neither destination is selected initially
    const radios = screen.getAllByRole('radio') as HTMLInputElement[]
    expect(radios.every((radio) => !radio.checked)).toBe(true)

    // Submitting without selection fails closed and shows an alert
    fireEvent.click(screen.getByRole('button', { name: /export encrypted backup/i }))
    expect(onExport).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent(
      /select an encrypted export destination/i,
    )

    // Explicitly select a destination and submit
    fireEvent.click(screen.getByLabelText(/download encrypted backup file/i))
    fireEvent.click(screen.getByRole('button', { name: /export encrypted backup/i }))
    expect(onExport).toHaveBeenCalledWith('file-download')
  })

  it('renders an empty status when no vault is present', () => {
    const emptyPreview: VaultBackupPreviewResult = {
      ok: false,
      code: 'NO_VAULT',
      message: 'No encrypted credential vault is stored on this device.',
    }
    render(<VaultBackupExportPreview preview={emptyPreview} onExport={vi.fn()} />)

    expect(screen.getByRole('status')).toHaveTextContent(/no encrypted credential vault/i)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('renders an error alert with detected version when envelope version is unsupported', () => {
    const unsupportedPreview: VaultBackupPreviewResult = {
      ok: false,
      code: 'UNSUPPORTED_VERSION',
      message: 'Unsupported vault version: 99. Supported version: 1.',
      envelopeVersion: 99,
    }
    render(<VaultBackupExportPreview preview={unsupportedPreview} onExport={vi.fn()} />)

    expect(screen.getByRole('alert')).toHaveAttribute('data-error-code', 'UNSUPPORTED_VERSION')
    expect(screen.getByTestId('vault-preview-unsupported-version')).toHaveTextContent('v99')
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })
})
