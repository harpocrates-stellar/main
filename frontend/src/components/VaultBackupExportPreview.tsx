import React, { useId, useState } from 'react'
import {
  type VaultBackupPreviewResult,
  type VaultExportDestination,
} from '../credentialVault'

export interface VaultBackupExportPreviewProps {
  preview: VaultBackupPreviewResult
  onExport: (destination: VaultExportDestination) => void | Promise<void>
  exportLabel?: string
}

const DESTINATION_OPTIONS: ReadonlyArray<{
  value: VaultExportDestination
  label: string
  description: string
}> = [
  {
    value: 'file-download',
    label: 'Download encrypted backup file (.json)',
    description: 'Save the encrypted vault envelope to a local file you choose.',
  },
  {
    value: 'encrypted-clipboard',
    label: 'Copy encrypted envelope to clipboard',
    description: 'Copy only the encrypted JSON envelope for manual transfer.',
  },
]

/**
 * Displays envelope version and nonsecret compatibility metadata for a
 * credential vault backup, and requires explicit user selection of the
 * encrypted export destination before invoking `onExport`.
 */
export function VaultBackupExportPreview({
  preview,
  onExport,
  exportLabel = 'Export encrypted backup',
}: VaultBackupExportPreviewProps) {
  const [selectedDestination, setSelectedDestination] = useState<VaultExportDestination | null>(null)
  const [selectionError, setSelectionError] = useState(false)
  const groupName = useId()
  const errorId = useId()

  if (!preview.ok) {
    if (preview.code === 'NO_VAULT') {
      return (
        <section
          className="vault-backup-preview vault-backup-preview--empty"
          role="status"
          aria-label="Vault backup export preview"
        >
          <h3>Vault backup export preview</h3>
          <p>{preview.message}</p>
        </section>
      )
    }

    return (
      <section
        className="vault-backup-preview vault-backup-preview--error"
        role="alert"
        data-error-code={preview.code}
        aria-label="Vault backup export preview"
      >
        <h3>Vault backup export preview</h3>
        <p>{preview.message}</p>
        {preview.envelopeVersion !== undefined ? (
          <p data-testid="vault-preview-unsupported-version">
            Detected envelope version: <code>v{preview.envelopeVersion}</code>
          </p>
        ) : null}
      </section>
    )
  }

  const { metadata } = preview

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!selectedDestination) {
      setSelectionError(true)
      return
    }
    setSelectionError(false)
    await onExport(selectedDestination)
  }

  return (
    <section
      className="vault-backup-preview"
      aria-label="Vault backup export preview"
    >
      <h3>Vault backup export preview</h3>
      <p role="status">{metadata.compatibilityNote}</p>

      <dl className="vault-backup-preview__metadata">
        <div>
          <dt>Envelope version</dt>
          <dd data-testid="vault-preview-version">
            <code>v{metadata.envelopeVersion}</code>
          </dd>
        </div>
        <div>
          <dt>Compatibility</dt>
          <dd data-testid="vault-preview-compatibility">
            {metadata.compatible ? 'Compatible' : 'Incompatible'}
          </dd>
        </div>
        <div>
          <dt>Key derivation</dt>
          <dd>
            <code>{metadata.kdf}</code> ({metadata.kdfIterations.toLocaleString()} iterations)
          </dd>
        </div>
        <div>
          <dt>Cipher</dt>
          <dd>
            <code>{metadata.cipher}</code>
          </dd>
        </div>
        <div>
          <dt>Encrypted payload size</dt>
          <dd>
            {metadata.encryptedPayloadBytes} bytes (salt: {metadata.saltBytes}B, iv: {metadata.ivBytes}B, ciphertext: {metadata.ciphertextBytes}B)
          </dd>
        </div>
      </dl>

      <p className="vault-backup-preview__privacy-note">
        Preview displays nonsecret metadata only. Passphrases, credential seeds, and nullifier seeds are never shown.
      </p>

      <form onSubmit={handleSubmit} noValidate>
        <fieldset aria-describedby={selectionError ? errorId : undefined}>
          <legend>Select encrypted export destination (required)</legend>
          {DESTINATION_OPTIONS.map((option) => (
            <label key={option.value} className="vault-backup-preview__destination">
              <input
                type="radio"
                name={groupName}
                value={option.value}
                checked={selectedDestination === option.value}
                onChange={() => {
                  setSelectedDestination(option.value)
                  setSelectionError(false)
                }}
              />
              <span>{option.label}</span>
              <small>{option.description}</small>
            </label>
          ))}
        </fieldset>

        {selectionError ? (
          <p id={errorId} role="alert">
            Please select an encrypted export destination before exporting.
          </p>
        ) : null}

        <button type="submit">{exportLabel}</button>
      </form>
    </section>
  )
}

export default VaultBackupExportPreview
