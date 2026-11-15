import React, { useId, useMemo, useState } from 'react'
import type {
  CredentialVault,
  VaultBackupExportPayload,
} from '../credentialVault'
import type { VaultBackupDestinationKind } from '../safeStorage'

export interface VaultBackupExportPreviewCardProps {
  vault: CredentialVault
  onExport: (payload: VaultBackupExportPayload) => void
}

export function VaultBackupExportPreviewCard({
  vault,
  onExport,
}: VaultBackupExportPreviewCardProps) {
  const [selectedDestination, setSelectedDestination] = useState<
    VaultBackupDestinationKind | ''
  >('')
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const headingId = useId()
  const destinationSelectId = useId()

  const preview = useMemo(() => vault.getBackupExportPreview(), [vault])

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!selectedDestination) {
      setErrorMessage('Select an encrypted export destination before exporting.')
      return
    }

    try {
      setErrorMessage(null)
      const payload = vault.exportEncryptedBackup({
        destination: selectedDestination,
        explicitlySelectedByUser: true,
      })
      onExport(payload)
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Unable to export vault backup')
    }
  }

  return (
    <section aria-labelledby={headingId} className="vault-backup-preview">
      <h2 id={headingId}>Encrypted Vault Backup Preview</h2>
      <dl>
        <div>
          <dt>Envelope format version</dt>
          <dd>v{preview.envelopeVersion}</dd>
        </div>
        <div>
          <dt>Compatibility status</dt>
          <dd>{preview.supportedVersion ? 'Compatible' : 'Unsupported'}</dd>
        </div>
        <div>
          <dt>Key derivation</dt>
          <dd>
            {preview.compatibility.kdfAlgorithm} ({preview.compatibility.kdfIterations}{' '}
            iterations)
          </dd>
        </div>
        <div>
          <dt>Authenticated cipher</dt>
          <dd>{preview.compatibility.cipherAlgorithm}</dd>
        </div>
        <div>
          <dt>Encrypted payload size</dt>
          <dd>
            {preview.serializedByteLength} bytes ({preview.compatibility.ciphertextByteLength}{' '}
            ciphertext bytes)
          </dd>
        </div>
        <div>
          <dt>Suggested backup file</dt>
          <dd>{preview.suggestedFileName}</dd>
        </div>
      </dl>

      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor={destinationSelectId}>Encrypted export destination</label>
        </div>
        <div>
          <select
            id={destinationSelectId}
            value={selectedDestination}
            onChange={(e) => {
              setSelectedDestination(e.target.value as VaultBackupDestinationKind | '')
              setErrorMessage(null)
            }}
          >
            <option value="">Choose an export destination...</option>
            <option value="download-file">Encrypted JSON file download (.json)</option>
            <option value="clipboard-encrypted-json">
              Copy encrypted envelope JSON to clipboard
            </option>
          </select>
        </div>
        {errorMessage ? <p role="alert">{errorMessage}</p> : null}
        <div>
          <button type="submit">Export encrypted backup</button>
        </div>
      </form>
    </section>
  )
}
