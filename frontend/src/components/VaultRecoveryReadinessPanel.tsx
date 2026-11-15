import { useId, useState } from 'react'
import type {
  CredentialVault,
  VaultRecoveryReadinessReport,
} from '../credentialVault'

export interface VaultRecoveryReadinessPanelProps {
  vault: CredentialVault
}

export function VaultRecoveryReadinessPanel({
  vault,
}: VaultRecoveryReadinessPanelProps) {
  const [report, setReport] = useState<VaultRecoveryReadinessReport>(() =>
    vault.getRecoveryReadinessReport(),
  )
  const headingId = useId()

  const handleRefresh = () => {
    setReport(vault.getRecoveryReadinessReport())
  }

  const formatLabel =
    report.formatVersion === null
      ? `None (supports v${report.supportedFormatVersion})`
      : `v${report.formatVersion} (supports v${report.supportedFormatVersion})`

  const storageLabel =
    report.storageStatus === 'available'
      ? 'Available'
      : report.storageStatus === 'read-only'
        ? 'Read-only (quota or write restricted)'
        : 'Unavailable'

  const backupLabel = report.backupPresent
    ? report.backupMatchesCurrentVersion
      ? 'Recorded for active format version'
      : 'Outdated format backup'
    : 'No encrypted backup recorded'

  return (
    <section aria-labelledby={headingId} className="vault-recovery-readiness">
      <h2 id={headingId}>Local Vault Recovery Readiness</h2>
      <p role="status">
        Overall readiness:{' '}
        {report.overallStatus === 'ready'
          ? 'Ready for offline recovery'
          : report.overallStatus === 'unavailable'
            ? 'Storage unavailable'
            : 'Action needed'}
      </p>
      <dl>
        <div>
          <dt>Format version</dt>
          <dd>{formatLabel}</dd>
        </div>
        <div>
          <dt>Browser storage availability</dt>
          <dd>{storageLabel}</dd>
        </div>
        <div>
          <dt>Encrypted backup presence</dt>
          <dd>{backupLabel}</dd>
        </div>
      </dl>

      {report.actionItems.length > 0 ? (
        <ul>
          {report.actionItems.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : null}

      <div>
        <button type="button" onClick={handleRefresh}>
          Refresh readiness check
        </button>
      </div>
    </section>
  )
}
