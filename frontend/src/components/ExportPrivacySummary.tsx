import { AlertTriangle, ShieldCheck } from 'lucide-react'
import type { ExportPrivacySummaryResult } from '../exportPrivacySummary'
import './ExportPrivacySummary.css'

type Props = {
  summary: ExportPrivacySummaryResult
  onAcknowledgeSensitiveFields?: (keys: string[]) => void
}

/**
 * Evidence Studio panel: summarizes included metadata classes and public
 * identifiers before exporting an evidence artifact, and requires explicit
 * acknowledgement only for newly exposed sensitive fields.
 */
export function ExportPrivacySummary({ summary, onAcknowledgeSensitiveFields }: Props) {
  if (!summary.ok) {
    if (summary.code === 'MISSING_EVIDENCE') {
      return (
        <div className="export-privacy-summary export-privacy-summary--empty" role="status">
          <h3>Export privacy summary</h3>
          <p className="muted">Generate evidence to review included metadata before exporting.</p>
        </div>
      )
    }

    return (
      <div
        className="export-privacy-summary export-privacy-summary--error"
        role="alert"
        data-error-code={summary.code}
      >
        <h3>Export privacy summary</h3>
        <p>{summary.message}</p>
      </div>
    )
  }

  const newlyExposedKeys = summary.newlyExposedSensitiveFields.map((field) => field.key)

  return (
    <div
      className="export-privacy-summary"
      role="region"
      aria-label="Export privacy summary"
    >
      <header className="export-privacy-summary__header">
        <ShieldCheck size={16} aria-hidden="true" />
        <h3>Export privacy summary</h3>
        <span
          className={
            summary.requiresAcknowledgement
              ? 'export-privacy-summary__badge export-privacy-summary__badge--warn'
              : 'export-privacy-summary__badge'
          }
        >
          {summary.requiresAcknowledgement ? 'Acknowledgement required' : 'Ready to export'}
        </span>
      </header>

      <p className="export-privacy-summary__overview">{summary.summary}</p>

      <div className="export-privacy-summary__section">
        <h4>Included metadata classes</h4>
        <ul className="export-privacy-summary__classes" aria-label="Included metadata classes">
          {summary.metadataClasses.map((item) => (
            <li
              key={item.key}
              className="export-privacy-summary__class-row"
              data-metadata-class={item.key}
            >
              <span className="export-privacy-summary__class-label">{item.label}</span>
              <span className="export-privacy-summary__class-desc">{item.description}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="export-privacy-summary__section">
        <h4>Public identifiers</h4>
        <dl className="export-privacy-summary__identifiers" aria-label="Public identifiers">
          {summary.publicIdentifiers.map((identifier) => (
            <div
              key={identifier.key}
              className={
                identifier.sensitive
                  ? 'export-privacy-summary__id-row export-privacy-summary__id-row--sensitive'
                  : 'export-privacy-summary__id-row'
              }
              data-identifier-key={identifier.key}
              data-sensitive={identifier.sensitive ? 'true' : 'false'}
            >
              <dt>{identifier.label}</dt>
              <dd>
                <code>{identifier.value}</code>
              </dd>
            </div>
          ))}
        </dl>
      </div>

      {summary.requiresAcknowledgement ? (
        <div className="export-privacy-summary__ack" role="group" aria-label="Newly exposed sensitive fields">
          <p className="export-privacy-summary__ack-title">
            <AlertTriangle size={14} aria-hidden="true" />
            Newly exposed sensitive fields
          </p>
          <ul className="export-privacy-summary__ack-list">
            {summary.newlyExposedSensitiveFields.map((field) => (
              <li key={field.key} data-sensitive-key={field.key}>
                <strong>{field.label}:</strong> {field.reason}
              </li>
            ))}
          </ul>
          <label className="export-privacy-summary__ack-label">
            <input
              type="checkbox"
              checked={false}
              onChange={(event) => {
                if (event.target.checked) {
                  onAcknowledgeSensitiveFields?.(newlyExposedKeys)
                }
              }}
            />
            <span>
              I acknowledge exporting the newly exposed sensitive{' '}
              {summary.newlyExposedSensitiveFields.length === 1 ? 'field' : 'fields'} listed above.
            </span>
          </label>
        </div>
      ) : summary.sensitiveFields.length > 0 ? (
        <p className="export-privacy-summary__acked-note" role="status">
          Sensitive fields acknowledged for export.
        </p>
      ) : null}

      <p className="export-privacy-summary__footnote muted">
        Seeds, private keys, and raw witness secrets are never included in exported artifacts.
      </p>
    </div>
  )
}

export default ExportPrivacySummary
