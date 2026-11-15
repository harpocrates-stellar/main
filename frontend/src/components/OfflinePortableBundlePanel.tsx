import { useState } from 'react'
import {
  MAX_PORTABLE_OFFLINE_BUNDLE_BYTES,
  inspectPortableOfflineBundle,
  type PortableOfflineBundleReport,
} from '../services/verificationFlow'

type Props = {
  disabled?: boolean
  onEnterOfflineMode?: () => void
}

export function OfflinePortableBundlePanel({
  disabled = false,
  onEnterOfflineMode,
}: Props) {
  const [bundleText, setBundleText] = useState('')
  const [report, setReport] = useState<PortableOfflineBundleReport | null>(null)

  const handleFileImport = async (file: File) => {
    onEnterOfflineMode?.()
    if (file.size > MAX_PORTABLE_OFFLINE_BUNDLE_BYTES) {
      // Enforce size ceiling before reading full text into JSON.parse
      const syntheticBytes = new Uint8Array(file.size)
      setReport(inspectPortableOfflineBundle(syntheticBytes))
      return
    }
    const raw = await file.text()
    setBundleText(raw)
    setReport(inspectPortableOfflineBundle(raw))
  }

  const handlePasteInspect = () => {
    onEnterOfflineMode?.()
    setReport(inspectPortableOfflineBundle(bundleText))
  }

  return (
    <section
      className="offline-portable-bundle-panel"
      aria-labelledby="offline-portable-bundle-heading"
    >
      <h3 id="offline-portable-bundle-heading">Offline portable bundle entry point</h3>
      <p className="muted" style={{ fontSize: 12 }}>
        Import a bounded portable verification bundle (up to 128 KB) for air-gapped local inspection. Skipped online revocation and registry checks are reported as unavailable and never marked as passed.
      </p>

      <div className="form-group" style={{ marginTop: 8 }}>
        <label htmlFor="offline-bundle-file-input">
          Import portable bundle file (.json, max 128 KB)
        </label>
        <input
          id="offline-bundle-file-input"
          type="file"
          accept=".json,application/json"
          disabled={disabled}
          onChange={(event) => {
            const file = event.target.files?.[0] ?? null
            if (file) void handleFileImport(file)
            event.target.value = ''
          }}
        />
      </div>

      <div className="form-group" style={{ marginTop: 8 }}>
        <label htmlFor="offline-bundle-json-input">Portable bundle JSON</label>
        <textarea
          id="offline-bundle-json-input"
          rows={3}
          disabled={disabled}
          value={bundleText}
          onChange={(e) => setBundleText(e.target.value)}
          placeholder="Paste portable verification bundle JSON for offline inspection"
        />
      </div>

      <div role="group" aria-label="Offline bundle actions" style={{ marginTop: 8 }}>
        <div style={{ marginBottom: 6 }}>
          <button
            type="button"
            className="hero-secondary"
            disabled={disabled || !bundleText.trim()}
            onClick={handlePasteInspect}
          >
            Inspect bundle offline
          </button>
        </div>
        {bundleText || report ? (
          <div>
            <button
              type="button"
              className="hero-secondary"
              disabled={disabled}
              onClick={() => {
                setBundleText('')
                setReport(null)
              }}
            >
              Clear offline bundle
            </button>
          </div>
        ) : null}
      </div>

      {report ? (
        <div
          className="offline-bundle-report"
          data-disposition={report.overallDisposition}
          style={{ marginTop: 10 }}
        >
          <div
            role={report.accepted ? 'status' : 'alert'}
            aria-live={report.accepted ? 'polite' : 'assertive'}
          >
            <p style={{ fontSize: 12 }}>
              <strong>Disposition ({report.overallDisposition}):</strong> {report.summary}
            </p>
            {report.errorCode ? (
              <p className="muted" style={{ fontSize: 11, marginTop: 4 }}>
                Bundle error code: {report.errorCode}
              </p>
            ) : null}
          </div>

          <div style={{ marginTop: 10 }}>
            <h4 style={{ fontSize: 13 }}>Local bundle checks</h4>
            <ul aria-label="Local bundle checks" style={{ fontSize: 12 }}>
              {report.localChecks.map((check) => (
                <li key={check.id} data-check-status={check.status}>
                  <strong>{check.label}</strong> [{check.status}]: {check.detail}
                </li>
              ))}
            </ul>
          </div>

          <div style={{ marginTop: 10 }}>
            <h4 style={{ fontSize: 13 }}>
              Unavailable live checks (skipped offline — never passed)
            </h4>
            <ul aria-label="Unavailable live checks" style={{ fontSize: 12 }}>
              {report.unavailableLiveChecks.map((check) => (
                <li
                  key={check.id}
                  data-testid={`offline-live-check-${check.id}`}
                  data-check-status={check.status}
                >
                  <strong>{check.label}</strong> [{check.status}]: {check.detail}
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
    </section>
  )
}
