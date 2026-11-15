import { useMemo, useState } from 'react'
import {
  computeExportContextFingerprint,
  freezeReviewedVerificationExport,
  serializeReviewedVerificationExport,
  type FrozenReviewedVerificationExport,
  type VerificationExportPreviewInput,
} from '../services/verificationFlow'

type Props = {
  input: VerificationExportPreviewInput
  disabled?: boolean
  onExportJson?: (serializedJson: string, snapshot: FrozenReviewedVerificationExport) => void
}

export function VerificationExportPreview({ input, disabled = false, onExportJson }: Props) {
  const [frozenPreview, setFrozenPreview] =
    useState<FrozenReviewedVerificationExport | null>(null)
  const [exportedPayload, setExportedPayload] = useState<string | null>(null)

  const liveFingerprint = useMemo(
    () => computeExportContextFingerprint(input),
    [input],
  )

  const canPrepare = Boolean(input.statementHash.trim()) && !disabled
  const liveContextDiverged =
    frozenPreview !== null && frozenPreview.snapshotFingerprint !== liveFingerprint

  const handlePrepare = () => {
    const snapshot = freezeReviewedVerificationExport(input)
    setFrozenPreview(snapshot)
    setExportedPayload(null)
  }

  const handleExportReviewed = () => {
    if (!frozenPreview) return
    const serialized = serializeReviewedVerificationExport(frozenPreview)
    setExportedPayload(serialized)
    onExportJson?.(serialized, frozenPreview)
  }

  return (
    <section
      className="export-preview-panel"
      aria-labelledby="verification-export-preview-heading"
    >
      <h3 id="verification-export-preview-heading">Verification export preview</h3>
      <p className="muted" style={{ fontSize: 12 }}>
        Review included fields, observation freshness, and any unresolved checks before exporting a frozen verification snapshot.
      </p>

      {!frozenPreview ? (
        <div style={{ marginTop: 8 }}>
          <button
            type="button"
            className="hero-secondary"
            disabled={!canPrepare}
            onClick={handlePrepare}
          >
            Prepare export preview
          </button>
        </div>
      ) : (
        <div className="export-preview-card" style={{ marginTop: 10 }}>
          {liveContextDiverged ? (
            <div role="status" aria-live="polite" style={{ marginBottom: 8 }}>
              <p style={{ fontSize: 12 }}>
                Live portal state changed after this preview was captured. Exporting uses the exact reviewed snapshot without silently refreshing trust context.
              </p>
            </div>
          ) : null}

          <div style={{ marginBottom: 10 }}>
            <h4 style={{ fontSize: 13 }}>Freshness</h4>
            <p data-testid="export-preview-freshness" style={{ fontSize: 12 }}>
              <strong>{frozenPreview.freshness.state}</strong>: {frozenPreview.freshness.label}
            </p>
          </div>

          <div style={{ marginBottom: 10 }}>
            <h4 style={{ fontSize: 13 }}>
              Included fields ({frozenPreview.includedFields.length})
            </h4>
            <dl className="data-list" aria-label="Included export fields">
              {frozenPreview.includedFields.map((field) => (
                <div key={field.key}>
                  <dt>{field.label} ({field.key})</dt>
                  <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all' }}>
                    {field.value}
                  </dd>
                </div>
              ))}
            </dl>
          </div>

          <div style={{ marginBottom: 10 }}>
            <h4 style={{ fontSize: 13 }}>
              Unresolved checks ({frozenPreview.unresolvedChecks.length})
            </h4>
            {frozenPreview.unresolvedChecks.length === 0 ? (
              <p style={{ fontSize: 12 }}>
                None — all required online verification checks resolved.
              </p>
            ) : (
              <ul aria-label="Unresolved verification checks" style={{ fontSize: 12 }}>
                {frozenPreview.unresolvedChecks.map((check) => (
                  <li key={check.id}>
                    <strong>{check.label}:</strong> {check.reason}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div role="group" aria-label="Export preview actions">
            <div style={{ marginBottom: 6 }}>
              <button
                type="button"
                className="hero-secondary"
                onClick={handleExportReviewed}
              >
                Export reviewed result JSON
              </button>
            </div>
            {liveContextDiverged ? (
              <div style={{ marginBottom: 6 }}>
                <button
                  type="button"
                  className="hero-secondary"
                  onClick={handlePrepare}
                >
                  Update preview from current result
                </button>
              </div>
            ) : null}
            <div>
              <button
                type="button"
                className="hero-secondary"
                onClick={() => {
                  setFrozenPreview(null)
                  setExportedPayload(null)
                }}
              >
                Close export preview
              </button>
            </div>
          </div>

          {exportedPayload ? (
            <div role="status" aria-live="polite" style={{ marginTop: 10 }}>
              <p style={{ fontSize: 12 }}>
                Exported exact reviewed snapshot ({frozenPreview.reviewedAtIso}).
              </p>
              <pre
                data-testid="exported-verification-json"
                style={{ fontSize: 11, overflowX: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
              >
                {exportedPayload}
              </pre>
            </div>
          ) : null}
        </div>
      )}
    </section>
  )
}
