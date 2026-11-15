import { useState } from 'react'
import {
  compareVerificationReceipts,
  createReceiptComparisonShareUrl,
  type ReceiptComparisonReport,
} from '../services/verificationFlow'

export function VerificationReceiptComparisonPanel() {
  const [baselineJson, setBaselineJson] = useState('')
  const [candidateJson, setCandidateJson] = useState('')
  const [comparisonError, setComparisonError] = useState<string | null>(null)
  const [report, setReport] = useState<ReceiptComparisonReport | null>(null)
  const [shareUrl, setShareUrl] = useState<string | null>(null)

  const handleCompare = () => {
    try {
      const nextReport = compareVerificationReceipts(baselineJson, candidateJson)
      const origin =
        typeof window !== 'undefined' && window.location?.origin
          ? `${window.location.origin}/`
          : 'https://harpocrates.local/'
      const nextUrl = createReceiptComparisonShareUrl(nextReport, origin)
      setComparisonError(null)
      setReport(nextReport)
      setShareUrl(nextUrl)
    } catch (err) {
      setReport(null)
      setShareUrl(null)
      setComparisonError(
        err instanceof Error ? err.message : 'Unable to compare verification receipts.',
      )
    }
  }

  const handleClear = () => {
    setBaselineJson('')
    setCandidateJson('')
    setComparisonError(null)
    setReport(null)
    setShareUrl(null)
  }

  return (
    <section
      className="receipt-comparison-panel"
      aria-labelledby="receipt-comparison-heading"
    >
      <h3 id="receipt-comparison-heading">Compare verification receipts</h3>
      <p className="muted" style={{ fontSize: 12 }}>
        Compare two signed or portable verification receipts to inspect changed trust and chain observations with exact timestamps.
      </p>

      <div className="form-group" style={{ marginTop: 8 }}>
        <label htmlFor="baseline-receipt-json">Baseline receipt JSON</label>
        <textarea
          id="baseline-receipt-json"
          rows={3}
          value={baselineJson}
          onChange={(e) => {
            setBaselineJson(e.target.value)
            setComparisonError(null)
          }}
          placeholder="Paste earlier verification receipt JSON"
        />
      </div>

      <div className="form-group" style={{ marginTop: 8 }}>
        <label htmlFor="candidate-receipt-json">Candidate receipt JSON</label>
        <textarea
          id="candidate-receipt-json"
          rows={3}
          value={candidateJson}
          onChange={(e) => {
            setCandidateJson(e.target.value)
            setComparisonError(null)
          }}
          placeholder="Paste newer verification receipt JSON"
        />
      </div>

      <div role="group" aria-label="Receipt comparison actions" style={{ marginTop: 8 }}>
        <div style={{ marginBottom: 6 }}>
          <button
            type="button"
            className="hero-secondary"
            disabled={!baselineJson.trim() || !candidateJson.trim()}
            onClick={handleCompare}
          >
            Compare receipts
          </button>
        </div>
        {baselineJson || candidateJson || report || comparisonError ? (
          <div>
            <button
              type="button"
              className="hero-secondary"
              onClick={handleClear}
            >
              Clear receipt comparison
            </button>
          </div>
        ) : null}
      </div>

      {comparisonError ? (
        <div role="alert" aria-live="assertive" style={{ marginTop: 8 }}>
          <p style={{ fontSize: 12 }}>{comparisonError}</p>
        </div>
      ) : null}

      {report ? (
        <div className="receipt-comparison-results" style={{ marginTop: 10 }}>
          <dl className="data-list" aria-label="Receipt comparison timestamps">
            <div>
              <dt>Baseline timestamp</dt>
              <dd data-testid="comparison-baseline-timestamp">
                {report.baselineVerifiedAt}
              </dd>
            </div>
            <div>
              <dt>Candidate timestamp</dt>
              <dd data-testid="comparison-candidate-timestamp">
                {report.candidateVerifiedAt}
              </dd>
            </div>
            <div>
              <dt>Statement match</dt>
              <dd>
                {report.sameStatement
                  ? 'Same statement identity'
                  : 'Different statement digests'}
              </dd>
            </div>
          </dl>

          {report.strippedPrivateFieldNames.length > 0 ? (
            <p role="status" style={{ fontSize: 12, marginTop: 8 }}>
              Stripped private metadata fields from comparison and share URL:{' '}
              {report.strippedPrivateFieldNames.join(', ')}
            </p>
          ) : null}

          <div style={{ marginTop: 10 }}>
            <h4 style={{ fontSize: 13 }}>
              Changed trust observations ({report.changedTrustObservations.length})
            </h4>
            {report.changedTrustObservations.length === 0 ? (
              <p style={{ fontSize: 12 }}>No trust standing changes between receipts.</p>
            ) : (
              <ul aria-label="Changed trust observations" style={{ fontSize: 12 }}>
                {report.changedTrustObservations.map((diff) => (
                  <li key={diff.key}>
                    <strong>{diff.label}:</strong> {diff.baselineValue} (
                    {report.baselineVerifiedAt}) → {diff.candidateValue} (
                    {report.candidateVerifiedAt})
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div style={{ marginTop: 10 }}>
            <h4 style={{ fontSize: 13 }}>
              Changed chain observations ({report.changedChainObservations.length})
            </h4>
            {report.changedChainObservations.length === 0 ? (
              <p style={{ fontSize: 12 }}>No chain observation changes between receipts.</p>
            ) : (
              <ul aria-label="Changed chain observations" style={{ fontSize: 12 }}>
                {report.changedChainObservations.map((diff) => (
                  <li key={diff.key}>
                    <strong>{diff.label}:</strong> {diff.baselineValue} (
                    {report.baselineVerifiedAt}) → {diff.candidateValue} (
                    {report.candidateVerifiedAt})
                  </li>
                ))}
              </ul>
            )}
          </div>

          {shareUrl ? (
            <div style={{ marginTop: 10 }}>
              <h4 style={{ fontSize: 13 }}>Sanitized comparison URL</h4>
              <p
                data-testid="receipt-comparison-share-url"
                style={{ fontSize: 11, overflowWrap: 'anywhere', wordBreak: 'break-all' }}
              >
                {shareUrl}
              </p>
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  )
}
