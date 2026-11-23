import { useMemo, useState } from 'react'
import { AlertTriangle, ArrowLeftRight, CheckCircle2, Link2, Trash2, Upload } from 'lucide-react'
import type { VerificationReceiptPayload } from '../verificationReceipt'
import {
  compareVerificationReceipts,
  createReceiptComparisonShareUrl,
  MAX_RECEIPT_INPUT_BYTES,
  parseReceiptInput,
  type ComparedObservation,
  type ObservationCategory,
} from '../services/receiptComparison'

type Props = {
  initialLeft?: VerificationReceiptPayload | null
  initialRight?: VerificationReceiptPayload | null
  baseUrl?: string
}

const CATEGORY_LABELS: Record<ObservationCategory, string> = {
  trust: 'Trust Observations',
  chain: 'Chain Observations',
  artifact: 'Artifact Identifiers',
}

const CATEGORY_ORDER: ObservationCategory[] = ['trust', 'chain', 'artifact']

function formatCellValue(obs: ComparedObservation, side: 'left' | 'right'): string {
  const value = side === 'left' ? obs.leftValue : obs.rightValue
  if (
    (obs.key === 'videoHash' ||
      obs.key === 'proofId' ||
      obs.key === 'metadataHash' ||
      obs.key === 'transactionHash') &&
    value.length === 64
  ) {
    return `${value.slice(0, 12)}…${value.slice(-8)}`
  }
  return value
}

export function ReceiptComparisonView({
  initialLeft = null,
  initialRight = null,
  baseUrl,
}: Props) {
  const [leftText, setLeftText] = useState(() =>
    initialLeft ? JSON.stringify(initialLeft, null, 2) : '',
  )
  const [rightText, setRightText] = useState(() =>
    initialRight ? JSON.stringify(initialRight, null, 2) : '',
  )
  const [leftReceipt, setLeftReceipt] = useState<VerificationReceiptPayload | null>(initialLeft)
  const [rightReceipt, setRightReceipt] = useState<VerificationReceiptPayload | null>(initialRight)
  const [leftError, setLeftError] = useState<string | null>(null)
  const [rightError, setRightError] = useState<string | null>(null)
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'error'>('idle')

  const handleTextChange = (side: 'left' | 'right', value: string) => {
    setCopyState('idle')
    if (side === 'left') {
      setLeftText(value)
    } else {
      setRightText(value)
    }

    if (!value.trim()) {
      if (side === 'left') {
        setLeftReceipt(null)
        setLeftError(null)
      } else {
        setRightReceipt(null)
        setRightError(null)
      }
      return
    }

    const parsed = parseReceiptInput(value)
    if (parsed.ok) {
      if (side === 'left') {
        setLeftReceipt(parsed.receipt)
        setLeftError(null)
      } else {
        setRightReceipt(parsed.receipt)
        setRightError(null)
      }
    } else {
      if (side === 'left') {
        setLeftReceipt(null)
        setLeftError(parsed.message)
      } else {
        setRightReceipt(null)
        setRightError(parsed.message)
      }
    }
  }

  const handleFileUpload = async (side: 'left' | 'right', file: File | null) => {
    if (!file) return
    if (file.size > MAX_RECEIPT_INPUT_BYTES) {
      const msg = `Receipt file exceeds the 8 KB size limit (${(file.size / 1024).toFixed(1)} KB).`
      if (side === 'left') {
        setLeftReceipt(null)
        setLeftError(msg)
      } else {
        setRightReceipt(null)
        setRightError(msg)
      }
      return
    }
    const text = await file.text()
    handleTextChange(side, text)
  }

  const handleSwap = () => {
    setCopyState('idle')
    setLeftText(rightText)
    setRightText(leftText)
    setLeftReceipt(rightReceipt)
    setRightReceipt(leftReceipt)
    setLeftError(rightError)
    setRightError(leftError)
  }

  const handleClear = () => {
    setCopyState('idle')
    setLeftText('')
    setRightText('')
    setLeftReceipt(null)
    setRightReceipt(null)
    setLeftError(null)
    setRightError(null)
  }

  const comparison = useMemo(() => {
    if (!leftReceipt || !rightReceipt) return null
    return compareVerificationReceipts(leftReceipt, rightReceipt)
  }, [leftReceipt, rightReceipt])

  const shareLink = useMemo(() => {
    if (!leftReceipt || !rightReceipt) return null
    return createReceiptComparisonShareUrl(
      leftReceipt,
      rightReceipt,
      baseUrl ? { baseUrl } : undefined,
    )
  }, [leftReceipt, rightReceipt, baseUrl])

  const handleCopyLink = async () => {
    if (!shareLink || !shareLink.ok) return
    try {
      await navigator.clipboard.writeText(shareLink.url)
      setCopyState('copied')
    } catch {
      setCopyState('error')
    }
  }

  return (
    <section
      className="receipt-comparison"
      aria-labelledby="receipt-comparison-heading"
      style={{
        marginTop: '1.25rem',
        padding: '1rem',
        border: '1px solid var(--border, #2a2f3a)',
        borderRadius: 10,
      }}
    >
      <header
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.75rem',
          flexWrap: 'wrap',
          marginBottom: '0.75rem',
        }}
      >
        <div>
          <h3 id="receipt-comparison-heading" style={{ margin: 0 }}>
            Compare Verification Receipts
          </h3>
          <p className="muted" style={{ margin: '0.25rem 0 0', fontSize: 12 }}>
            Inspect trust and on-chain observation changes between two verification receipts with exact UTC timestamps.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="hero-secondary"
            onClick={handleSwap}
            disabled={!leftText && !rightText}
            aria-label="Swap receipts"
          >
            <ArrowLeftRight size={14} aria-hidden="true" />
            <span>Swap</span>
          </button>
          <button
            type="button"
            className="hero-secondary"
            onClick={handleClear}
            disabled={!leftText && !rightText && !leftError && !rightError}
            aria-label="Clear receipt comparison"
          >
            <Trash2 size={14} aria-hidden="true" />
            <span>Clear</span>
          </button>
        </div>
      </header>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '0.75rem',
          marginBottom: '1rem',
        }}
      >
        {/* Receipt A */}
        <div className="form-group">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <label htmlFor="receipt-a-input">Receipt A (Baseline)</label>
            <label
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                fontSize: 11,
                cursor: 'pointer',
              }}
            >
              <Upload size={12} aria-hidden="true" />
              <span>Load JSON</span>
              <input
                type="file"
                accept=".json,application/json"
                aria-label="Upload Receipt A JSON"
                style={{ display: 'none' }}
                onChange={(e) => {
                  const file = e.target.files?.[0] ?? null
                  void handleFileUpload('left', file)
                  e.target.value = ''
                }}
              />
            </label>
          </div>
          <textarea
            id="receipt-a-input"
            rows={5}
            value={leftText}
            onChange={(e) => handleTextChange('left', e.target.value)}
            placeholder="Paste verification receipt JSON or QR payload…"
            aria-label="Receipt A JSON or QR payload"
            style={{ width: '100%', fontFamily: 'monospace', fontSize: 11 }}
          />
          {leftError ? (
            <p role="alert" className="verify-error" style={{ fontSize: 11, marginTop: 4 }}>
              {leftError}
            </p>
          ) : null}
        </div>

        {/* Receipt B */}
        <div className="form-group">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <label htmlFor="receipt-b-input">Receipt B (Comparison)</label>
            <label
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                fontSize: 11,
                cursor: 'pointer',
              }}
            >
              <Upload size={12} aria-hidden="true" />
              <span>Load JSON</span>
              <input
                type="file"
                accept=".json,application/json"
                aria-label="Upload Receipt B JSON"
                style={{ display: 'none' }}
                onChange={(e) => {
                  const file = e.target.files?.[0] ?? null
                  void handleFileUpload('right', file)
                  e.target.value = ''
                }}
              />
            </label>
          </div>
          <textarea
            id="receipt-b-input"
            rows={5}
            value={rightText}
            onChange={(e) => handleTextChange('right', e.target.value)}
            placeholder="Paste verification receipt JSON or QR payload…"
            aria-label="Receipt B JSON or QR payload"
            style={{ width: '100%', fontFamily: 'monospace', fontSize: 11 }}
          />
          {rightError ? (
            <p role="alert" className="verify-error" style={{ fontSize: 11, marginTop: 4 }}>
              {rightError}
            </p>
          ) : null}
        </div>
      </div>

      {comparison ? (
        <div className="receipt-comparison-results">
          {/* Timestamp summary */}
          <div
            className="receipt-comparison-timestamps"
            role="status"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '0.5rem',
              padding: '0.75rem',
              borderRadius: 8,
              background: 'rgba(255, 255, 255, 0.03)',
              marginBottom: '0.75rem',
              fontSize: 12,
            }}
          >
            <div>
              <span className="muted" style={{ display: 'block', fontSize: 11 }}>
                Receipt A Timestamp (UTC)
              </span>
              <time dateTime={comparison.leftTimestamp} data-testid="receipt-a-timestamp">
                {comparison.leftTimestamp}
              </time>
            </div>
            <div>
              <span className="muted" style={{ display: 'block', fontSize: 11 }}>
                Receipt B Timestamp (UTC)
              </span>
              <time dateTime={comparison.rightTimestamp} data-testid="receipt-b-timestamp">
                {comparison.rightTimestamp}
              </time>
            </div>
            <div>
              <span className="muted" style={{ display: 'block', fontSize: 11 }}>
                Elapsed Time Delta
              </span>
              <strong data-testid="receipt-time-delta">{comparison.timeDeltaLabel}</strong>
            </div>
          </div>

          {/* High-level change summary */}
          <div
            role={comparison.trustChanged || !comparison.sameArtifact ? 'alert' : 'status'}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.65rem 0.75rem',
              borderRadius: 8,
              marginBottom: '0.75rem',
              fontSize: 12,
              border: '1px solid var(--border, #2a2f3a)',
            }}
          >
            {comparison.trustChanged || comparison.chainChanged || !comparison.sameArtifact ? (
              <AlertTriangle size={15} aria-hidden="true" />
            ) : (
              <CheckCircle2 size={15} aria-hidden="true" />
            )}
            <span>
              {!comparison.sameArtifact
                ? 'Different artifacts: Receipt A and Receipt B reference different video hashes.'
                : comparison.changedCount === 0
                  ? 'No trust or chain observation changes detected between these receipts.'
                  : `${comparison.changedCount} observation${comparison.changedCount === 1 ? '' : 's'} changed (${[
                      comparison.trustChanged ? 'trust changed' : null,
                      comparison.chainChanged ? 'chain changed' : null,
                      comparison.artifactChanged ? 'artifact metadata changed' : null,
                    ]
                      .filter(Boolean)
                      .join(', ')}).`}
            </span>
          </div>

          {/* Grouped comparison tables */}
          {CATEGORY_ORDER.map((category) => {
            const rows = comparison.observations.filter((obs) => obs.category === category)
            const categoryChanged = rows.some((r) => r.changed)
            return (
              <div key={category} style={{ marginBottom: '0.9rem' }}>
                <h4
                  style={{
                    margin: '0 0 0.4rem',
                    fontSize: 12,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                  }}
                >
                  <span>{CATEGORY_LABELS[category]}</span>
                  {categoryChanged ? (
                    <span
                      data-testid={`category-changed-${category}`}
                      style={{
                        fontSize: 10,
                        padding: '1px 6px',
                        borderRadius: 999,
                        border: '1px solid currentColor',
                      }}
                    >
                      Changed
                    </span>
                  ) : null}
                </h4>
                <table
                  style={{
                    width: '100%',
                    borderCollapse: 'collapse',
                    fontSize: 12,
                  }}
                >
                  <thead>
                    <tr>
                      <th style={{ textAlign: 'left', padding: '4px 6px' }}>Observation</th>
                      <th style={{ textAlign: 'left', padding: '4px 6px' }}>Receipt A</th>
                      <th style={{ textAlign: 'left', padding: '4px 6px' }}>Receipt B</th>
                      <th style={{ textAlign: 'left', padding: '4px 6px' }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((obs) => (
                      <tr
                        key={obs.key}
                        data-changed={obs.changed ? 'true' : 'false'}
                        data-severity={obs.severity}
                        style={{
                          borderTop: '1px solid var(--border, #2a2f3a)',
                          background: obs.changed ? 'rgba(245, 158, 11, 0.08)' : 'transparent',
                        }}
                      >
                        <td style={{ padding: '6px' }}>
                          <strong>{obs.label}</strong>
                          {obs.detail ? (
                            <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>
                              {obs.detail}
                            </div>
                          ) : null}
                        </td>
                        <td
                          style={{
                            padding: '6px',
                            fontFamily: 'monospace',
                            overflowWrap: 'anywhere',
                          }}
                          title={obs.leftValue}
                        >
                          {formatCellValue(obs, 'left')}
                        </td>
                        <td
                          style={{
                            padding: '6px',
                            fontFamily: 'monospace',
                            overflowWrap: 'anywhere',
                          }}
                          title={obs.rightValue}
                        >
                          {formatCellValue(obs, 'right')}
                        </td>
                        <td style={{ padding: '6px' }}>
                          {obs.changed ? 'Changed' : 'Unchanged'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          })}

          {/* Privacy-safe comparison share link */}
          <div style={{ marginTop: '0.75rem' }}>
            <button
              type="button"
              className="hero-secondary"
              disabled={!shareLink || !shareLink.ok}
              onClick={() => void handleCopyLink()}
              aria-label="Copy comparison link"
            >
              <Link2 size={14} aria-hidden="true" />
              <span>Copy comparison link</span>
            </button>
            <p className="muted" role="status" aria-live="polite" style={{ fontSize: 11, marginTop: 6 }}>
              {copyState === 'copied'
                ? 'Comparison link copied. It contains only public receipt digests and timestamps — never private evidence metadata.'
                : copyState === 'error'
                  ? 'Unable to copy the comparison link.'
                  : 'Shared comparison URLs include only public hashes, timestamps, and chain identifiers — never private evidence metadata.'}
            </p>
          </div>
        </div>
      ) : (
        <p className="muted" style={{ fontSize: 12, margin: 0 }}>
          Provide two valid verification receipts above to compare trust and chain observations.
        </p>
      )}
    </section>
  )
}

export default ReceiptComparisonView
