import type { CSSProperties } from 'react'
import type {
  StructuredVerificationResultModel,
  StructuredVerificationVerdict,
  TrustDimensionStatus,
} from '../services/verificationFlow'

type Props = {
  model: StructuredVerificationResultModel
}

function verdictLabel(verdict: StructuredVerificationVerdict): string {
  switch (verdict) {
    case 'verified':
      return 'Verified'
    case 'rejected':
      return 'Rejected'
    case 'unconfirmed':
      return 'Unconfirmed'
    case 'pending':
      return 'Pending'
  }
}

function verdictBannerStyle(verdict: StructuredVerificationVerdict): CSSProperties {
  switch (verdict) {
    case 'verified':
      return {
        backgroundColor: '#063322',
        border: '1px solid #1f7a4c',
        color: '#ecfdf5',
      }
    case 'rejected':
      return {
        backgroundColor: '#3b0d15',
        border: '1px solid #dc2626',
        color: '#fef2f2',
      }
    case 'unconfirmed':
      return {
        backgroundColor: '#332206',
        border: '1px solid #d97706',
        color: '#fffbeb',
      }
    case 'pending':
      return {
        backgroundColor: '#111827',
        border: '1px solid #374151',
        color: '#f3f4f6',
      }
  }
}

function dimensionBadgeLabel(status: TrustDimensionStatus): string {
  switch (status) {
    case 'verified':
      return 'Verified'
    case 'failed':
      return 'Failed'
    case 'unverified':
      return 'Unverified'
    case 'not-applicable':
      return 'Not applicable'
  }
}

function dimensionBadgeStyle(status: TrustDimensionStatus): CSSProperties {
  switch (status) {
    case 'verified':
      return {
        backgroundColor: '#064e3b',
        border: '1px solid #10b981',
        color: '#ecfdf5',
      }
    case 'failed':
      return {
        backgroundColor: '#7f1d1d',
        border: '1px solid #f87171',
        color: '#fef2f2',
      }
    case 'unverified':
      return {
        backgroundColor: '#78350f',
        border: '1px solid #fbbf24',
        color: '#fffbeb',
      }
    case 'not-applicable':
      return {
        backgroundColor: '#1f2937',
        border: '1px solid #6b7280',
        color: '#f3f4f6',
      }
  }
}

export function StructuredTrustDimensionsPanel({ model }: Props) {
  return (
    <section
      className="structured-trust-dimensions"
      aria-labelledby="structured-trust-dimensions-heading"
      data-testid="structured-trust-dimensions-panel"
      style={{
        backgroundColor: '#0d1320',
        border: '1px solid #263248',
        borderRadius: 10,
        padding: '12px 14px',
        marginTop: 12,
        marginBottom: 12,
        color: '#f1f5f9',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          gap: 8,
          flexWrap: 'wrap',
          marginBottom: 8,
        }}
      >
        <h3
          id="structured-trust-dimensions-heading"
          style={{ margin: 0, fontSize: '0.95rem', color: '#f8fafc' }}
        >
          Independent Trust Dimensions
        </h3>
        <span style={{ fontSize: 11, color: '#cbd5e1' }}>
          Non-masking evaluation across 4 orthogonal checks
        </span>
      </div>

      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        data-testid="structured-overall-verdict"
        data-verdict={model.overallVerdict}
        style={{
          ...verdictBannerStyle(model.overallVerdict),
          borderRadius: 8,
          padding: '8px 10px',
          marginBottom: 10,
          fontSize: 12,
          lineHeight: 1.45,
        }}
      >
        <strong style={{ marginRight: 6 }}>
          Overall verdict: {verdictLabel(model.overallVerdict)}
        </strong>
        <span>{model.overallSummary}</span>
      </div>

      <ul
        aria-label="Independent trust dimensions breakdown"
        style={{
          listStyle: 'none',
          margin: 0,
          padding: 0,
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
          gap: 8,
        }}
      >
        {model.dimensionList.map((dimension) => (
          <li
            key={dimension.id}
            data-testid={`trust-dimension-${dimension.id}`}
            data-dimension-status={dimension.status}
            data-reason-code={dimension.reasonCode}
            style={{
              backgroundColor: '#111827',
              border:
                dimension.status === 'failed'
                  ? '1px solid #ef4444'
                  : '1px solid #293548',
              borderRadius: 8,
              padding: '8px 10px',
              color: '#f1f5f9',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 6,
                marginBottom: 4,
              }}
            >
              <h4
                style={{
                  margin: 0,
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  color: '#f8fafc',
                }}
              >
                {dimension.label}
              </h4>
              <span
                data-testid={`trust-dimension-badge-${dimension.id}`}
                style={{
                  ...dimensionBadgeStyle(dimension.status),
                  borderRadius: 999,
                  padding: '2px 8px',
                  fontSize: 11,
                  fontWeight: 600,
                  whiteSpace: 'nowrap',
                }}
              >
                {dimensionBadgeLabel(dimension.status)}
              </span>
            </div>
            <p
              style={{
                margin: '4px 0',
                fontSize: 11,
                lineHeight: 1.4,
                color: '#e2e8f0',
                overflowWrap: 'anywhere',
              }}
            >
              {dimension.summary}
            </p>
            <p
              style={{
                margin: 0,
                fontSize: 10,
                color: '#cbd5e1',
              }}
            >
              Code:{' '}
              <code style={{ color: '#f8fafc', fontSize: 10 }}>
                {dimension.reasonCode}
              </code>
            </p>
          </li>
        ))}
      </ul>
    </section>
  )
}
