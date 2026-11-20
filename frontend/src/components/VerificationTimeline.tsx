import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import type { VerificationErrorCode, VerificationStatus } from '../hooks/useVerification'
import {
  evaluateVerificationObservations,
  formatLedgerBounds,
  type SourceAgreement,
} from '../services/verificationFlow'

type TimelineState = 'pending' | 'active' | 'complete' | 'failed'

type TimelineStep = {
  id: string
  label: string
  detail: string
  state: TimelineState
  sourceLabel: string
  ledgerBoundsLabel?: string
}

type Props = {
  status: VerificationStatus
  verifyHash: string
  events: ProofEvent[]
  chainProof: ChainProofRecord | null
  errorCode: VerificationErrorCode | null
  offline?: boolean
  nowMs?: number
}

function markerLabel(state: TimelineState): string {
  if (state === 'complete') return 'Complete'
  if (state === 'active') return 'In progress'
  if (state === 'failed') return 'Not confirmed'
  return 'Pending'
}

function agreementBadgeLabel(agreement: SourceAgreement): string {
  switch (agreement) {
    case 'contradictory':
      return 'Source disagreement'
    case 'stale':
      return 'Stale evidence'
    case 'aligned':
      return 'Sources aligned'
    default:
      return 'Partial observations'
  }
}

export function VerificationTimeline({
  status,
  verifyHash,
  events,
  chainProof,
  errorCode,
  offline = false,
  nowMs,
}: Props) {
  const hasRun = status !== 'idle' || Boolean(verifyHash) || events.length > 0 || Boolean(chainProof)
  const isBusy = status === 'validating' || status === 'hashing' || status === 'verifying'
  const failed = status === 'error' || status === 'cancelled'
  const chainFailed = failed && (errorCode === 'REVOKED_EVIDENCE' || errorCode === 'EXPIRED_EVIDENCE')
  const decisionComplete = status === 'success'

  const observations = evaluateVerificationObservations({
    events,
    chainProof,
    errorCode,
    offline,
    nowMs,
  })

  const backendBoundsLabel = formatLedgerBounds(observations.sources.backend.ledgerBounds)
  const sorobanBoundsLabel = formatLedgerBounds(observations.sources.soroban.ledgerBounds)
  const combinedBoundsLabel = formatLedgerBounds(observations.ledgerBounds)

  const steps: TimelineStep[] = [
    {
      id: 'input',
      label: 'Evidence received',
      detail: hasRun ? 'Synthetic metadata and local evidence checks are scoped to this run.' : 'Choose an evidence file to begin.',
      state: hasRun ? 'complete' : 'pending',
      sourceLabel: 'Source: Local browser',
    },
    {
      id: 'hash',
      label: 'Evidence fingerprinted',
      detail: verifyHash ? 'A local fingerprint is available for the lookup boundary.' : 'The fingerprint is created locally and is never displayed as raw evidence.',
      state: verifyHash ? 'complete' : status === 'hashing' ? 'active' : 'pending',
      sourceLabel: 'Source: Local browser',
    },
    {
      id: 'database',
      label: 'Database corroboration',
      detail: events.length > 0 ? `${events.length} matching record${events.length === 1 ? '' : 's'} returned.` : 'No database confirmation has been received.',
      state: events.length > 0 ? 'complete' : status === 'verifying' ? 'active' : failed ? 'failed' : 'pending',
      sourceLabel: `Source: ${observations.sources.backend.label}`,
      ledgerBoundsLabel: events.length > 0 ? backendBoundsLabel : undefined,
    },
    {
      id: 'chain',
      label: 'Chain record',
      detail: chainProof ? (chainFailed ? 'The chain record is not trusted for this run.' : 'A chain record was returned for this fingerprint.') : 'No chain record has been confirmed.',
      state: chainProof ? (chainFailed ? 'failed' : 'complete') : status === 'verifying' ? 'active' : failed ? 'failed' : 'pending',
      sourceLabel: `Source: ${observations.sources.soroban.label}`,
      ledgerBoundsLabel: chainProof ? sorobanBoundsLabel : undefined,
    },
    {
      id: 'decision',
      label: 'Verification decision',
      detail: decisionComplete ? 'All available evidence sources corroborated this artifact.' : failed ? 'No trust decision was made.' : 'Waiting for all available evidence sources.',
      state: decisionComplete ? 'complete' : failed ? 'failed' : isBusy ? 'active' : 'pending',
      sourceLabel: offline ? 'Source: Local browser (offline)' : 'Source: Backend + Soroban',
      ledgerBoundsLabel: hasRun ? combinedBoundsLabel : undefined,
    },
  ]

  return (
    <section className="verification-timeline" aria-labelledby="verification-timeline-heading">
      <div className="verification-timeline__header">
        <div>
          <p className="eyebrow">Evidence path</p>
          <h3 id="verification-timeline-heading">Verification timeline</h3>
        </div>
        <span className="verification-timeline__privacy">No raw evidence</span>
      </div>
      {hasRun ? (
        <div
          className={`verification-timeline__observation verification-timeline__observation--${observations.agreement}`}
          data-observation-status={observations.agreement}
          data-observation-freshness={observations.freshness}
          role={observations.agreement === 'contradictory' ? 'alert' : 'status'}
        >
          <div className="verification-timeline__observation-header">
            <span className="verification-timeline__observation-badge">
              {agreementBadgeLabel(observations.agreement)}
            </span>
            <span className="verification-timeline__observation-bounds">
              {combinedBoundsLabel}
            </span>
          </div>
          <p className="verification-timeline__observation-summary">{observations.summary}</p>
        </div>
      ) : null}
      <ol className="verification-timeline__list">
        {steps.map((step) => (
          <li className={`verification-timeline__step verification-timeline__step--${step.state}`} key={step.id}>
            <span className="verification-timeline__marker" aria-hidden="true">
              {step.state === 'complete' ? '✓' : step.state === 'failed' ? '!' : step.state === 'active' ? '•' : '·'}
            </span>
            <div className="verification-timeline__content">
              <div className="verification-timeline__title-row">
                <strong>{step.label}</strong>
                <span>{markerLabel(step.state)}</span>
              </div>
              <p>{step.detail}</p>
              <div className="verification-timeline__meta">
                <span>{step.sourceLabel}</span>
                {step.ledgerBoundsLabel ? <span>{step.ledgerBoundsLabel}</span> : null}
              </div>
            </div>
          </li>
        ))}
      </ol>
    </section>
  )
}

export default VerificationTimeline
