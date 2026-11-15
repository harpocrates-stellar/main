import { useMemo } from 'react'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import type { VerificationErrorCode, VerificationStatus } from '../hooks/useVerification'
import {
  analyzeTimelineObservations,
  type TimelineLedgerBounds,
  type TimelineProvenanceDiscrepancy,
  type TimelineStageId,
} from '../services/verificationFlow'

type TimelineState = 'pending' | 'active' | 'complete' | 'failed'

type TimelineStep = {
  id: TimelineStageId
  label: string
  detail: string
  state: TimelineState
}

type Props = {
  status: VerificationStatus
  verifyHash: string
  events: ProofEvent[]
  chainProof: ChainProofRecord | null
  errorCode: VerificationErrorCode | null
  offline?: boolean
  ledgerBounds?: TimelineLedgerBounds | null
  observedAtIso?: string | null
  isStaleObservation?: boolean
  maxObservationAgeMs?: number
  nowMs?: number
  provenanceMismatches?: readonly TimelineProvenanceDiscrepancy[]
}

function markerLabel(state: TimelineState): string {
  if (state === 'complete') return 'Complete'
  if (state === 'active') return 'In progress'
  if (state === 'failed') return 'Not confirmed'
  return 'Pending'
}

export function VerificationTimeline({
  status,
  verifyHash,
  events,
  chainProof,
  errorCode,
  offline = false,
  ledgerBounds = null,
  observedAtIso = null,
  isStaleObservation = false,
  maxObservationAgeMs,
  nowMs,
  provenanceMismatches,
}: Props) {
  const hasRun = status !== 'idle' || Boolean(verifyHash) || events.length > 0 || Boolean(chainProof)
  const isBusy = status === 'validating' || status === 'hashing' || status === 'verifying'
  const failed = status === 'error' || status === 'cancelled'
  const chainFailed = failed && (errorCode === 'REVOKED_EVIDENCE' || errorCode === 'EXPIRED_EVIDENCE')
  const decisionComplete = status === 'success'

  const observationAnalysis = useMemo(
    () =>
      analyzeTimelineObservations({
        status,
        verifyHash,
        events,
        chainProof,
        errorCode,
        offline,
        ledgerBounds,
        observedAtIso,
        isStaleObservation,
        maxObservationAgeMs,
        nowMs,
        provenanceMismatches,
      }),
    [
      status,
      verifyHash,
      events,
      chainProof,
      errorCode,
      offline,
      ledgerBounds,
      observedAtIso,
      isStaleObservation,
      maxObservationAgeMs,
      nowMs,
      provenanceMismatches,
    ],
  )

  const steps: TimelineStep[] = [
    {
      id: 'input',
      label: 'Evidence received',
      detail: hasRun ? 'Synthetic metadata and local evidence checks are scoped to this run.' : 'Choose an evidence file to begin.',
      state: hasRun ? 'complete' : 'pending',
    },
    {
      id: 'hash',
      label: 'Evidence fingerprinted',
      detail: verifyHash ? 'A local fingerprint is available for the lookup boundary.' : 'The fingerprint is created locally and is never displayed as raw evidence.',
      state: verifyHash ? 'complete' : status === 'hashing' ? 'active' : 'pending',
    },
    {
      id: 'database',
      label: 'Database corroboration',
      detail: events.length > 0 ? `${events.length} matching record${events.length === 1 ? '' : 's'} returned.` : 'No database confirmation has been received.',
      state: events.length > 0 ? 'complete' : status === 'verifying' ? 'active' : failed ? 'failed' : 'pending',
    },
    {
      id: 'chain',
      label: 'Chain record',
      detail: chainProof ? (chainFailed ? 'The chain record is not trusted for this run.' : 'A chain record was returned for this fingerprint.') : 'No chain record has been confirmed.',
      state: chainProof ? (chainFailed ? 'failed' : 'complete') : status === 'verifying' ? 'active' : failed ? 'failed' : 'pending',
    },
    {
      id: 'decision',
      label: 'Verification decision',
      detail: decisionComplete ? 'All available evidence sources corroborated this artifact.' : failed ? 'No trust decision was made.' : 'Waiting for all available evidence sources.',
      state: decisionComplete ? 'complete' : failed ? 'failed' : isBusy ? 'active' : 'pending',
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
      <ol className="verification-timeline__list">
        {steps.map((step) => {
          const annotation = observationAnalysis.stageAnnotations[step.id]
          return (
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
                <p
                  className="muted verification-timeline__meta"
                  data-testid={`timeline-meta-${step.id}`}
                  style={{ fontSize: 11, marginTop: 2 }}
                >
                  Source: {annotation.observationSource} · Bounds: {annotation.ledgerBoundsLabel}
                </p>
              </div>
            </li>
          )
        })}
      </ol>

      {hasRun ? (
        <div className="verification-timeline__diagnostics" style={{ marginTop: 10 }}>
          <div
            data-testid="timeline-freshness-status"
            data-freshness-state={observationAnalysis.freshness.state}
            role="status"
            style={{ fontSize: 12 }}
          >
            <strong>Observation freshness ({observationAnalysis.freshness.state}):</strong>{' '}
            {observationAnalysis.freshness.summary}
          </div>

          {observationAnalysis.hasContradiction ? (
            <div
              data-testid="timeline-source-disagreements"
              role="status"
              aria-live="polite"
              style={{ marginTop: 8, fontSize: 12 }}
            >
              <strong>
                Source disagreements ({observationAnalysis.disagreements.length}):
              </strong>
              <ul aria-label="Source disagreements" style={{ marginTop: 4 }}>
                {observationAnalysis.disagreements.map((item) => (
                  <li key={item.id}>
                    [{item.sources[0]} vs {item.sources[1]}] {item.summary}
                  </li>
                ))}
              </ul>
            </div>
          ) : observationAnalysis.freshness.state === 'stale' ? (
            <p
              data-testid="timeline-no-contradiction-note"
              style={{ marginTop: 6, fontSize: 12 }}
            >
              Source agreement: No contradictory observations detected across sources (observation is aged, not conflicting).
            </p>
          ) : null}
        </div>
      ) : null}
    </section>
  )
}

export default VerificationTimeline
