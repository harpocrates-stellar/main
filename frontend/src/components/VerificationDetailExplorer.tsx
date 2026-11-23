import { useState, useId } from 'react'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import type {
  VerificationDetails,
  VerificationCheckStatus,
} from '../services/verificationFlow'
import { shortHash } from '../utils'

type Props = {
  details: VerificationDetails
  defaultExpanded?: boolean
  className?: string
}

function StatusIcon({ status }: { status?: VerificationCheckStatus }) {
  switch (status) {
    case 'passed':
      return <CheckCircle2 size={16} className="text-success" aria-hidden="true" />
    case 'failed':
      return <XCircle size={16} className="text-error" aria-hidden="true" />
    case 'warning':
      return <AlertTriangle size={16} className="text-warning" aria-hidden="true" />
    case 'info':
    default:
      return <Info size={16} className="text-info" aria-hidden="true" />
  }
}

function StatusBadge({ status }: { status?: VerificationCheckStatus }) {
  const label =
    status === 'passed'
      ? 'Passed'
      : status === 'failed'
        ? 'Failed'
        : status === 'warning'
          ? 'Warning'
          : 'Info'

  return (
    <span className={`detail-status-badge detail-status-badge--${status || 'info'}`}>
      <StatusIcon status={status} />
      <span>{label}</span>
    </span>
  )
}

export function VerificationDetailExplorer({
  details,
  defaultExpanded = true,
  className = '',
}: Props) {
  const baseId = useId()
  const publicInputsHeaderId = `${baseId}-public-inputs-header`
  const publicInputsPanelId = `${baseId}-public-inputs-panel`
  const chainObservationsHeaderId = `${baseId}-chain-obs-header`
  const chainObservationsPanelId = `${baseId}-chain-obs-panel`
  const trustReasonsHeaderId = `${baseId}-trust-reasons-header`
  const trustReasonsPanelId = `${baseId}-trust-reasons-panel`

  const [expandedSections, setExpandedSections] = useState({
    publicInputs: defaultExpanded,
    chainObservations: defaultExpanded,
    trustReasons: defaultExpanded,
  })

  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }))
  }

  const allExpanded =
    expandedSections.publicInputs &&
    expandedSections.chainObservations &&
    expandedSections.trustReasons

  const toggleAll = () => {
    const next = !allExpanded
    setExpandedSections({
      publicInputs: next,
      chainObservations: next,
      trustReasons: next,
    })
  }

  const publicChecks = details.publicInputChecks || []
  const chainObs = details.chainObservations || []
  const trustReasons = details.trustReasons || []

  const publicPassedCount = publicChecks.filter((c) => c.status === 'passed').length

  return (
    <section
      className={`verification-detail-explorer ${className}`}
      aria-labelledby={`${baseId}-explorer-title`}
    >
      <header className="detail-explorer-header">
        <div className="detail-explorer-title-group">
          <p className="eyebrow">Corroboration & Audit</p>
          <h3 id={`${baseId}-explorer-title`} className="detail-explorer-title">
            Verification Detail Explorer
          </h3>
          <p className="muted detail-explorer-subtitle">
            Expandable breakdown of public input validation, smart contract registry observations,
            and deterministic trust decisions.
          </p>
        </div>
        <button
          type="button"
          className="detail-explorer-toggle-all"
          onClick={toggleAll}
          aria-label={allExpanded ? 'Collapse all verification detail sections' : 'Expand all verification detail sections'}
        >
          {allExpanded ? 'Collapse All' : 'Expand All'}
        </button>
      </header>

      <div className="detail-explorer-sections">
        {/* Section 1: Public-Input Checks */}
        <div className="detail-section">
          <h4>
            <button
              type="button"
              id={publicInputsHeaderId}
              className="detail-section-toggle"
              aria-expanded={expandedSections.publicInputs}
              aria-controls={publicInputsPanelId}
              onClick={() => toggleSection('publicInputs')}
            >
              <span className="detail-section-toggle-left">
                <span className="detail-section-name">Public-Input Checks</span>
                <span className="detail-count-badge">
                  {publicPassedCount}/{publicChecks.length} passed
                </span>
              </span>
              <span className="detail-section-toggle-icon" aria-hidden="true">
                {expandedSections.publicInputs ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
              </span>
            </button>
          </h4>
          <div
            id={publicInputsPanelId}
            role="region"
            aria-labelledby={publicInputsHeaderId}
            hidden={!expandedSections.publicInputs}
            className="detail-section-panel"
          >
            {publicChecks.length === 0 ? (
              <p className="muted">No public-input checks available.</p>
            ) : (
              <ul className="detail-items-list" role="list">
                {publicChecks.map((check) => (
                  <li key={check.id} className={`detail-item detail-item--${check.status}`}>
                    <div className="detail-item-header">
                      <strong className="detail-item-name">{check.name}</strong>
                      <StatusBadge status={check.status} />
                    </div>
                    <p className="detail-item-summary">{check.summary}</p>
                    {check.detail ? <p className="detail-item-desc muted">{check.detail}</p> : null}
                    {check.value ? (
                      <div className="detail-item-value">
                        <span className="detail-value-label">Value:</span>
                        <code title={check.value}>{shortHash(check.value)}</code>
                      </div>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Section 2: Chain Observations */}
        <div className="detail-section">
          <h4>
            <button
              type="button"
              id={chainObservationsHeaderId}
              className="detail-section-toggle"
              aria-expanded={expandedSections.chainObservations}
              aria-controls={chainObservationsPanelId}
              onClick={() => toggleSection('chainObservations')}
            >
              <span className="detail-section-toggle-left">
                <span className="detail-section-name">Chain Observations</span>
                <span className="detail-count-badge">
                  {chainObs.length} observation{chainObs.length === 1 ? '' : 's'}
                </span>
              </span>
              <span className="detail-section-toggle-icon" aria-hidden="true">
                {expandedSections.chainObservations ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
              </span>
            </button>
          </h4>
          <div
            id={chainObservationsPanelId}
            role="region"
            aria-labelledby={chainObservationsHeaderId}
            hidden={!expandedSections.chainObservations}
            className="detail-section-panel"
          >
            {chainObs.length === 0 ? (
              <p className="muted">No chain observations recorded.</p>
            ) : (
              <dl className="detail-observations-grid">
                {chainObs.map((obs) => (
                  <div key={obs.id} className="detail-obs-row">
                    <dt className="detail-obs-label">{obs.label}</dt>
                    <dd className="detail-obs-value">
                      <div className="detail-obs-value-row">
                        <span className="detail-obs-text">{obs.value}</span>
                        {obs.status ? <StatusBadge status={obs.status} /> : null}
                      </div>
                      {obs.detail ? <p className="muted detail-obs-detail">{obs.detail}</p> : null}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        </div>

        {/* Section 3: Trust Reasons */}
        <div className="detail-section">
          <h4>
            <button
              type="button"
              id={trustReasonsHeaderId}
              className="detail-section-toggle"
              aria-expanded={expandedSections.trustReasons}
              aria-controls={trustReasonsPanelId}
              onClick={() => toggleSection('trustReasons')}
            >
              <span className="detail-section-toggle-left">
                <span className="detail-section-name">Trust Reasons</span>
                <span className="detail-count-badge">
                  {trustReasons.length} decision factor{trustReasons.length === 1 ? '' : 's'}
                </span>
              </span>
              <span className="detail-section-toggle-icon" aria-hidden="true">
                {expandedSections.trustReasons ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
              </span>
            </button>
          </h4>
          <div
            id={trustReasonsPanelId}
            role="region"
            aria-labelledby={trustReasonsHeaderId}
            hidden={!expandedSections.trustReasons}
            className="detail-section-panel"
          >
            {trustReasons.length === 0 ? (
              <p className="muted">No trust reasons provided.</p>
            ) : (
              <ul className="detail-items-list" role="list">
                {trustReasons.map((reason) => (
                  <li key={reason.id} className={`detail-item detail-item--${reason.status}`}>
                    <div className="detail-item-header">
                      <strong className="detail-item-name">{reason.title}</strong>
                      <StatusBadge status={reason.status} />
                    </div>
                    <p className="detail-item-summary">{reason.description}</p>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </section>
  )
}

export default VerificationDetailExplorer
