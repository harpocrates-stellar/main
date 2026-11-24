import { useRef, useState } from 'react'
import type { ChainProofRecord } from '../stellarTypes'
import {
  shouldResetDependentTabState,
  type ResolvedVerifiedStatementIdentity,
  type VerificationResultTabId,
} from '../services/verificationFlow'

type Props = {
  identity: ResolvedVerifiedStatementIdentity
  status: string
  offline: boolean
  chainProof: ChainProofRecord | null
}

const TAB_ORDER: readonly {
  readonly id: VerificationResultTabId
  readonly label: string
}[] = Object.freeze([
  Object.freeze({ id: 'summary', label: 'Summary' }),
  Object.freeze({ id: 'chain', label: 'Chain binding' }),
  Object.freeze({ id: 'corroboration', label: 'Event corroboration' }),
])

export function VerificationResultTabs({
  identity,
  status,
  offline,
  chainProof,
}: Props) {
  const [prevStatementKey, setPrevStatementKey] = useState(identity.statementKey)
  const [activeTab, setActiveTab] = useState<VerificationResultTabId>('summary')
  const [showFullCommitments, setShowFullCommitments] = useState(false)
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null)
  const tabRefs = useRef<Record<VerificationResultTabId, HTMLButtonElement | null>>({
    summary: null,
    chain: null,
    corroboration: null,
  })

  if (shouldResetDependentTabState(prevStatementKey, identity.statementKey)) {
    setPrevStatementKey(identity.statementKey)
    setActiveTab('summary')
    setShowFullCommitments(false)
    setSelectedEventId(null)
  }

  const digestLabel = identity.statementDigest || 'No verified statement'
  const proofLabel = identity.proofId ?? 'Unassigned'

  const moveTabByOffset = (offset: number) => {
    const currentIndex = TAB_ORDER.findIndex((tab) => tab.id === activeTab)
    const nextIndex = (currentIndex + offset + TAB_ORDER.length) % TAB_ORDER.length
    const nextTab = TAB_ORDER[nextIndex].id
    setActiveTab(nextTab)
    tabRefs.current[nextTab]?.focus()
  }

  const selectedEvent =
    identity.matchingEvents.find((event) => event.id === selectedEventId) ?? null

  return (
    <section
      className="verification-result-tabs"
      aria-labelledby="verification-result-tabs-heading"
    >
      <h3 id="verification-result-tabs-heading">Result perspectives</h3>

      <div
        role="tablist"
        aria-label="Verification result perspectives"
        style={{ marginTop: 8, marginBottom: 10 }}
      >
        {TAB_ORDER.map((tab) => {
          const isSelected = activeTab === tab.id
          return (
            <div key={tab.id} style={{ marginBottom: 6 }}>
              <button
                ref={(el) => {
                  tabRefs.current[tab.id] = el
                }}
                id={`verify-result-tab-${tab.id}`}
                type="button"
                role="tab"
                className={`hero-secondary ${isSelected ? 'active' : ''}`}
                aria-selected={isSelected}
                aria-controls={`verify-result-panel-${tab.id}`}
                tabIndex={isSelected ? 0 : -1}
                onClick={() => setActiveTab(tab.id)}
                onKeyDown={(event) => {
                  if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
                    event.preventDefault()
                    moveTabByOffset(1)
                  } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
                    event.preventDefault()
                    moveTabByOffset(-1)
                  } else if (event.key === 'Home') {
                    event.preventDefault()
                    setActiveTab(TAB_ORDER[0].id)
                    tabRefs.current[TAB_ORDER[0].id]?.focus()
                  } else if (event.key === 'End') {
                    event.preventDefault()
                    const last = TAB_ORDER[TAB_ORDER.length - 1].id
                    setActiveTab(last)
                    tabRefs.current[last]?.focus()
                  }
                }}
              >
                {tab.label}
              </button>
            </div>
          )
        })}
      </div>

      <div
        id={`verify-result-panel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`verify-result-tab-${activeTab}`}
        tabIndex={0}
      >
        <dl className="data-list" aria-label="Active statement identity">
          <div>
            <dt>Statement digest</dt>
            <dd
              data-testid="tab-statement-digest"
              style={{ overflowWrap: 'anywhere', wordBreak: 'break-all' }}
            >
              {digestLabel}
            </dd>
          </div>
          <div>
            <dt>Proof identity</dt>
            <dd
              data-testid="tab-proof-identity"
              style={{ overflowWrap: 'anywhere', wordBreak: 'break-all' }}
            >
              {proofLabel}
            </dd>
          </div>
        </dl>

        {activeTab === 'summary' ? (
          <div style={{ marginTop: 8 }}>
            <h4 style={{ fontSize: 13 }}>Statement summary</h4>
            <p style={{ fontSize: 12 }}>
              Phase: <strong>{status}</strong> · Mode:{' '}
              {offline ? 'Local browser inspection' : 'Registry & event corroboration'} ·
              Matching events: {identity.matchingEvents.length}
            </p>
          </div>
        ) : null}

        {activeTab === 'chain' ? (
          <div style={{ marginTop: 8 }}>
            <h4 style={{ fontSize: 13 }}>On-chain commitment binding</h4>
            <p style={{ fontSize: 12 }}>
              {offline
                ? 'Offline mode active: Soroban commitments were not queried.'
                : chainProof
                  ? `Registry tier ${chainProof.tier} standing code ${chainProof.status}.`
                  : 'No on-chain commitment loaded for this statement.'}
            </p>
            <div style={{ marginTop: 6 }}>
              <button
                type="button"
                className="hero-secondary"
                aria-expanded={showFullCommitments}
                onClick={() => setShowFullCommitments((prev) => !prev)}
              >
                {showFullCommitments ? 'Hide commitment digests' : 'Inspect commitment digests'}
              </button>
            </div>
            {showFullCommitments ? (
              <dl
                className="data-list"
                data-testid="dependent-commitment-details"
                style={{ marginTop: 8 }}
              >
                <div>
                  <dt>Metadata digest</dt>
                  <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all' }}>
                    {identity.metadataHash ?? 'Unavailable'}
                  </dd>
                </div>
                <div>
                  <dt>Registry source</dt>
                  <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all' }}>
                    {identity.chainSource ?? 'Unavailable'}
                  </dd>
                </div>
              </dl>
            ) : null}
          </div>
        ) : null}

        {activeTab === 'corroboration' ? (
          <div style={{ marginTop: 8 }}>
            <h4 style={{ fontSize: 13 }}>
              Matching statement events ({identity.matchingEvents.length})
            </h4>
            {identity.matchingEvents.length === 0 ? (
              <p style={{ fontSize: 12 }}>
                No corroborated events recorded for this statement digest.
              </p>
            ) : (
              <ul style={{ fontSize: 12 }}>
                {identity.matchingEvents.map((event) => (
                  <li key={event.id} style={{ marginBottom: 6 }}>
                    <div>
                      <button
                        type="button"
                        className="hero-secondary"
                        aria-pressed={selectedEventId === event.id}
                        onClick={() => setSelectedEventId(event.id)}
                      >
                        Inspect event #{event.id} ({event.tier})
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {selectedEvent ? (
              <p
                data-testid="dependent-selected-event"
                style={{ fontSize: 12, marginTop: 6, overflowWrap: 'anywhere' }}
              >
                Selected event #{selectedEvent.id} transaction: {selectedEvent.tx_hash ?? 'pending'}
              </p>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  )
}
