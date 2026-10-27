import { useEffect, useId, useState } from 'react'
import { AlertCircle, CheckCircle2, Loader2, ShieldAlert } from 'lucide-react'
import {
  DisputeReason,
  DISPUTE_REASON_LABELS,
  getOpenDisputeCount,
  isValidDisputeReason,
  isValidEvidenceHash,
  openDispute,
  respondDispute,
} from '../harpocratesRegistry'
import { useTransactionState } from '../hooks/useTransactionState'
import { formatContractErrorMessage } from '../services/apiError'
import type { ChainProofRecord } from '../stellarTypes'

const DEFAULT_CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

export type DisputePanelProps = {
  proofId?: string | null
  wallet: string
  networkMismatch?: string | null
  contractId?: string
  offline?: boolean
  chainProof?: ChainProofRecord | null
}

export function DisputePanel({
  proofId,
  wallet,
  networkMismatch,
  contractId = DEFAULT_CONTRACT_ID,
  offline = false,
  chainProof: _chainProof,
}: DisputePanelProps) {
  const [activeTab, setActiveTab] = useState<'open' | 'respond'>('open')
  const [openDisputeCount, setOpenDisputeCount] = useState<number | null>(null)
  const [isLoadingCount, setIsLoadingCount] = useState(false)

  // Form states for Open Dispute
  const [openReason, setOpenReason] = useState<number>(DisputeReason.ContentError)
  const [openEvidenceHash, setOpenEvidenceHash] = useState('')
  const [openValidationFeedback, setOpenValidationFeedback] = useState<string | null>(null)

  // Form states for Respond Dispute
  const [respondDisputeId, setRespondDisputeId] = useState('')
  const [respondCommitment, setRespondCommitment] = useState('')
  const [respondValidationFeedback, setRespondValidationFeedback] = useState<string | null>(null)

  const [actionError, setActionError] = useState<string | null>(null)
  const [successHash, setSuccessHash] = useState<string | null>(null)

  const reasonSelectId = useId()
  const evidenceInputId = useId()
  const disputeIdInputId = useId()
  const commitmentInputId = useId()

  const { state: txState, machine, send: sendTxEvent } = useTransactionState()

  // Load open dispute count whenever proofId or offline status changes
  useEffect(() => {
    let cancelled = false
    if (offline || !proofId || !contractId) {
      setOpenDisputeCount(null)
      return
    }

    setIsLoadingCount(true)
    getOpenDisputeCount(contractId, proofId, wallet || undefined)
      .then((count) => {
        if (!cancelled) setOpenDisputeCount(count)
      })
      .catch(() => {
        if (!cancelled) setOpenDisputeCount(null)
      })
      .finally(() => {
        if (!cancelled) setIsLoadingCount(false)
      })

    return () => {
      cancelled = true
    }
  }, [contractId, proofId, wallet, offline])

  const isSubmitting = txState.status === 'submitting' || txState.status === 'awaiting_confirmation'

  // Open dispute submit handler
  async function handleOpenDispute(e: React.FormEvent) {
    e.preventDefault()
    setActionError(null)
    setOpenValidationFeedback(null)
    setSuccessHash(null)

    if (networkMismatch) {
      setActionError(`Wallet network mismatch: ${networkMismatch}. Please switch network to testnet.`)
      return
    }

    if (!wallet) {
      setActionError('Wallet not connected.')
      return
    }

    if (!proofId) {
      setActionError('No proof ID loaded to challenge.')
      return
    }

    if (!isValidDisputeReason(openReason)) {
      setOpenValidationFeedback('Select a valid dispute reason (1 to 6).')
      return
    }

    const trimmedEvidence = openEvidenceHash.trim()
    if (!isValidEvidenceHash(trimmedEvidence)) {
      setOpenValidationFeedback('Evidence hash must be a 64-character (32-byte) hex string.')
      return
    }

    try {
      const res = await openDispute(
        {
          contractId,
          publicKey: wallet,
          proofId,
          reason: openReason,
          evidenceHash: trimmedEvidence,
        },
        machine,
      )
      setSuccessHash(res.hash)
      // refresh count
      if (contractId && proofId) {
        getOpenDisputeCount(contractId, proofId, wallet).then(setOpenDisputeCount).catch(() => {})
      }
    } catch (err) {
      const formatted = formatContractErrorMessage(err)
      setActionError(formatted)
    }
  }

  // Respond dispute submit handler
  async function handleRespondDispute(e: React.FormEvent) {
    e.preventDefault()
    setActionError(null)
    setRespondValidationFeedback(null)
    setSuccessHash(null)

    if (networkMismatch) {
      setActionError(`Wallet network mismatch: ${networkMismatch}. Please switch network to testnet.`)
      return
    }

    if (!wallet) {
      setActionError('Wallet not connected.')
      return
    }

    const trimmedDisputeId = respondDisputeId.trim()
    if (!isValidEvidenceHash(trimmedDisputeId)) {
      setRespondValidationFeedback('Dispute ID must be a 64-character (32-byte) hex string.')
      return
    }

    const trimmedCommitment = respondCommitment.trim()
    if (!isValidEvidenceHash(trimmedCommitment)) {
      setRespondValidationFeedback('Response commitment must be a 64-character (32-byte) hex string.')
      return
    }

    try {
      const res = await respondDispute(
        {
          contractId,
          publicKey: wallet,
          disputeId: trimmedDisputeId,
          responseCommitment: trimmedCommitment,
        },
        machine,
      )
      setSuccessHash(res.hash)
    } catch (err) {
      const formatted = formatContractErrorMessage(err)
      setActionError(formatted)
    }
  }

  return (
    <div className="dispute-panel" data-testid="dispute-panel" style={{ marginTop: '1.25rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
        <h4 style={{ margin: 0, fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <ShieldAlert size={14} aria-hidden="true" />
          <span>Dispute Registry</span>
        </h4>
        <span
          className="badge"
          data-testid="open-dispute-count"
          style={{ fontSize: '0.75rem', fontWeight: 600 }}
        >
          {offline
            ? 'Offline'
            : isLoadingCount
              ? 'Loading…'
              : openDisputeCount !== null
                ? `${openDisputeCount} open`
                : '0 open'}
        </span>
      </div>

      {offline ? (
        <p className="muted" style={{ fontSize: 11 }}>
          Disputes cannot be inspected or submitted in offline mode.
        </p>
      ) : !wallet ? (
        <p className="muted" data-testid="dispute-wallet-required" style={{ fontSize: 12 }}>
          Connect your wallet to open a dispute or respond as an issuer.
        </p>
      ) : (
        <>
          {networkMismatch ? (
            <div
              className="network-mismatch-banner"
              data-testid="dispute-network-mismatch-guard"
              role="alert"
              aria-live="assertive"
              style={{ marginBottom: '0.75rem', padding: '0.5rem', fontSize: '11px' }}
            >
              <span>⚠ Network Mismatch: Transactions are disabled. {networkMismatch}</span>
            </div>
          ) : null}

          {/* Tab selector */}
          <div role="tablist" style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'open'}
              className={`mode-toggle ${activeTab === 'open' ? 'active' : ''}`}
              style={{ flex: 1, padding: '0.3rem 0.5rem', fontSize: '11px' }}
              onClick={() => {
                setActiveTab('open')
                setActionError(null)
              }}
            >
              Open Dispute
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'respond'}
              className={`mode-toggle ${activeTab === 'respond' ? 'active' : ''}`}
              style={{ flex: 1, padding: '0.3rem 0.5rem', fontSize: '11px' }}
              onClick={() => {
                setActiveTab('respond')
                setActionError(null)
              }}
            >
              Respond to Dispute
            </button>
          </div>

          {activeTab === 'open' ? (
            <form onSubmit={handleOpenDispute} data-testid="open-dispute-form">
              <div style={{ marginBottom: '0.5rem' }}>
                <label
                  htmlFor={reasonSelectId}
                  style={{ display: 'block', fontSize: '11px', marginBottom: '0.2rem' }}
                >
                  Reason Code
                </label>
                <select
                  id={reasonSelectId}
                  value={openReason}
                  disabled={isSubmitting}
                  onChange={(e) => setOpenReason(Number(e.target.value))}
                  style={{
                    width: '100%',
                    padding: '0.35rem',
                    fontSize: '11px',
                    borderRadius: '4px',
                    backgroundColor: 'var(--color-bg-subtle, #1e1e24)',
                    color: 'inherit',
                  }}
                >
                  {Object.entries(DISPUTE_REASON_LABELS).map(([code, label]) => (
                    <option key={code} value={code}>
                      {code} - {label}
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ marginBottom: '0.5rem' }}>
                <label
                  htmlFor={evidenceInputId}
                  style={{ display: 'block', fontSize: '11px', marginBottom: '0.2rem' }}
                >
                  Evidence Hash (32-byte hex)
                </label>
                <input
                  id={evidenceInputId}
                  type="text"
                  value={openEvidenceHash}
                  disabled={isSubmitting}
                  placeholder="64-character hex hash"
                  onChange={(e) => {
                    setOpenEvidenceHash(e.target.value)
                    setOpenValidationFeedback(null)
                  }}
                  style={{
                    width: '100%',
                    padding: '0.35rem',
                    fontSize: '11px',
                    borderRadius: '4px',
                    boxSizing: 'border-box',
                    backgroundColor: 'var(--color-bg-subtle, #1e1e24)',
                    color: 'inherit',
                  }}
                />
                {openValidationFeedback ? (
                  <p
                    data-testid="open-validation-error"
                    role="alert"
                    style={{ color: '#ff6b6b', fontSize: '10px', marginTop: '0.2rem' }}
                  >
                    {openValidationFeedback}
                  </p>
                ) : null}
              </div>

              <button
                type="submit"
                className="hero-primary"
                disabled={isSubmitting || Boolean(networkMismatch) || !proofId}
                style={{ width: '100%', padding: '0.4rem', fontSize: '11px' }}
              >
                {isSubmitting ? (
                  <>
                    <Loader2 size={12} className="spin" aria-hidden="true" />
                    <span>Submitting Dispute…</span>
                  </>
                ) : (
                  'Open Dispute'
                )}
              </button>
            </form>
          ) : (
            <form onSubmit={handleRespondDispute} data-testid="respond-dispute-form">
              <div style={{ marginBottom: '0.5rem' }}>
                <label
                  htmlFor={disputeIdInputId}
                  style={{ display: 'block', fontSize: '11px', marginBottom: '0.2rem' }}
                >
                  Dispute ID (32-byte hex)
                </label>
                <input
                  id={disputeIdInputId}
                  type="text"
                  value={respondDisputeId}
                  disabled={isSubmitting}
                  placeholder="64-character hex dispute ID"
                  onChange={(e) => {
                    setRespondDisputeId(e.target.value)
                    setRespondValidationFeedback(null)
                  }}
                  style={{
                    width: '100%',
                    padding: '0.35rem',
                    fontSize: '11px',
                    borderRadius: '4px',
                    boxSizing: 'border-box',
                    backgroundColor: 'var(--color-bg-subtle, #1e1e24)',
                    color: 'inherit',
                  }}
                />
              </div>

              <div style={{ marginBottom: '0.5rem' }}>
                <label
                  htmlFor={commitmentInputId}
                  style={{ display: 'block', fontSize: '11px', marginBottom: '0.2rem' }}
                >
                  Response Commitment (32-byte hex)
                </label>
                <input
                  id={commitmentInputId}
                  type="text"
                  value={respondCommitment}
                  disabled={isSubmitting}
                  placeholder="64-character hex commitment"
                  onChange={(e) => {
                    setRespondCommitment(e.target.value)
                    setRespondValidationFeedback(null)
                  }}
                  style={{
                    width: '100%',
                    padding: '0.35rem',
                    fontSize: '11px',
                    borderRadius: '4px',
                    boxSizing: 'border-box',
                    backgroundColor: 'var(--color-bg-subtle, #1e1e24)',
                    color: 'inherit',
                  }}
                />
                {respondValidationFeedback ? (
                  <p
                    data-testid="respond-validation-error"
                    role="alert"
                    style={{ color: '#ff6b6b', fontSize: '10px', marginTop: '0.2rem' }}
                  >
                    {respondValidationFeedback}
                  </p>
                ) : null}
              </div>

              <button
                type="submit"
                className="hero-primary"
                disabled={isSubmitting || Boolean(networkMismatch)}
                style={{ width: '100%', padding: '0.4rem', fontSize: '11px' }}
              >
                {isSubmitting ? (
                  <>
                    <Loader2 size={12} className="spin" aria-hidden="true" />
                    <span>Submitting Response…</span>
                  </>
                ) : (
                  'Respond to Dispute'
                )}
              </button>
            </form>
          )}

          {/* Transaction State & Action Feedback */}
          {txState.status === 'awaiting_confirmation' ? (
            <div
              data-testid="tx-status-awaiting"
              style={{
                marginTop: '0.5rem',
                fontSize: '11px',
                color: 'var(--text-muted)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.3rem',
              }}
            >
              <Loader2 size={12} className="spin" aria-hidden="true" />
              <span>Awaiting transaction confirmation…</span>
            </div>
          ) : null}

          {txState.status === 'confirmed' || successHash ? (
            <div
              data-testid="tx-status-confirmed"
              role="status"
              style={{
                marginTop: '0.5rem',
                fontSize: '11px',
                color: '#51cf66',
                display: 'flex',
                alignItems: 'center',
                gap: '0.3rem',
              }}
            >
              <CheckCircle2 size={14} aria-hidden="true" />
              <span>Dispute transaction confirmed!</span>
            </div>
          ) : null}

          {actionError ? (
            <div
              data-testid="dispute-action-error"
              role="alert"
              style={{
                marginTop: '0.5rem',
                fontSize: '11px',
                color: '#ff6b6b',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.3rem',
              }}
            >
              <AlertCircle size={14} style={{ flexShrink: 0, marginTop: '1px' }} aria-hidden="true" />
              <span>{actionError}</span>
            </div>
          ) : null}

          {(txState.status === 'confirmed' || txState.status === 'failed' || actionError) && !isSubmitting ? (
            <div style={{ marginTop: '0.4rem', textAlign: 'right' }}>
              <button
                type="button"
                className="hero-secondary"
                style={{ fontSize: '10px', padding: '0.2rem 0.4rem' }}
                onClick={() => {
                  sendTxEvent({ type: 'RESET' })
                  setActionError(null)
                  setSuccessHash(null)
                }}
              >
                Reset
              </button>
            </div>
          ) : null}
        </>
      )}
    </div>
  )
}
