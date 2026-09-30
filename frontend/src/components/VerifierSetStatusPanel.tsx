import { useVerifierState } from '../hooks/useVerifierState'

export function VerifierSetStatusPanel() {
  const { verifierState, loading, error } = useVerifierState()

  if (loading) {
    return (
      <div className="chain-grid" role="group" aria-label="Verifier set status loading">
        <p className="muted">Loading verifier status...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="chain-grid" role="group" aria-label="Verifier set status error">
        <p className="muted" style={{ color: 'var(--text-error)' }}>
          Failed to load verifier state
        </p>
      </div>
    )
  }

  if (!verifierState) {
    return (
      <div className="chain-grid" role="group" aria-label="Verifier set status not found">
        <p className="muted">Verifier state not found on-chain.</p>
      </div>
    )
  }

  const {
    activeVerifier,
    pendingVerifier,
    previousVerifier,
    activationLedger,
    overlapWindow,
    rollbackWindowEnd,
  } = verifierState

  return (
    <div className="chain-grid" role="group" aria-label="Verifier set status panel">
      <span>Active Verifier</span>
      <code>{activeVerifier ? activeVerifier.slice(0, 8) + '...' + activeVerifier.slice(-4) : 'None'}</code>

      {pendingVerifier ? (
        <>
          <span>Pending Verifier</span>
          <code>{pendingVerifier.slice(0, 8) + '...' + pendingVerifier.slice(-4)}</code>
          <span>Activation Ledger</span>
          <strong>{activationLedger}</strong>
        </>
      ) : null}

      {previousVerifier ? (
        <>
          <span>Previous Verifier</span>
          <code>{previousVerifier.slice(0, 8) + '...' + previousVerifier.slice(-4)}</code>
        </>
      ) : null}

      {overlapWindow !== '0' && (
        <>
          <span>Overlap Window</span>
          <strong>{overlapWindow} ledgers</strong>
        </>
      )}

      {rollbackWindowEnd !== '0' && (
        <>
          <span>Rollback End</span>
          <strong>Ledger {rollbackWindowEnd}</strong>
        </>
      )}
    </div>
  )
}
