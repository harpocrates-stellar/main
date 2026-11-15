import React, { useEffect, useId, useState } from 'react'
import type {
  CredentialVault,
  ExternalVaultChangeState,
  ExternalVaultRecoveryResult,
} from '../credentialVault'

export interface CrossTabVaultChangeBannerProps {
  vault: CredentialVault
  onRecovered?: (result: ExternalVaultRecoveryResult) => void
}

export function CrossTabVaultChangeBanner({
  vault,
  onRecovered,
}: CrossTabVaultChangeBannerProps) {
  const [changeState, setChangeState] = useState<ExternalVaultChangeState>(() =>
    vault.getExternalChangeState(),
  )
  const [passphrase, setPassphrase] = useState('')
  const [recoveryError, setRecoveryError] = useState<string | null>(null)
  const passphraseInputId = useId()
  const headingId = useId()

  useEffect(() => {
    return vault.subscribeExternalChange((next) => {
      setChangeState(next)
      setRecoveryError(null)
    })
  }, [vault])

  if (!changeState.stale) {
    return null
  }

  const handleReunlock = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setRecoveryError(null)
    const result = await vault.resolveExternalChange({
      type: 'reunlock-updated-vault',
      password: passphrase,
    })
    setPassphrase('')
    if (!result.resolved) {
      setRecoveryError(
        'Could not unlock the updated vault with that passphrase. Your active work remains preserved.',
      )
      return
    }
    onRecovered?.(result)
  }

  const handleContinueLocked = async () => {
    setRecoveryError(null)
    const result = await vault.resolveExternalChange({
      type: 'continue-locked-preserve-work',
    })
    onRecovered?.(result)
  }

  const handleDiscardWork = async () => {
    setRecoveryError(null)
    const result = await vault.resolveExternalChange({
      type: 'discard-active-work',
    })
    onRecovered?.(result)
  }

  return (
    <section role="alert" aria-labelledby={headingId} className="vault-stale-banner">
      <h2 id={headingId}>
        {changeState.kind === 'removed'
          ? 'Credential vault was removed in another tab'
          : 'Credential vault was updated in another tab'}
      </h2>
      <p>
        Unlocked credentials in this tab were invalidated to prevent signing with stale
        witness material.
        {changeState.activeWorkPreserved
          ? ' Your unsaved non-secret work is preserved until you choose how to proceed.'
          : ' Choose a recovery action to continue.'}
      </p>

      {changeState.kind === 'updated' ? (
        <form onSubmit={handleReunlock}>
          <div>
            <label htmlFor={passphraseInputId}>Updated vault passphrase</label>
          </div>
          <div>
            <input
              id={passphraseInputId}
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              autoComplete="current-password"
            />
          </div>
          <div>
            <button type="submit">Unlock updated vault and keep work</button>
          </div>
        </form>
      ) : null}

      {recoveryError ? <p role="status">{recoveryError}</p> : null}

      <div>
        <div>
          <button type="button" onClick={handleContinueLocked}>
            Keep work and stay locked
          </button>
        </div>
        <div>
          <button type="button" onClick={handleDiscardWork}>
            Discard active work
          </button>
        </div>
      </div>
    </section>
  )
}
