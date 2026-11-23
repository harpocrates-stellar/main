import React, { useState } from 'react'
import { AlertTriangle, RefreshCw, Save, Trash2 } from 'lucide-react'
import type { PreservedActiveWork, RecoveryAction, StaleReason } from '../credentialVault'

export interface VaultRecoveryBannerProps {
  staleReason: StaleReason | null
  preservedWork?: PreservedActiveWork | null
  onRecover: (action: RecoveryAction, passphrase?: string) => void | Promise<void>
  onDismiss?: () => void
}

export function VaultRecoveryBanner({
  staleReason,
  preservedWork,
  onRecover,
  onDismiss,
}: VaultRecoveryBannerProps) {
  const [passphrase, setPassphrase] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleAction = async (action: RecoveryAction) => {
    setError(null)
    if (action === 'overwrite' && !passphrase.trim()) {
      setError('Please provide a vault passphrase to overwrite and secure the vault.')
      return
    }
    setIsSubmitting(true)
    try {
      await onRecover(action, passphrase || undefined)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Recovery action failed')
    } finally {
      setIsSubmitting(false)
    }
  }

  const reasonDescription =
    staleReason === 'envelope-removed'
      ? 'The credential vault envelope was deleted in another tab or browser window.'
      : staleReason === 'envelope-corrupted'
        ? 'The vault envelope in browser storage was corrupted or replaced with an unsupported version.'
        : 'The credential vault envelope was updated with new credentials in another browser tab.'

  return (
    <section
      className="vault-recovery-banner"
      role="alert"
      aria-live="assertive"
      aria-label="Cross-tab vault update notice"
    >
      <div className="banner-header">
        <AlertTriangle className="banner-icon" size={18} aria-hidden="true" />
        <h3 className="banner-title">Cross-tab vault change detected</h3>
      </div>

      <p className="banner-description">
        {reasonDescription} Your current active session has been invalidated, but in-progress witness
        material has been quarantined and preserved.
      </p>

      {preservedWork?.customData ? (
        <div className="banner-preserved-details">
          <span>Active work preserved: </span>
          <code>{JSON.stringify(preservedWork.customData)}</code>
        </div>
      ) : null}

      <div className="banner-passphrase-row">
        <label htmlFor="recovery-passphrase-input">
          Vault passphrase (required for overwrite, optional for reload):
        </label>
        <input
          id="recovery-passphrase-input"
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="Enter passphrase"
          autoComplete="off"
          disabled={isSubmitting}
        />
      </div>

      {error ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}

      <div className="banner-actions" role="group" aria-label="Vault recovery options">
        <button
          type="button"
          className="btn-recovery btn-overwrite"
          disabled={isSubmitting}
          onClick={() => void handleAction('overwrite')}
          aria-label="Overwrite storage with current active work"
        >
          <Save size={14} aria-hidden="true" />
          Keep active work &amp; overwrite
        </button>

        <button
          type="button"
          className="btn-recovery btn-reload"
          disabled={isSubmitting}
          onClick={() => void handleAction('reload')}
          aria-label="Reload remote vault and discard local active work"
        >
          <RefreshCw size={14} aria-hidden="true" />
          Reload remote vault
        </button>

        <button
          type="button"
          className="btn-recovery btn-discard"
          disabled={isSubmitting}
          onClick={() => void handleAction('discard')}
          aria-label="Discard local active work and lock vault"
        >
          <Trash2 size={14} aria-hidden="true" />
          Discard local work
        </button>

        {onDismiss ? (
          <button
            type="button"
            className="btn-recovery btn-dismiss"
            onClick={onDismiss}
            aria-label="Dismiss notice"
          >
            Dismiss
          </button>
        ) : null}
      </div>
    </section>
  )
}
