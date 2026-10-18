import { useMemo, useState } from 'react'
import { Link2 } from 'lucide-react'
import {
  createVerificationShareLink,
  type VerificationShareLinkInput,
} from '../verificationShareLink'

type Props = {
  input: VerificationShareLinkInput | null
  /** Optional absolute base; defaults to window.location origin+path. */
  baseUrl?: string
  className?: string
}

/**
 * Generates a privacy-safe shareable verification link and copies it.
 * Disabled when required public fields are unavailable.
 */
export function ShareVerificationLink({ input, baseUrl, className }: Props) {
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'error' | 'invalid'>('idle')

  const created = useMemo(() => {
    if (!input) return null
    return createVerificationShareLink(input, baseUrl ? { baseUrl } : undefined)
  }, [input, baseUrl])

  const disabled = !created || !created.ok

  async function onCopy() {
    if (!created || !created.ok) {
      setCopyState('invalid')
      return
    }
    try {
      await navigator.clipboard.writeText(created.url)
      setCopyState('copied')
    } catch {
      setCopyState('error')
    }
  }

  return (
    <div className={className ?? 'share-verification-link'} role="group" aria-label="Shareable verification link">
      <button
        type="button"
        className="hero-secondary verify-action-btn"
        disabled={disabled}
        onClick={() => void onCopy()}
        aria-label="Copy shareable verification link"
      >
        <Link2 size={14} aria-hidden="true" />
        <span>Copy verification link</span>
      </button>
      {copyState !== 'idle' ? (
        <p className="share-link-status muted" aria-live="polite" style={{ marginTop: 6, fontSize: 11 }}>
          {copyState === 'copied'
            ? 'Verification link copied. It contains only public hashes and registry identifiers.'
            : copyState === 'invalid'
              ? 'Unable to build a verification link from the current public fields.'
              : 'Unable to copy the verification link.'}
        </p>
      ) : (
        <p className="muted" style={{ marginTop: 6, fontSize: 11 }}>
          Share a link that opens Verify with public digests only — never media or secrets.
        </p>
      )}
    </div>
  )
}
