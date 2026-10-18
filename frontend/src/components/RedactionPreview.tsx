import { EyeOff, ShieldCheck } from 'lucide-react'
import { useMemo } from 'react'
import type { ProofPackage } from '../types'
import {
  buildRedactionPreview,
  type RedactionPreviewSecrets,
} from '../redactionPreview'

type Props = {
  proof: ProofPackage | null
  secrets?: RedactionPreviewSecrets | null
}

/**
 * Evidence Studio panel: shows what crosses the public boundary after redaction.
 * Presentational — all policy lives in `buildRedactionPreview`.
 */
export function RedactionPreview({ proof, secrets }: Props) {
  const result = useMemo(
    () => buildRedactionPreview({ proof, secrets }),
    [proof, secrets],
  )

  if (!result.ok) {
    if (result.code === 'MISSING_EVIDENCE') {
      return (
        <div className="redaction-preview redaction-preview--empty" role="status">
          <h3>Redaction preview</h3>
          <p className="muted">Generate evidence to preview the privacy-safe public boundary.</p>
        </div>
      )
    }

    return (
      <div
        className="redaction-preview redaction-preview--error"
        role="alert"
        data-error-code={result.code}
      >
        <h3>Redaction preview</h3>
        <p>{result.message}</p>
      </div>
    )
  }

  return (
    <div className="redaction-preview" role="region" aria-label="Privacy-safe redaction preview">
      <header className="redaction-preview__header">
        <ShieldCheck size={16} aria-hidden="true" />
        <h3>Redaction preview</h3>
      </header>
      <p className="redaction-preview__summary" role="status">
        {result.summary}
      </p>
      <ul className="redaction-preview__list">
        {result.fields.map((field) => (
          <li
            key={field.key}
            className={
              field.disclosed
                ? 'redaction-preview__row redaction-preview__row--disclosed'
                : 'redaction-preview__row redaction-preview__row--redacted'
            }
            data-key={field.key}
            data-disclosed={field.disclosed ? 'true' : 'false'}
            data-reason={field.reason}
          >
            <span className="redaction-preview__label">{field.label}</span>
            <span className="redaction-preview__value">
              {!field.disclosed ? <EyeOff size={12} aria-hidden="true" /> : null}
              <code>{field.value}</code>
            </span>
          </li>
        ))}
      </ul>
      <p className="redaction-preview__footnote muted">
        Seeds, witness proofs, private keys, and media URLs never leave this boundary.
      </p>
    </div>
  )
}

export default RedactionPreview
