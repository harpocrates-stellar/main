import { EyeOff, ShieldCheck } from 'lucide-react'
import type { ProofPreparationPreviewResult } from '../proofPreparationPreview'
import './ProofPreparationPreview.css'

type Props = {
  preparation: ProofPreparationPreviewResult
}

/**
 * Evidence Studio panel: shows the canonical public inputs and policy version
 * a Silent Witness proof would bind, before proving starts.
 *
 * Presentational and strictly read-only — all policy lives in
 * `buildProofPreparationPreview`, and this panel exposes no submit action.
 */
export function ProofPreparationPreview({ preparation }: Props) {
  if (!preparation.ok) {
    if (preparation.code === 'MISSING_EVIDENCE') {
      return (
        <div className="proof-preparation proof-preparation--empty" role="status">
          <h3>Proof preparation preview</h3>
          <p className="muted">Generate evidence to preview the canonical public inputs.</p>
        </div>
      )
    }

    return (
      <div
        className="proof-preparation proof-preparation--error"
        role="alert"
        data-error-code={preparation.code}
      >
        <h3>Proof preparation preview</h3>
        <p>{preparation.message}</p>
      </div>
    )
  }

  return (
    <div
      className="proof-preparation"
      role="region"
      aria-label="Read-only proof preparation preview"
    >
      <header className="proof-preparation__header">
        <ShieldCheck size={16} aria-hidden="true" />
        <h3>Proof preparation preview</h3>
        <span className="proof-preparation__badge">Read-only</span>
      </header>
      <p className="proof-preparation__policy">
        Policy <code>{preparation.policyId}</code>
        <span aria-hidden="true"> · </span>
        version <code>{preparation.policyVersion}</code>
      </p>
      <p className="proof-preparation__summary">{preparation.summary}</p>
      <dl className="proof-preparation__list" aria-label="Canonical public inputs">
        {preparation.publicInputs.map((field) => (
          <div
            key={field.key}
            className="proof-preparation__row proof-preparation__row--public"
            data-key={field.key}
            data-disclosed="true"
          >
            <dt>{field.label}</dt>
            <dd>
              <code>{field.value}</code>
            </dd>
          </div>
        ))}
        {preparation.concealedInputs.map((field) => (
          <div
            key={field.key}
            className="proof-preparation__row proof-preparation__row--concealed"
            data-key={field.key}
            data-disclosed="false"
          >
            <dt>{field.label}</dt>
            <dd>
              <EyeOff size={12} aria-hidden="true" />
              <code>{field.value}</code>
            </dd>
          </div>
        ))}
      </dl>
      <p className="proof-preparation__footnote muted">
        Private witness values stay in this browser. Nothing is proven or submitted from this preview.
      </p>
    </div>
  )
}

export default ProofPreparationPreview
