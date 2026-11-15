import type { TrustVsSignatureStandingExplanation } from '../services/verificationFlow'

type Props = {
  explanation: TrustVsSignatureStandingExplanation | null
}

export function TrustStandingNotice({ explanation }: Props) {
  if (!explanation) return null

  return (
    <section
      className="trust-standing-notice"
      aria-labelledby="trust-standing-heading"
      data-reason-code={explanation.code}
      data-standing-category={explanation.category}
    >
      <h3 id="trust-standing-heading">Trust and signature standing</h3>
      <dl className="data-list" aria-label="Proof and issuer standing details">
        <div>
          <dt>Underlying proof</dt>
          <dd data-testid="standing-underlying-proof">
            {explanation.underlyingProofLabel}
          </dd>
        </div>
        <div>
          <dt>Standing code</dt>
          <dd data-testid="standing-reason-code">{explanation.code}</dd>
        </div>
      </dl>
      <p style={{ marginTop: 8, fontSize: 13 }}>
        <strong>{explanation.headline}</strong>
      </p>
      <p style={{ marginTop: 4, fontSize: 12 }}>
        {explanation.accessibleExplanation}
      </p>
    </section>
  )
}
