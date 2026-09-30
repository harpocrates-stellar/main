import type { ChainProofRecord } from '../stellarTypes'
import { useIssuerTrust } from '../hooks/useIssuerTrust'
import { useProofRevocationReason } from '../hooks/useProofRevocationReason'
import { IssuerTrustBadge } from '../provenance/IssuerTrustBadge'
import { shortHash } from '../utils'

type Props = {
  chainProof: ChainProofRecord | null
  proofId?: string | null
  sourceAddress?: string
}

export function formatProofExpiry(expiresAt: number | null): string {
  if (expiresAt === 0) return 'Never'
  if (expiresAt === null || !Number.isSafeInteger(expiresAt) || expiresAt < 0) return 'Unavailable'

  const milliseconds = expiresAt * 1000
  if (!Number.isFinite(milliseconds)) return 'Unavailable'

  const date = new Date(milliseconds)
  return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toISOString()
}

export function ChainProofPanel({ chainProof, proofId, sourceAddress }: Props) {
  // The badge reflects the registry's issuer standing, which is separate from
  // the record's own status: a record can stay REGISTERED on chain while its
  // issuer has since been revoked (see THREAT_MODEL.md T3).
  const issuerTrust = useIssuerTrust({
    issuer: chainProof?.issuer ?? null,
    expiresAt: chainProof?.expiresAt ?? null,
    enabled: chainProof !== null,
  })
  const revocationReason = useProofRevocationReason({
    proofId,
    sourceAddress,
    revoked: chainProof?.status === 2,
  })

  if (!chainProof) {
    return <p className="muted">No on-chain match loaded.</p>
  }

  return (
    <div className="chain-grid">
      <span>Tier</span>
      <strong>{chainProof.tier}</strong>
      <span>Status</span>
      <strong>{chainProof.status}</strong>
      <span>Expires</span>
      <strong>{formatProofExpiry(chainProof.expiresAt)}</strong>
      {chainProof.status === 2 ? (
        <>
          <span>Revocation reason</span>
          <strong aria-live="polite">{revocationReason ?? 'Revocation reason unavailable.'}</strong>
        </>
      ) : null}
      <span>Issuer</span>
      <div className="chain-grid__value">
        <IssuerTrustBadge trust={issuerTrust} />
      </div>
      <span>Source</span>
      <code>{chainProof.source ? shortHash(chainProof.source) : 'None'}</code>
      <span>Metadata</span>
      <code>{shortHash(chainProof.metadataHash)}</code>
    </div>
  )
}
