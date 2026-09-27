import type { ChainProofRecord } from '../stellarTypes'
import { useIssuerTrust } from '../hooks/useIssuerTrust'
import { IssuerTrustBadge } from '../provenance/IssuerTrustBadge'
import { shortHash } from '../utils'

type Props = {
  chainProof: ChainProofRecord | null
}

export function ChainProofPanel({ chainProof }: Props) {
  // The badge reflects the registry's issuer standing, which is separate from
  // the record's own status: a record can stay REGISTERED on chain while its
  // issuer has since been revoked (see THREAT_MODEL.md T3).
  const issuerTrust = useIssuerTrust({
    issuer: chainProof?.issuer ?? null,
    expiresAt: chainProof?.expiresAt ?? null,
    enabled: chainProof !== null,
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
