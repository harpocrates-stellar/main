import type { IssuerRotationRecord } from '../stellarTypes'
import type { IssuerTrustState } from '../provenance/issuerTrust'

export type IssuerDirectoryEntry = {
  address: string
  metadataHash: string | null
  active: boolean
  isVerifiable: boolean
  rotation: IssuerRotationRecord | null
  issuerState: 'active' | 'rotating' | 'revoked'
  trustState: IssuerTrustState
  graceWindowEnd: string | null
}
