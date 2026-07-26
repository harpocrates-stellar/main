export type IdentityTier = 'silent' | 'source' | 'seal'

export type Hex32 = string & { readonly __hex32: unique symbol }
export type HexBytes = string & { readonly __hexBytes: unique symbol }

export type SilentWitnessArtifacts = {
  publicInputs: HexBytes
  proof: HexBytes
}

export type RegisterProofInput = {
  contractId: string
  publicKey: string
  tier: IdentityTier
  videoHash: string
  metadataHash: string
  proofId: string
  silentWitness?: {
    publicInputs: string
    proof: string
  }
}

export type NormalizedRegisterProofInput = {
  contractId: string
  publicKey: string
  tier: IdentityTier
  videoHash: Hex32
  metadataHash: Hex32
  proofId: Hex32
  silentWitness?: SilentWitnessArtifacts
}

export type TxState = 'idle' | 'submitting' | 'awaiting_confirmation' | 'confirmed' | 'failed' | 'timeout'

export type TxStatusLabel =
  | 'Not submitted'
  | 'Pending'
  | 'Confirmed'
  | 'Failed'
  | 'Rejected by wallet'
  | 'Timed out'

export function describeTxState(state: TxState): TxStatusLabel {
  switch (state) {
    case 'idle':
      return 'Not submitted'
    case 'submitting':
      return 'Pending'
    case 'awaiting_confirmation':
      return 'Pending'
    case 'confirmed':
      return 'Confirmed'
    case 'failed':
      return 'Failed'
    case 'timeout':
      return 'Timed out'
  }
}

export type RegisterProofResult = {
  hash: string
  status: string
  txState: TxState
}

export type ChainProofRecord = {
  videoHash: string
  metadataHash: string
  tier: number
  status: number
  createdAt: string
  source: string | null
  issuer: string | null
}

export type RegistryMethod =
  | 'register_anonymous_verified'
  | 'register_source'
  | 'register_seal'
  | 'get_by_video'
  | 'get_proof'
  | 'get_proof_status'
  | 'get_proof_history_at'
  | 'get_proof_history_count'
  | 'revoke_proof'
  | 'verify_proof'
  | 'expire_proof'
  | 'correct_proof'

export type ProofLifecycleAction = 1 | 2 | 3 | 4 | 5 | 6

export type ProofHistoryEntry = {
  action: ProofLifecycleAction
  timestamp: string
  actor: string | null
  reasonCode: number
}

export type ProofHistoryResult = {
  entries: ProofHistoryEntry[]
  count: number
}
