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

export type RegisterProofResult = {
  hash: string
  status: string
}

export type VerifierRotationInput = {
  contractId: string
  publicKey: string
  verifier: string
  activationLedger: number | bigint
  overlapWindow: number | bigint
  rollbackWindow: number | bigint
}

export type VerifierRotationActionInput = {
  contractId: string
  publicKey: string
}

export type ChainVerifierState = {
  activeVerifier: string | null
  pendingVerifier: string | null
  previousVerifier: string | null
  activationLedger: string
  overlapWindow: string
  rollbackWindow: string
  rollbackWindowEnd: string
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
  | 'schedule_verifier_rotation'
  | 'activate_verifier_rotation'
  | 'rollback_verifier_rotation'
  | 'get_verifier_state'
