import type { IdentityTier } from './stellarTypes'
import type { TimeAttestation } from './timeAttestation'

export type { IdentityTier }

export type Stage = 'idle' | 'hashing' | 'embedding' | 'proving' | 'ready' | 'registered' | 'error' | 'cancelled'

export type UploadAdmissionStatus = 'idle' | 'admitted' | 'rejected'

export type UploadAdmissionReason =
  | 'queue_full'
  | 'identity_limit'
  | 'timeout'
  | 'rate_limited'

export type UploadErrorKind = 'none' | 'admission_rejected' | 'invalid_evidence' | 'unknown'

export type UploadAdmissionState = {
  status: UploadAdmissionStatus
  reason: UploadAdmissionReason | null
  message: string
  retryAfter: number | null
  retryable: boolean
  actionHint: 'retry' | 'fix_input' | 'reduce_file_size' | 'use_supported_format' | 'check_resource' | 'none'
}

export type View = 'landing' | 'studio' | 'verify'

export type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

export type ProofPackage = {
  fileName: string
  sourceHash: string
  videoHash: string
  metadataHash: string
  proofId: string
  timestamp: string
  tier: IdentityTier
  silentWitness?: SilentWitnessProof
  timeAttestation?: TimeAttestation
}

export type ProofEvent = {
  id: number
  event_type: string
  file_name: string | null
  video_hash: string | null
  proof_id: string | null
  tier: string | null
  tx_hash?: string | null
  tx_status?: string | null
  created_at: string
  time_attestation?: TimeAttestation
  claimed_capture_time?: string
}
