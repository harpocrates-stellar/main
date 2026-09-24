import type { ProofStage } from '../proofStage'

/**
 * The proof-stage vocabulary is canonical in `../proofStage` so the prover, the
 * worker boundary, and the Evidence Studio UI cannot drift apart. Re-exported
 * here to keep the existing worker contract import path stable.
 */
export type { ProofStage }

export type ProofErrorCode =
  | 'BUSY'
  | 'CANCELLED'
  | 'CRASHED'
  | 'INVALID_INPUT'
  | 'UNSUPPORTED_ENVIRONMENT'
  | 'CIRCUIT_LOAD_FAILED'
  | 'PROOF_GENERATION_FAILED'
  | 'TIMEOUT'

export type TransferableProofInput = {
  videoHash: string
  credentialSecret: ArrayBuffer
  nullifierSecret: ArrayBuffer
}

export type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

export type WorkerRequest =
  | { type: 'GENERATE_PROOF'; requestId: string; input: TransferableProofInput }
  | { type: 'CANCEL'; requestId: string }

export type WorkerResponse =
  | { type: 'READY' }
  | { type: 'PROGRESS'; requestId: string; stage: ProofStage }
  | { type: 'RESULT'; requestId: string; proof: SilentWitnessProof }
  | { type: 'ERROR'; requestId: string; code: ProofErrorCode; message: string }
  | { type: 'CANCELLED'; requestId: string }
