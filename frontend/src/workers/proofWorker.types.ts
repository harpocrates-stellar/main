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
  | 'UNSUPPORTED_INPUT_SCHEMA'
  | 'ARTIFACT_MISMATCH'
  | 'INVALID_PROOF_OUTPUT'
  | 'UNSUPPORTED_ENVIRONMENT'
  | 'CIRCUIT_LOAD_FAILED'
  | 'MEMORY_LIMIT_EXCEEDED'
  | 'PROOF_GENERATION_FAILED'
  | 'TIMEOUT'
  | 'WORKER_UNAVAILABLE'
  | 'FALLBACK_LIMIT_EXCEEDED'

/**
 * Which runtime actually executes proof generation.
 * - 'worker'      — the dedicated Web Worker.
 * - 'main-thread' — the non-worker fallback (explicit bounds enforced).
 */
export type RuntimeMode = 'worker' | 'main-thread'

/** Why the client ended up proving on the main thread. */
export type FallbackReason =
  | 'worker_api_unavailable'
  | 'worker_spawn_failed'
  | 'worker_crashed'
  | 'runtime_forced_main'

export type TransferableProofInput = {
  videoHash: string
  credentialSecret: ArrayBuffer
  nullifierSecret: ArrayBuffer
  inputSchemaVersion?: number
  verifierScope?: string
  epoch?: number
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
