/**
 * Canonical proof-generation phase vocabulary for the Silent Witness flow.
 *
 * Single source of truth shared by:
 *   - the main-thread prover            (`noirClient.ts`)
 *   - the proof Web Worker boundary     (`workers/proofWorker.types.ts`)
 *   - the Evidence Studio phase display (`views/StudioView.tsx`)
 *
 * Privacy-safe by construction: a phase is a static identifier describing
 * *local computation only*. It never carries media, witness values, secrets,
 * public inputs, or proof bytes, so it is safe to announce in the UI and to
 * forward across the worker boundary.
 */

export const PROOF_STAGES = [
  'loading_circuits',
  'executing_helper',
  'executing_main',
  'generating_proof',
] as const

export type ProofStage = (typeof PROOF_STAGES)[number]

/** Ordered phases exactly as they occur during one Silent Witness proof. */
export const PROOF_STAGE_SEQUENCE: readonly ProofStage[] = Object.freeze([...PROOF_STAGES])

/** Human-readable, privacy-safe labels for each phase. */
export const PROOF_STAGE_LABELS: Readonly<Record<ProofStage, string>> = Object.freeze({
  loading_circuits: 'Loading circuits…',
  executing_helper: 'Computing credential root and nullifier…',
  executing_main: 'Executing witness…',
  generating_proof: 'Generating UltraHonk proof…',
})

export function isProofStage(value: unknown): value is ProofStage {
  return typeof value === 'string' && (PROOF_STAGES as readonly string[]).includes(value)
}

export function proofStageLabel(stage: ProofStage): string {
  return PROOF_STAGE_LABELS[stage]
}

/** Zero-based position of a phase in the canonical sequence (or -1). */
export function proofStageIndex(stage: ProofStage): number {
  return PROOF_STAGE_SEQUENCE.indexOf(stage)
}

export type ProofStageStatus = 'complete' | 'active' | 'pending'

/**
 * Derive a phase's display status relative to the currently running phase.
 * Phases before the current one are complete, the current one is active, and
 * everything after is pending. Unknown/absent current phases leave every entry
 * pending so a stale value can never render as "complete".
 */
export function proofStageStatus(
  phase: ProofStage,
  current: ProofStage | null,
): ProofStageStatus {
  if (!current) return 'pending'
  const phaseIndex = proofStageIndex(phase)
  const currentIndex = proofStageIndex(current)
  if (currentIndex < 0 || phaseIndex < 0) return 'pending'
  if (phaseIndex < currentIndex) return 'complete'
  if (phaseIndex === currentIndex) return 'active'
  return 'pending'
}
