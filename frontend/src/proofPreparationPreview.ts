/**
 * Read-only proof preparation preview for Evidence Studio.
 *
 * Before proving, an operator can see the canonical public inputs a Silent
 * Witness proof would bind and the policy version that defines their encoding.
 *
 * Guarantees (pure / deterministic — safe to unit test):
 * - Private witness values are never accepted by this module, so they cannot
 *   be disclosed: the two witness inputs are listed by name as `[REDACTED]`.
 * - Values are canonicalized through the same schema normalizer that proving
 *   uses, so what the operator sees is what the circuit receives.
 * - No circuits are loaded, no proof is generated, and no transaction is
 *   submitted.
 */

import {
  CIRCUIT_INPUT_SCHEMA_ID,
  CIRCUIT_INPUT_SCHEMA_VERSION,
  canonicalSilentWitnessPublicInputs,
  silentWitnessEpoch,
} from './circuitInputSchema'
import { REDACTED_PLACEHOLDER } from './redactionPreview'
import type { IdentityTier, ProofPackage } from './types'

/** Preview schema version. Bump on incompatible field-shape changes. */
export const PROOF_PREPARATION_PREVIEW_VERSION = 1 as const

/** Policy that defines the canonical proof-input envelope. */
export const PROOF_PREPARATION_POLICY_ID = CIRCUIT_INPUT_SCHEMA_ID
export const PROOF_PREPARATION_POLICY_VERSION = CIRCUIT_INPUT_SCHEMA_VERSION

/** Canonical verifier scope used by Evidence Studio ('0' = global scope). */
export const PROOF_PREPARATION_VERIFIER_SCOPE = '0'

export type ProofPreparationErrorCode =
  | 'MISSING_EVIDENCE'
  | 'UNSUPPORTED_TIER'
  | 'INVALID_PUBLIC_INPUTS'

export type ProofPreparationField = {
  key: string
  label: string
  /** Display value only — canonical field material or the redaction placeholder. */
  value: string
  disclosed: boolean
}

export type ProofPreparationPreviewOk = {
  ok: true
  version: typeof PROOF_PREPARATION_PREVIEW_VERSION
  tier: 'silent'
  policyId: string
  policyVersion: number
  publicInputs: ProofPreparationField[]
  concealedInputs: ProofPreparationField[]
  /** The preview never mutates state or submits anything. */
  readOnly: true
  transactionSubmission: 'none'
  summary: string
}

export type ProofPreparationPreviewErr = {
  ok: false
  code: ProofPreparationErrorCode
  /** Stable, privacy-safe operator message — never embeds evidence values. */
  message: string
}

export type ProofPreparationPreviewResult =
  | ProofPreparationPreviewOk
  | ProofPreparationPreviewErr

export type ProofPreparationPreviewInput = {
  proof: ProofPackage | null | undefined
  tier: IdentityTier
  /** Canonical verifier scope; defaults to the global scope. */
  verifierScope?: string
  /** Day-granular epoch; defaults to the current UTC day. */
  epoch?: number
}

const ERROR_MESSAGES: Record<ProofPreparationErrorCode, string> = {
  MISSING_EVIDENCE: 'Generate evidence to preview its canonical proof inputs.',
  UNSUPPORTED_TIER: 'This identity tier does not generate a zero-knowledge proof.',
  INVALID_PUBLIC_INPUTS: 'Canonical proof inputs are unavailable for this evidence.',
}

/** Public input order is the schema order, so the preview cannot reshuffle it. */
const PUBLIC_INPUT_LABELS: Record<string, string> = {
  video_hash_hi: 'Video hash · high 128 bits',
  video_hash_lo: 'Video hash · low 128 bits',
  verifier_scope: 'Verifier scope',
  epoch: 'Epoch',
}

/** Witness inputs are listed by name only; their values never enter the view model. */
const CONCEALED_INPUTS = [
  { key: 'credential_secret', label: 'Credential secret' },
  { key: 'nullifier_secret', label: 'Nullifier secret' },
] as const

function error(code: ProofPreparationErrorCode): ProofPreparationPreviewErr {
  return { ok: false, code, message: ERROR_MESSAGES[code] }
}

/**
 * Build the read-only proof preparation preview.
 *
 * Failure modes return stable codes and never echo hashes, scopes, secrets, or
 * witness material.
 */
export function buildProofPreparationPreview(
  input: ProofPreparationPreviewInput,
): ProofPreparationPreviewResult {
  if (input == null || typeof input !== 'object' || input.tier !== 'silent') {
    return error('UNSUPPORTED_TIER')
  }

  const proof = input.proof
  if (proof == null) return error('MISSING_EVIDENCE')

  let canonical
  try {
    canonical = canonicalSilentWitnessPublicInputs({
      videoHash: proof.videoHash,
      verifierScope: input.verifierScope ?? PROOF_PREPARATION_VERIFIER_SCOPE,
      epoch: input.epoch ?? silentWitnessEpoch(),
    })
  } catch {
    // Malformed hashes, non-canonical scopes and unsafe epochs fail closed.
    return error('INVALID_PUBLIC_INPUTS')
  }

  const publicInputs = Object.keys(canonical).map((key) => ({
    key,
    label: PUBLIC_INPUT_LABELS[key],
    value: canonical[key as keyof typeof canonical],
    disclosed: true,
  }))

  const concealedInputs = CONCEALED_INPUTS.map((field) => ({
    key: field.key,
    label: field.label,
    value: REDACTED_PLACEHOLDER,
    disclosed: false,
  }))

  return {
    ok: true,
    version: PROOF_PREPARATION_PREVIEW_VERSION,
    tier: 'silent',
    policyId: PROOF_PREPARATION_POLICY_ID,
    policyVersion: PROOF_PREPARATION_POLICY_VERSION,
    publicInputs,
    concealedInputs,
    readOnly: true,
    transactionSubmission: 'none',
    summary: `${publicInputs.length} canonical public inputs · ${concealedInputs.length} witness values concealed · read-only`,
  }
}

/** Stable operator message for an error code (used by UI and tests). */
export function proofPreparationErrorMessage(code: ProofPreparationErrorCode): string {
  return ERROR_MESSAGES[code]
}
