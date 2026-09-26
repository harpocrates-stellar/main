import schema from '../../zk/noir/circuit_input_schema_v1.json'
import type { CompiledCircuit } from '@noir-lang/types'

export const CIRCUIT_INPUT_SCHEMA_VERSION = 1
export const BN254_FIELD_MODULUS = BigInt(schema.field_modulus)

export type SilentWitnessInput = {
  videoHash: string
  credentialSecret: string
  nullifierSecret: string
  inputSchemaVersion?: number
  verifierScope?: string
  epoch?: number
}

export type CircuitInputErrorCode =
  | 'invalid_input'
  | 'unsupported_input_schema'
  | 'artifact_mismatch'
  | 'invalid_proof_output'
  | 'circuit_load_failed'
  | 'proof_generation_failed'

/** Error messages are fixed codes and never include witness or proof material. */
export class CircuitInputError extends Error {
  readonly code: CircuitInputErrorCode

  constructor(code: CircuitInputErrorCode) {
    super(code)
    this.name = 'CircuitInputError'
    this.code = code
  }
}

function normalizeInputField(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 80 ||
      !/^(?:0|[1-9][0-9]*|0[xX][0-9a-fA-F]+)$/.test(value)) return null
  const field = BigInt(value)
  return field < BN254_FIELD_MODULUS ? field.toString(10) : null
}

function proofField(value: unknown): bigint | null {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*|0[xX][0-9a-fA-F]+)$/.test(value) || value.length > 80) {
    return null
  }
  const field = BigInt(value)
  return field < BN254_FIELD_MODULUS ? field : null
}

export function prepareSilentWitnessInputs(input: SilentWitnessInput) {
  if (!input || typeof input !== 'object') throw new CircuitInputError('invalid_input')
  if (input.inputSchemaVersion !== undefined && input.inputSchemaVersion !== CIRCUIT_INPUT_SCHEMA_VERSION) {
    throw new CircuitInputError('unsupported_input_schema')
  }
  const credential = normalizeInputField(input.credentialSecret)
  const nullifier = normalizeInputField(input.nullifierSecret)
  const scope = normalizeInputField(input.verifierScope ?? '0')
  if (typeof input.videoHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(input.videoHash) ||
      credential === null || nullifier === null || scope === null ||
      !Number.isSafeInteger(input.epoch ?? 0) || (input.epoch ?? 0) < 0) {
    throw new CircuitInputError('invalid_input')
  }

  return {
    credential_secret: credential,
    nullifier_secret: nullifier,
    video_hash_hi: BigInt(`0x${input.videoHash.slice(0, 32)}`).toString(10),
    video_hash_lo: BigInt(`0x${input.videoHash.slice(32)}`).toString(10),
    verifier_scope: scope,
    epoch: String(input.epoch ?? 0),
  }
}

export type PublicFrame = 'browser_v1' | 'unscoped_v1' | 'scoped_v2'

async function bytecodeDigest(bytecode: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bytecode))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/** The published four-field browser artifact has its own pinned frame. */
export async function assertArtifactPair(helper: CompiledCircuit, main: CompiledCircuit): Promise<PublicFrame> {
  const matches = (artifact: CompiledCircuit, names: string[], publicStart: number) => {
    const actual = artifact?.abi?.parameters
    const version = (artifact as CompiledCircuit & { noir_version?: string })?.noir_version
    return typeof artifact?.bytecode === 'string' && artifact.bytecode.length > 0 &&
      version?.startsWith(`${schema.noir_version}+`) && Array.isArray(actual) &&
      actual.length === names.length && actual.every((parameter, index) =>
        parameter.name === names[index] && parameter.type?.kind === 'field' &&
        parameter.visibility === (index < publicStart ? 'private' : 'public'))
  }

  for (const frame of ['browser_v1', 'unscoped_v1', 'scoped_v2'] as const) {
    const abi = schema.artifact_abis[frame]
    const returns = helper?.abi?.return_type
    if (matches(helper, abi.helper_parameters, abi.helper_parameters.length) &&
        matches(main, abi.main_parameters, 2) &&
        returns?.visibility === 'public' && returns.abi_type.kind === 'tuple' &&
        returns.abi_type.fields.length === abi.helper_return_fields &&
        returns.abi_type.fields.every((field) => field.kind === 'field') &&
        main.abi.return_type === null) {
      if (frame === 'browser_v1') {
        const pinned = schema.artifact_abis.browser_v1
        try {
          if (await bytecodeDigest(helper.bytecode) !== pinned.helper_bytecode_sha256 ||
              await bytecodeDigest(main.bytecode) !== pinned.main_bytecode_sha256) {
            throw new CircuitInputError('artifact_mismatch')
          }
        } catch {
          throw new CircuitInputError('artifact_mismatch')
        }
      }
      return frame
    }
  }
  throw new CircuitInputError('artifact_mismatch')
}

/** Check length, ordering, and values before handing a proof to a verifier. */
export function assertProofOutput(
  proofBytes: number,
  publicInputs: string[],
  expected: Record<string, string>,
  frame: PublicFrame,
): void {
  const fields = schema.public_frames[frame]
  if (!Number.isSafeInteger(proofBytes) || proofBytes < schema.proof_bytes.min ||
      proofBytes > schema.proof_bytes.max || !Array.isArray(publicInputs) ||
      publicInputs.length !== fields.length) {
    throw new CircuitInputError('invalid_proof_output')
  }
  try {
    for (let i = 0; i < fields.length; i += 1) {
      const actual = publicInputs[i]
      const wanted = expected[fields[i]]
      const actualField = proofField(actual)
      const expectedField = proofField(wanted)
      if (actualField === null || expectedField === null || actualField !== expectedField) {
        throw new CircuitInputError('invalid_proof_output')
      }
    }
  } catch {
    throw new CircuitInputError('invalid_proof_output')
  }
}

export const PUBLIC_FRAMES = schema.public_frames
