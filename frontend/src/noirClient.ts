import { encodeFieldToBytes32Hex, encodePublicInputs } from './verifierInputs'
import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'

export type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
  /** Domain tag as a 32-byte hex string (no 0x prefix). */
  domainTag: string
  proof: string
  /** Hex-encoded public inputs: 5 × 32 bytes = 160 bytes (320 hex chars). */
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

export type GenerateSilentWitnessInput = {
  videoHash: string
  credentialSecret: string
  nullifierSecret: string
  /** Scope field element (BN254). Pass '0' for global/unscoped. */
  verifierScope?: string
  /** Epoch number. Pass 0 for unscoped or legacy proofs. */
  epoch?: number
}

/**
 * Explicit bounds enforced at the trust boundary (the browser prover).
 * Secret values are capped so a single request can never drive unbounded
 * work; the scope/epoch values mirror the contracts' scalar limits and keep
 * malformed inputs from reaching the WASM prover.
 */
export const PROOF_INPUT_BOUNDS = {
  maxSecretBytes: 256,
  maxEpoch: 0xffffffff,
  /** BN254 base field modulus — verifier_scope must fit in one field element. */
  frModulus: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n,
} as const

const HEX64 = /^[0-9a-fA-F]{64}$/

function assertBoundedInput(input: GenerateSilentWitnessInput): void {
  if (!HEX64.test(input.videoHash)) {
    throw new Error('videoHash must be a 64-character hex string.')
  }
  const credBytes = new TextEncoder().encode(input.credentialSecret).length
  const nullBytes = new TextEncoder().encode(input.nullifierSecret).length
  if (credBytes === 0 || nullBytes === 0) {
    throw new Error('credentialSecret and nullifierSecret are required.')
  }
  if (credBytes > PROOF_INPUT_BOUNDS.maxSecretBytes || nullBytes > PROOF_INPUT_BOUNDS.maxSecretBytes) {
    throw new Error('Secret input exceeds the maximum allowed size.')
  }
  let scopeField: bigint
  try {
    scopeField = BigInt(input.verifierScope ?? '0')
  } catch {
    throw new Error('verifierScope must be a decimal string.')
  }
  if (scopeField < 0n || scopeField >= PROOF_INPUT_BOUNDS.frModulus) {
    throw new Error('verifierScope must be a valid BN254 field element.')
  }
  const epoch = input.epoch ?? 0
  if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > PROOF_INPUT_BOUNDS.maxEpoch) {
    throw new Error('epoch must be a u32.')
  }
}

let helperCircuitPromise: Promise<CompiledCircuit> | null = null
let mainCircuitPromise: Promise<CompiledCircuit> | null = null

/**
 * Generate a Silent Witness Noir/UltraHonk proof.
 *
 * The helper circuit computes (credential_root, nullifier, domain_tag) from
 * the private inputs so the browser never needs to reproduce the Pedersen
 * hash in JavaScript.  domain_tag binds the proof to the Harpocrates protocol
 * version and network embedded in the circuit constants — a proof generated
 * for testnet will fail the in-circuit assert if submitted to a mainnet
 * verifier with different embedded constants.
 *
 * Errors are intentionally stable, human-readable strings that never contain
 * secret material, witness data, or user input.
 */
export async function generateSilentWitnessProof(
  input: GenerateSilentWitnessInput,
): Promise<SilentWitnessProof> {
  assertBoundedInput(input)
  const {
    videoHash,
    credentialSecret,
    nullifierSecret,
    verifierScope = '0',
    epoch = 0,
  } = input

  const [helperCircuit, mainCircuit] = await Promise.all([loadHelperCircuit(), loadMainCircuit()])

  const video_hash_hi = BigInt(`0x${videoHash.slice(0, 32)}`).toString(10)
  const video_hash_lo = BigInt(`0x${videoHash.slice(32)}`).toString(10)
  const scope_field = BigInt(verifierScope).toString(10)
  const epoch_field = BigInt(epoch).toString(10)
  const privateInputs = {
    credential_secret: credentialSecret,
    nullifier_secret: nullifierSecret,
    video_hash_hi,
    video_hash_lo,
    verifier_scope: scope_field,
    epoch: epoch_field,
  }

  // Helper returns (credential_root, nullifier, domain_tag).
  const helperResult = await new Noir(helperCircuit).execute(privateInputs)
  const [credentialRoot, nullifier, domainTag] = helperResult.returnValue as string[]

  const publicInputs = {
    credential_root: credentialRoot,
    nullifier,
    verifier_scope: scope_field,
    epoch: epoch_field,
  }

  const { witness } = await new Noir(mainCircuit).execute({
    ...privateInputs,
    ...publicInputs,
  })

  const backend = new UltraHonkBackend(mainCircuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proofHex = bytesToHex(proofData.proof)

    // Public inputs in on-chain ordering:
    //   [0] video_hash_hi, [1] video_hash_lo, [2] credential_root,
    //   [3] nullifier,     [4] domain_tag
    const publicInputHex = encodePublicInputs(proofData.publicInputs, [
      'video_hash_hi',
      'video_hash_lo',
      'credential_root',
      'nullifier',
      'domain_tag',
    ])
    return {
      credentialRoot: encodeFieldToBytes32Hex(credentialRoot, 'credential_root'),
      nullifier: encodeFieldToBytes32Hex(nullifier, 'nullifier'),
      domainTag: encodeFieldToBytes32Hex(domainTag, 'domain_tag'),
      proof: proofHex,
      publicInputs: publicInputHex,
      proofBytes: proofData.proof.length,
      publicInputBytes: publicInputHex.length / 2,
    }
  } finally {
    await backend.destroy()
  }
}

async function loadHelperCircuit() {
  helperCircuitPromise ??= loadCircuit('/noir/silent_witness_helper.json')
  return helperCircuitPromise
}

async function loadMainCircuit() {
  mainCircuitPromise ??= loadCircuit('/noir/silent_witness.json')
  return mainCircuitPromise
}

async function loadCircuit(path: string) {
  const response = await fetch(path, { cache: 'no-store' }) // cache prohibition
  if (!response.ok) {
    throw new Error('Unable to load the Noir circuit artifact required for proof generation.')
  }
  return (await response.json()) as CompiledCircuit
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}