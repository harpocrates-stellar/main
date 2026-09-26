import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'
import { encodeFieldToBytes32Hex, encodePublicInputs } from './verifierInputs'
import { throwIfAborted } from './utils'

type SilentWitnessProof = {
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

export type AggregatedProof = {
  protocol: string
  version: number
  type: string
  batchId: string
  batchSize: number
  maxBatchSize: number
  videoHashes: string[]
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

type GenerateSilentWitnessInput = {
  videoHash: string
  credentialSecret: string
  nullifierSecret: string
  /** Scope field element (BN254). Pass '0' for global/unscoped. */
  verifierScope?: string
  /** Epoch number. Pass 0 for unscoped or legacy proofs. */
  epoch?: number
}

export type GenerateAggregatedProofInput = {
  videoHashes: string[]
  credentialSecret: string
  nullifierSecret: string
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
 * When `signal` is provided the flow is checked cooperatively between phases
 * so a cancelled run stops before the next expensive step. The studio runs
 * this function inside the cancellable module worker
 * (see workers/proofWorker.ts and workers/proofWorkerClient.ts); it must not
 * be invoked on the UI thread with witnesses in scope.
 */
export async function generateSilentWitnessProof({
  videoHash,
  credentialSecret,
  nullifierSecret,
  verifierScope = '0',
  epoch = 0,
}: GenerateSilentWitnessInput, signal?: AbortSignal): Promise<SilentWitnessProof> {
  throwIfAborted(signal)
  const [helperCircuit, mainCircuit] = await Promise.all([loadHelperCircuit(), loadMainCircuit()])
  throwIfAborted(signal)

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
  throwIfAborted(signal)
  const [credentialRoot, nullifier, domainTag] = helperResult.returnValue as string[]

  const publicInputs = {
    credential_root: credentialRoot,
    nullifier,
    verifier_scope: scope_field,
    epoch: epoch_field,
  }

  throwIfAborted(signal)
  const { witness } = await new Noir(mainCircuit).execute({
    ...privateInputs,
    ...publicInputs,
  })
  throwIfAborted(signal)

  const backend = new UltraHonkBackend(mainCircuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    throwIfAborted(signal)
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

export async function sha256(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input)
  const hash = await crypto.subtle.digest('SHA-256', bytes)
  return bytesToHex(new Uint8Array(hash))
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
  const response = await fetch(path, { cache: 'no-store' })
  if (!response.ok) {
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
