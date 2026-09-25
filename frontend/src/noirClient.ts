import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'

import {
  checkAggregationBatchSize,
  encodeFieldToBytes32Hex,
  encodePublicInputs,
  MAX_AGGREGATION_SIZE,
  MIN_AGGREGATION_SIZE,
} from './verifierInputs'

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

export type GenerateSilentWitnessInput = {
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
let aggregatorCircuitPromise: Promise<CompiledCircuit> | null = null
let aggregatorHelperCircuitPromise: Promise<CompiledCircuit> | null = null

async function loadCircuit(path: string): Promise<CompiledCircuit> {
  const response = await fetch(path, { cache: 'no-store' })
  if (!response.ok) {
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

async function loadHelperCircuit(): Promise<CompiledCircuit> {
  helperCircuitPromise ??= loadCircuit('/noir/silent_witness_helper.json')
  return helperCircuitPromise
}

async function loadMainCircuit(): Promise<CompiledCircuit> {
  mainCircuitPromise ??= loadCircuit('/noir/silent_witness.json')
  return mainCircuitPromise
}

async function loadAggregatorCircuit(): Promise<CompiledCircuit> {
  aggregatorCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator.json')
  return aggregatorCircuitPromise
}

async function loadAggregatorHelperCircuit(): Promise<CompiledCircuit> {
  aggregatorHelperCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator_helper.json')
  return aggregatorHelperCircuitPromise
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * Generate a Silent Witness Noir/UltraHonk proof.
 *
 * The helper circuit computes (credential_root, nullifier, domain_tag) from
 * the private inputs so the browser never needs to reproduce the Pedersen
 * hash in JavaScript.  domain_tag binds the proof to the Harpocrates protocol
 * version and network embedded in the circuit constants — a proof generated
 * for testnet will fail the in-circuit assert if submitted to a mainnet
 * verifier with different embedded constants.
 */
export async function generateSilentWitnessProof({
  videoHash,
  credentialSecret,
  nullifierSecret,
  verifierScope = '0',
  epoch = 0,
}: GenerateSilentWitnessInput): Promise<SilentWitnessProof> {
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

/**
 * Generate a bounded aggregated proof for multiple video hashes.
 *
 * Uses the Silent Witness Aggregator circuit to produce a single
 * UltraHonk proof covering up to `MAX_AGGREGATION_SIZE` (8) video
 * hashes under the same credential identity.
 */
export async function generateAggregatedProof({
  videoHashes,
  credentialSecret,
  nullifierSecret,
}: GenerateAggregatedProofInput): Promise<AggregatedProof> {
  const batchSize = checkAggregationBatchSize(videoHashes.length)

  const [aggregatorHelperCircuit, aggregatorCircuit] = await Promise.all([
    loadAggregatorHelperCircuit(),
    loadAggregatorCircuit(),
  ])

  // Prepare input limbs for all MAX_AGGREGATION_SIZE (8) elements
  const helperInputs: Record<string, string> = {
    credential_secret: credentialSecret,
    nullifier_secret: nullifierSecret,
  }

  for (let i = 0; i < MAX_AGGREGATION_SIZE; i++) {
    if (i < batchSize) {
      const vh = videoHashes[i]
      helperInputs[`video_hash_hi_${i}`] = BigInt(`0x${vh.slice(0, 32)}`).toString(10)
      helperInputs[`video_hash_lo_${i}`] = BigInt(`0x${vh.slice(32)}`).toString(10)
    } else {
      helperInputs[`video_hash_hi_${i}`] = '0'
      helperInputs[`video_hash_lo_${i}`] = '0'
    }
  }

  // Execute aggregator helper to derive (credential_root, nullifier) pairs
  const helperResult = await new Noir(aggregatorHelperCircuit).execute(helperInputs)
  const returnPairs = helperResult.returnValue as Array<[string, string]>

  // Prepare aggregator circuit inputs
  const circuitInputs: Record<string, string> = {
    credential_secret: credentialSecret,
    nullifier_secret: nullifierSecret,
  }

  for (let i = 0; i < MAX_AGGREGATION_SIZE; i++) {
    circuitInputs[`video_hash_hi_${i}`] = helperInputs[`video_hash_hi_${i}`]
    circuitInputs[`video_hash_lo_${i}`] = helperInputs[`video_hash_lo_${i}`]
    circuitInputs[`credential_root_${i}`] = returnPairs[i][0]
    circuitInputs[`nullifier_${i}`] = returnPairs[i][1]
  }

  const { witness } = await new Noir(aggregatorCircuit).execute(circuitInputs)
  const backend = new UltraHonkBackend(aggregatorCircuit.bytecode)

  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proofHex = bytesToHex(proofData.proof)

    // Public inputs for the aggregator: 8 elements * 4 public fields = 32 public inputs
    const publicFieldNames: string[] = []
    for (let i = 0; i < MAX_AGGREGATION_SIZE; i++) {
      publicFieldNames.push(
        `video_hash_hi_${i}`,
        `video_hash_lo_${i}`,
        `credential_root_${i}`,
        `nullifier_${i}`,
      )
    }

    const publicInputHex = encodePublicInputs(proofData.publicInputs, publicFieldNames)
    const batchId = await sha256(videoHashes.join(':'))

    return {
      protocol: 'harpocrates',
      version: 1,
      type: 'aggregated_batch',
      batchId,
      batchSize,
      maxBatchSize: MAX_AGGREGATION_SIZE,
      videoHashes: videoHashes.map((vh) => vh.toLowerCase()),
      proof: proofHex,
      publicInputs: publicInputHex,
      proofBytes: proofData.proof.length,
      publicInputBytes: publicInputHex.length / 2,
    }
  } finally {
    await backend.destroy()
  }
}

async function sha256(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input)
  const hash = await crypto.subtle.digest('SHA-256', bytes)
  return bytesToHex(new Uint8Array(hash))
}
