import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'
import { encodeFieldToBytes32Hex, encodePublicInputs } from './verifierInputs'
import { assertArtifactPair, assertProofOutput, CircuitInputError, prepareSilentWitnessInputs, PUBLIC_FRAMES } from './circuitInputSchema'
import type { SilentWitnessInput } from './circuitInputSchema'

const MAX_AGGREGATION_SIZE = 8

type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
  /** Domain tag as a 32-byte hex string (no 0x prefix). */
  domainTag: string
  proof: string
  /** Hex-encoded verifier frame: five unscoped or seven scoped fields. */
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

type AggregatedProof = {
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

type GenerateAggregatedProofInput = {
  videoHashes: string[]
  credentialSecret: string
  nullifierSecret: string
}

let helperCircuitPromise: Promise<CompiledCircuit> | null = null
let mainCircuitPromise: Promise<CompiledCircuit> | null = null
let aggregatorCircuitPromise: Promise<CompiledCircuit> | null = null
let aggregatorHelperCircuitPromise: Promise<CompiledCircuit> | null = null

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
export async function generateSilentWitnessProof(input: SilentWitnessInput): Promise<SilentWitnessProof> {
  const prepared = prepareSilentWitnessInputs(input)
  try {
    const [helperCircuit, mainCircuit] = await Promise.all([loadHelperCircuit(), loadMainCircuit()])
    const frame = assertArtifactPair(helperCircuit, mainCircuit)
    if (frame === 'unscoped_v1' && (prepared.verifier_scope !== '0' || prepared.epoch !== '0')) {
      throw new CircuitInputError('unsupported_input_schema')
    }

    const helperInputs = frame === 'scoped_v2' ? prepared : {
      credential_secret: prepared.credential_secret,
      nullifier_secret: prepared.nullifier_secret,
      video_hash_hi: prepared.video_hash_hi,
      video_hash_lo: prepared.video_hash_lo,
    }
    const helperResult = await new Noir(helperCircuit).execute(helperInputs)
    const returned = helperResult.returnValue
    if (!Array.isArray(returned) || returned.length !== 3) {
      throw new CircuitInputError('invalid_proof_output')
    }
    const [credentialRoot, nullifier, domainTag] = returned as string[]
    const { witness } = await new Noir(mainCircuit).execute({
      ...helperInputs,
      credential_root: credentialRoot,
      nullifier,
      domain_tag: domainTag,
    })

    const backend = new UltraHonkBackend(mainCircuit.bytecode)
    try {
      const proofData = await backend.generateProof(witness, { keccak: true })
      assertProofOutput(proofData.proof.length, proofData.publicInputs, {
        video_hash_hi: prepared.video_hash_hi,
        video_hash_lo: prepared.video_hash_lo,
        credential_root: credentialRoot,
        nullifier,
        verifier_scope: prepared.verifier_scope,
        epoch: prepared.epoch,
        domain_tag: domainTag,
      }, frame)
      const publicInputHex = encodePublicInputs(proofData.publicInputs, PUBLIC_FRAMES[frame])
      return {
        credentialRoot: encodeFieldToBytes32Hex(credentialRoot, 'credential_root'),
        nullifier: encodeFieldToBytes32Hex(nullifier, 'nullifier'),
        domainTag: encodeFieldToBytes32Hex(domainTag, 'domain_tag'),
        proof: bytesToHex(proofData.proof),
        publicInputs: publicInputHex,
        proofBytes: proofData.proof.length,
        publicInputBytes: publicInputHex.length / 2,
      }
    } finally {
      await backend.destroy()
    }
  } catch (error) {
    if (error instanceof CircuitInputError) throw error
    throw new CircuitInputError('proof_generation_failed')
  }
}

export async function generateAggregatedProof({
  videoHashes,
  credentialSecret,
  nullifierSecret,
}: GenerateAggregatedProofInput): Promise<AggregatedProof> {
  if (!Array.isArray(videoHashes)) throw new CircuitInputError('invalid_input')
  const batchSize = videoHashes.length
  if (batchSize < 1 || batchSize > MAX_AGGREGATION_SIZE) {
    throw new CircuitInputError('invalid_input')
  }

  for (const vh of videoHashes) {
    prepareSilentWitnessInputs({ videoHash: vh, credentialSecret, nullifierSecret })
  }

  try {
    const [helperCircuit, aggCircuit] = await Promise.all([
      loadAggregatorHelperCircuit(),
      loadAggregatorCircuit(),
    ])

    // Build helper circuit inputs
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

    // Run helper circuit to derive batch public inputs
    const helperResult = await new Noir(helperCircuit).execute(helperInputs)
    const batchResults = helperResult.returnValue as [string, string][]

    // Build aggregator circuit inputs
    const aggInputs: Record<string, string> = {
      credential_secret: credentialSecret,
      nullifier_secret: nullifierSecret,
    }
    for (let i = 0; i < MAX_AGGREGATION_SIZE; i++) {
      const vh = i < batchSize ? videoHashes[i] : '0000000000000000000000000000000000000000000000000000000000000000'
      const credentialRoot = batchResults[i][0]
      const nullifier = batchResults[i][1]

      aggInputs[`video_hash_hi_${i}`] = BigInt(`0x${vh.slice(0, 32)}`).toString(10)
      aggInputs[`video_hash_lo_${i}`] = BigInt(`0x${vh.slice(32)}`).toString(10)
      aggInputs[`credential_root_${i}`] = credentialRoot
      aggInputs[`nullifier_${i}`] = nullifier
    }

    // Generate the aggregated UltraHonk proof
    const { witness } = await new Noir(aggCircuit).execute(aggInputs)

    const backend = new UltraHonkBackend(aggCircuit.bytecode)
    try {
      const proofData = await backend.generateProof(witness, { keccak: true })
      const proofHex = bytesToHex(proofData.proof)
      const publicInputHex = encodePublicInputs(proofData.publicInputs)

      // Generate deterministic batch ID from the video hashes
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
  } catch (error) {
    if (error instanceof CircuitInputError) throw error
    throw new CircuitInputError('proof_generation_failed')
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

async function loadAggregatorCircuit() {
  aggregatorCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator.json')
  return aggregatorCircuitPromise
}

async function loadAggregatorHelperCircuit() {
  aggregatorHelperCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator_helper.json')
  return aggregatorHelperCircuitPromise
}

async function loadCircuit(path: string) {
  try {
    const response = await fetch(path, { cache: 'no-store' })
    if (!response.ok) throw new CircuitInputError('circuit_load_failed')
    return (await response.json()) as CompiledCircuit
  } catch {
    throw new CircuitInputError('circuit_load_failed')
  }
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function sha256(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input)
  const hash = await crypto.subtle.digest('SHA-256', bytes)
  return bytesToHex(new Uint8Array(hash))
}
