import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'

const MAX_AGGREGATION_SIZE = 8

type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
  proof: string
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

type GenerateSilentWitnessInput = {
  videoHash: string
  credentialSecret: string
  nullifierSecret: string
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

export async function generateSilentWitnessProof({
  videoHash,
  credentialSecret,
  nullifierSecret,
}: GenerateSilentWitnessInput): Promise<SilentWitnessProof> {
  const [helperCircuit, mainCircuit] = await Promise.all([loadHelperCircuit(), loadMainCircuit()])
  const video_hash_hi = BigInt(`0x${videoHash.slice(0, 32)}`).toString(10)
  const video_hash_lo = BigInt(`0x${videoHash.slice(32)}`).toString(10)
  const privateInputs = {
    credential_secret: credentialSecret,
    nullifier_secret: nullifierSecret,
    video_hash_hi,
    video_hash_lo,
  }

  const helperResult = await new Noir(helperCircuit).execute(privateInputs)
  const [credentialRoot, nullifier] = helperResult.returnValue as string[]
  const publicInputs = {
    credential_root: credentialRoot,
    nullifier,
  }

  const { witness } = await new Noir(mainCircuit).execute({
    ...privateInputs,
    ...publicInputs,
  })

  const backend = new UltraHonkBackend(mainCircuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proofHex = bytesToHex(proofData.proof)
    const publicInputHex = proofData.publicInputs.map(fieldToBytes32Hex).join('')

    return {
      credentialRoot: fieldToBytes32Hex(credentialRoot),
      nullifier: fieldToBytes32Hex(nullifier),
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
 * Generate a bounded aggregated proof for multiple video hashes under the
 * same credential identity.
 *
 * Uses the `silent_witness_aggregator` circuit which can bundle up to
 * ``MAX_AGGREGATION_SIZE`` (8) individual Silent Witness proofs into a
 * single UltraHonk proof.
 *
 * @throws {Error} If the batch size exceeds MAX_AGGREGATION_SIZE or if any
 *   video hash is invalid.
 */
export async function generateAggregatedProof({
  videoHashes,
  credentialSecret,
  nullifierSecret,
}: GenerateAggregatedProofInput): Promise<AggregatedProof> {
  const batchSize = videoHashes.length
  if (batchSize < 1 || batchSize > MAX_AGGREGATION_SIZE) {
    throw new Error(
      `Batch size must be between 1 and ${MAX_AGGREGATION_SIZE} (got ${batchSize})`
    )
  }

  for (const vh of videoHashes) {
    if (!/^[0-9a-fA-F]{64}$/.test(vh)) {
      throw new Error(`Invalid video hash: ${vh}`)
    }
  }

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
    const publicInputHex = proofData.publicInputs.map(fieldToBytes32Hex).join('')

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
  const response = await fetch(path)
  if (!response.ok) {
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

function fieldToBytes32Hex(value: string) {
  const normalized = value.startsWith('0x') ? value.slice(2) : BigInt(value).toString(16)
  if (normalized.length > 64) {
    throw new Error('Noir field is larger than 32 bytes.')
  }
  return normalized.padStart(64, '0')
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function sha256(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input)
  const hash = await crypto.subtle.digest('SHA-256', bytes)
  return bytesToHex(new Uint8Array(hash))
}
