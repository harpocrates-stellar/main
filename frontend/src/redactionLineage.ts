import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'

import type { TransformationManifest } from './lineageManifest'
import {
  REDACTION_WITNESS_DOMAIN_TAG_HEX,
  SCHEMA_REDACTION_WITNESS,
  parseRedactionWitnessInputs,
} from './verifierInputs'

const MAX_CHUNKS = 4
const REPLAY_DOMAIN = 'harpocrates:redaction-lineage:v1:'
const BN254_SCALAR_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

const OPERATION_CODES: Record<TransformationManifest['operationType'], string> = {
  crop: '1',
  transcode: '2',
  blur: '3',
  redact: '4',
  compose: '5',
}

export type RedactionLineagePrivateWitness = {
  parentChunks: readonly string[]
  visibleChunks: readonly string[]
  removedDescriptors: readonly string[]
  parametersDigest: string
  blindingFactor: string
}

export type RedactionLineageProof = {
  schema: typeof SCHEMA_REDACTION_WITNESS
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

let circuitPromise: Promise<CompiledCircuit> | null = null

/** Canonical claim binding shared with ``backend.lineage``. */
export async function redactionReplayBinding(manifest: TransformationManifest): Promise<string> {
  const canonical = JSON.stringify(manifest, Object.keys(manifest).sort())
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`${REPLAY_DOMAIN}${canonical}`),
  )
  let value = 0n
  for (const byte of new Uint8Array(digest)) value = (value << 8n) | BigInt(byte)
  return (value % BN254_SCALAR_FIELD_MODULUS).toString(10)
}

/**
 * Generate and locally verify a bounded redaction-lineage proof.
 *
 * The caller owns the witness and must keep it out of persistence and logs.
 * A cancelled request is checked before and after proving; bb.js itself cannot
 * be interrupted mid-proof, so callers should terminate their worker to make
 * cancellation immediate.
 */
export async function generateRedactionLineageProof(
  manifest: TransformationManifest,
  privateWitness: RedactionLineagePrivateWitness,
  publicCommitments: { parentCommitment: string; outputCommitment: string },
  signal?: AbortSignal,
): Promise<RedactionLineageProof> {
  ensureWitnessShape(privateWitness)
  throwIfAborted(signal)

  const replayBinding = await redactionReplayBinding(manifest)
  const circuit = await loadCircuit()
  throwIfAborted(signal)
  const publicInputs = {
    parent_commitment: publicCommitments.parentCommitment,
    output_commitment: publicCommitments.outputCommitment,
    operation_type: OPERATION_CODES[manifest.operationType],
    replay_binding: replayBinding,
    domain_tag: BigInt(`0x${REDACTION_WITNESS_DOMAIN_TAG_HEX}`).toString(10),
  }

  const privateInputs = {
    parent_chunks: [...privateWitness.parentChunks],
    visible_chunks: [...privateWitness.visibleChunks],
    removed_descriptors: [...privateWitness.removedDescriptors],
    parameters_digest: privateWitness.parametersDigest,
    blinding_factor: privateWitness.blindingFactor,
  }

  const backend = new UltraHonkBackend(circuit.bytecode)
  try {
    const { witness } = await new Noir(circuit).execute({ ...privateInputs, ...publicInputs })
    throwIfAborted(signal)
    const proofData = await backend.generateProof(witness, { keccak: true })
    const verified = await backend.verifyProof(proofData, { keccak: true })
    if (!verified) throw new Error('Local redaction-lineage proof verification failed.')

    const publicInputHex = proofData.publicInputs.map(fieldToBytes32Hex).join('')
    // Reject a malformed artifact or accidental public-input ordering drift
    // before anything may be submitted to a backend or registry.
    parseRedactionWitnessInputs(hexToBytes(publicInputHex))
    return {
      schema: SCHEMA_REDACTION_WITNESS,
      proof: bytesToHex(proofData.proof),
      publicInputs: publicInputHex,
      proofBytes: proofData.proof.length,
      publicInputBytes: publicInputHex.length / 2,
    }
  } finally {
    await backend.destroy()
    // Drop references promptly. JavaScript cannot guarantee physical memory
    // zeroization for strings, so worker callers should use transferable
    // buffers for sensitive source material.
    privateInputs.parent_chunks.fill('0')
    privateInputs.visible_chunks.fill('0')
    privateInputs.removed_descriptors.fill('0')
    privateInputs.parameters_digest = '0'
    privateInputs.blinding_factor = '0'
  }
}

function ensureWitnessShape(witness: RedactionLineagePrivateWitness): void {
  for (const values of [witness.parentChunks, witness.visibleChunks, witness.removedDescriptors]) {
    if (values.length !== MAX_CHUNKS) throw new Error(`Redaction lineage requires exactly ${MAX_CHUNKS} chunks.`)
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('Redaction proof generation cancelled.', 'AbortError')
}

async function loadCircuit(): Promise<CompiledCircuit> {
  circuitPromise ??= (async () => {
    const response = await fetch('/noir/redaction_lineage.json', { cache: 'no-store' })
    if (!response.ok) throw new Error('Redaction-lineage circuit artifact is unavailable.')
    return (await response.json()) as CompiledCircuit
  })()
  return circuitPromise
}

function fieldToBytes32Hex(value: string): string {
  const normalized = value.startsWith('0x') ? value.slice(2) : BigInt(value).toString(16)
  if (normalized.length > 64) throw new Error('Noir field is larger than 32 bytes.')
  return normalized.padStart(64, '0')
}

function hexToBytes(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2)
  for (let index = 0; index < out.length; index += 1) out[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
