import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'

import { encodeFieldToBytes32Hex, encodePublicInputs } from './verifierInputs'

type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
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

let helperCircuitPromise: Promise<CompiledCircuit> | null = null
let mainCircuitPromise: Promise<CompiledCircuit> | null = null

self.addEventListener('message', async (event: MessageEvent<GenerateSilentWitnessInput>) => {
  const { videoHash, credentialSecret, nullifierSecret } = event.data

  try {
    const proof = await generateSilentWitnessProof({ videoHash, credentialSecret, nullifierSecret })
    self.postMessage({ type: 'success', proof })
  } catch (error) {
    self.postMessage({
      type: 'error',
      message: error instanceof Error ? error.message : 'Unknown error during proof generation',
    })
  }
})

async function generateSilentWitnessProof({
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
  const [credentialRoot, nullifier, domainTag] = helperResult.returnValue as string[]
  const publicInputs = {
    credential_root: credentialRoot,
    nullifier,
    verifier_scope: '0',
    epoch: '0',
    domain_tag: domainTag,
    // Circuit version committed to the proof envelope (#368). Must equal
    // CURRENT_CIRCUIT_VERSION in zk/noir/silent_witness/src/main.nr.
    circuit_version: '2',
  }

  const { witness } = await new Noir(mainCircuit).execute({
    ...privateInputs,
    ...publicInputs,
  })

  const backend = new UltraHonkBackend(mainCircuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proofHex = bytesToHex(proofData.proof)
    const publicInputHex = encodePublicInputs(proofData.publicInputs, [
      'video_hash_hi',
      'video_hash_lo',
      'credential_root',
      'nullifier',
      'verifier_scope',
      'epoch',
      'domain_tag',
      'circuit_version',
    ])

    return {
      credentialRoot: encodeFieldToBytes32Hex(credentialRoot, 'credential_root'),
      nullifier: encodeFieldToBytes32Hex(nullifier, 'nullifier'),
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
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
