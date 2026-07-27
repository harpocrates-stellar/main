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
  /** Scope field element (BN254). Pass '0' for global/unscoped. */
  verifierScope?: string
  /** Epoch number. Pass 0 for unscoped or legacy proofs. */
  epoch?: number
}

let helperCircuitPromise: Promise<CompiledCircuit> | null = null
let mainCircuitPromise: Promise<CompiledCircuit> | null = null

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

  const helperResult = await new Noir(helperCircuit).execute(privateInputs)
  const [credentialRoot, nullifier] = helperResult.returnValue as string[]
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
    const publicInputHex = proofData.publicInputs.map(fieldToBytes32Hex).join('')

    return {
      credentialRoot: fieldToBytes32Hex(credentialRoot),
      nullifier: fieldToBytes32Hex(nullifier),
      proof: proofHex,
      publicInputs: publicInputHex,
      proofBytes: proofData.proof.length,
      publicInputBytes: publicInputHex.length / 2,
    }

    if (signal?.aborted) {
      onAbort()
      return
    }

    signal?.addEventListener('abort', onAbort)

    worker.addEventListener('message', (event) => {
      signal?.removeEventListener('abort', onAbort)
      worker.terminate() // Forceful explicit memory clearing immediately upon completion.
      
      const { type, proof, message } = event.data
      if (type === 'success') {
        resolve(proof as SilentWitnessProof)
      } else {
        reject(new Error(message || 'Worker proof generation failed.'))
      }
    })

    worker.addEventListener('error', (error) => {
      signal?.removeEventListener('abort', onAbort)
      worker.terminate()
      reject(new Error(`Worker execution failed: ${error.message}`))
    })

    worker.postMessage(input)
  })
}
