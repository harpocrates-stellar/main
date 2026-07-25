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

export async function generateSilentWitnessProof(
  input: GenerateSilentWitnessInput,
  signal?: AbortSignal,
): Promise<SilentWitnessProof> {
  return new Promise((resolve, reject) => {
    // Spawn an isolated Web Worker to run the heavy proof logic.
    // This provides explicit ownership over the memory isolate, which
    // allows us to mitigate secret lifetimes by forcefully terminating the worker.
    const worker = new Worker(new URL('./proveWorker.ts', import.meta.url), {
      type: 'module',
    })

    const onAbort = () => {
      worker.terminate() // Hardware-level reclaim of memory.
      reject(new Error('Proof generation was cancelled or timed out.'))
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
