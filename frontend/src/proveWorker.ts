import { generateSilentWitnessProof } from './noirClient'
import { CircuitInputError } from './circuitInputSchema'
import type { SilentWitnessInput } from './circuitInputSchema'

// Legacy worker entry point uses the same versioned proving boundary.
self.addEventListener('message', async (event: MessageEvent<SilentWitnessInput>) => {
  try {
    const proof = await generateSilentWitnessProof(event.data)
    self.postMessage({ type: 'success', proof })
  } catch (error) {
    self.postMessage({
      type: 'error',
      message: error instanceof CircuitInputError ? error.code : 'proof_generation_failed',
    })
  }
})
