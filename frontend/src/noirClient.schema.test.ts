import { afterEach, describe, expect, it, vi } from 'vitest'
import helper from '../public/noir/silent_witness_helper.json'
import main from '../public/noir/silent_witness.json'
import { CircuitInputError } from './circuitInputSchema'
import { generateAggregatedProof, generateSilentWitnessProof } from './noirClient'

const input = {
  videoHash: '11'.repeat(16) + '22'.repeat(16),
  credentialSecret: '12345',
  nullifierSecret: '67890',
}

afterEach(() => vi.unstubAllGlobals())

describe('versioned browser proving boundary', () => {
  it('rejects the stale four-field browser artifacts before execution', async () => {
    const fetchArtifact = vi.fn(async (path: string) => ({
      ok: true,
      json: async () => path.includes('helper') ? helper : main,
    }))
    vi.stubGlobal('fetch', fetchArtifact)

    await expect(generateSilentWitnessProof(input)).rejects.toThrowError(
      new CircuitInputError('artifact_mismatch'),
    )
    expect(fetchArtifact).toHaveBeenCalledTimes(2)
  })

  it('rejects invalid aggregation input without fetching or echoing it', async () => {
    const fetchArtifact = vi.fn()
    vi.stubGlobal('fetch', fetchArtifact)
    const secret = 'private-value'
    const invalidHash = 'private-hash-value'
    try {
      await generateAggregatedProof({
        videoHashes: [invalidHash],
        credentialSecret: secret,
        nullifierSecret: '67890',
      })
      throw new Error('expected rejection')
    } catch (error) {
      expect(error).toBeInstanceOf(CircuitInputError)
      expect((error as Error).message).toBe('invalid_input')
      expect((error as Error).message).not.toContain(secret)
      expect((error as Error).message).not.toContain(invalidHash)
    }
    expect(fetchArtifact).not.toHaveBeenCalled()
  })
})
