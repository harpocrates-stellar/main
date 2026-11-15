import { afterEach, describe, expect, it, vi } from 'vitest'
import type { CompiledCircuit, InputMap } from '@noir-lang/types'
import helper from '../public/noir/silent_witness_helper.json'
import main from '../public/noir/silent_witness.json'
import { CircuitInputError } from './circuitInputSchema'

const { capturedMainInputs } = vi.hoisted(() => ({
  capturedMainInputs: { current: null as Record<string, string> | null },
}))

vi.mock('@noir-lang/noir_js', async () => {
  const actual = await vi.importActual<typeof import('@noir-lang/noir_js')>('@noir-lang/noir_js')
  class SpiedNoir extends actual.Noir {
    constructor(circuit: CompiledCircuit) {
      super(circuit)
    }
    override async execute(inputs: InputMap) {
      if ('credential_root' in inputs && 'nullifier' in inputs) {
        capturedMainInputs.current = inputs as Record<string, string>
      }
      return super.execute(inputs)
    }
  }
  return { ...actual, Noir: SpiedNoir }
})

vi.mock('@aztec/bb.js', () => ({
  UltraHonkBackend: class MockUltraHonkBackend {
    async generateProof() {
      const recorded = capturedMainInputs.current
      if (!recorded) {
        throw new Error('missing main circuit witness inputs')
      }
      const toFieldHex = (val: string) => `0x${BigInt(val).toString(16).padStart(64, '0')}`
      return {
        proof: new Uint8Array(14080).fill(0xab),
        publicInputs: [
          toFieldHex(recorded.video_hash_hi),
          toFieldHex(recorded.video_hash_lo),
          toFieldHex(recorded.credential_root),
          toFieldHex(recorded.nullifier),
        ],
      }
    }
    async destroy() {}
  },
}))

import { generateAggregatedProof, generateSilentWitnessProof } from './noirClient'

const realFetch = globalThis.fetch

const input = {
  videoHash: '11'.repeat(16) + '22'.repeat(16),
  credentialSecret: '12345',
  nullifierSecret: '67890',
}

afterEach(() => vi.unstubAllGlobals())

describe('versioned browser proving boundary', () => {
  it('rejects scope inputs that the published four-field artifact cannot bind', async () => {
    const fetchArtifact = vi.fn(async (url: string | URL | Request) => {
      const path = String(url)
      if (!path.includes('/noir/')) return realFetch(url)
      return {
        ok: true,
        json: async () => path.includes('helper') ? helper : main,
      }
    })
    vi.stubGlobal('fetch', fetchArtifact)

    await expect(generateSilentWitnessProof({ ...input, verifierScope: '7' })).rejects.toThrowError(
      new CircuitInputError('unsupported_input_schema'),
    )
    expect(fetchArtifact).toHaveBeenCalledTimes(2)
  })

  it('generates a four-field proof with the checked-in browser artifacts', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request) => {
      const path = String(url)
      if (!path.includes('/noir/')) return realFetch(url)
      return {
        ok: true,
        json: async () => path.includes('helper') ? helper : main,
      }
    }))

    const result = await generateSilentWitnessProof(input)
    expect(result.publicInputBytes).toBe(128)
    expect(result.proofBytes).toBeGreaterThan(64)
    expect(result.domainTag).toBeUndefined()
  }, 120_000)

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
