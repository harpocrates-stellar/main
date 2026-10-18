import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * Phase-status contract for the main-thread prover.
 *
 * The Noir/UltraHonk runtime is mocked so this exercises only the boundary
 * that matters for the UI: which `ProofStage` values are emitted, in what
 * order, and that none of them can carry secret material.
 */
const mocks = vi.hoisted(() => ({
  execute: vi.fn(),
  generateProof: vi.fn(),
  destroy: vi.fn(),
}))

vi.mock('@noir-lang/noir_js', () => ({
  Noir: class {
    execute(input: unknown) {
      return mocks.execute(input)
    }
  },
}))

vi.mock('@aztec/bb.js', () => ({
  UltraHonkBackend: class {
    generateProof(witness: unknown, options: unknown) {
      return mocks.generateProof(witness, options)
    }
    destroy() {
      return mocks.destroy()
    }
  },
}))

vi.mock('./verifierInputs', () => ({
  encodeFieldToBytes32Hex: (value: string) => value.padStart(64, '0').slice(-64),
  encodePublicInputs: (inputs: string[]) =>
    inputs.map((value) => value.padStart(64, '0').slice(-64)).join(''),
}))

import { PROOF_STAGE_SEQUENCE, proofStageIndex, type ProofStage } from './proofStage'
import { generateSilentWitnessProof } from './noirClient'

const validInput = {
  videoHash: 'a'.repeat(64),
  credentialSecret: 'credential-secret-fixture',
  nullifierSecret: 'nullifier-secret-fixture',
}

let executeCall = 0

beforeEach(() => {
  executeCall = 0
  mocks.execute.mockImplementation(async () => {
    executeCall += 1
    return executeCall % 2 === 1
      ? { returnValue: ['1', '2', '3'] }
      : { witness: { fixture: 1 } }
  })
  mocks.generateProof.mockResolvedValue({
    proof: new Uint8Array([1, 2, 3]),
    publicInputs: ['1', '2', '3', '4', '5'],
  })
  mocks.destroy.mockResolvedValue(undefined)
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({ ok: true, json: async () => ({ bytecode: '0x00' }) })),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('generateSilentWitnessProof phase reporting', () => {
  it('emits the canonical phases in order at real boundaries (positive)', async () => {
    const stages: ProofStage[] = []

    const proof = await generateSilentWitnessProof({
      ...validInput,
      onStage: (stage) => stages.push(stage),
    })

    expect(stages).toEqual([...PROOF_STAGE_SEQUENCE])
    expect(proof.proof).toBe('010203')
    expect(proof.proofBytes).toBe(3)
  })

  it('reports progress monotonically, never re-entering an earlier phase', async () => {
    const stages: ProofStage[] = []

    await generateSilentWitnessProof({
      ...validInput,
      onStage: (stage) => stages.push(stage),
    })

    const indexes = stages.map(proofStageIndex)
    expect(indexes).toEqual([...indexes].sort((a, b) => a - b))
  })

  it('resolves without a progress sink (regression)', async () => {
    const proof = await generateSilentWitnessProof(validInput)
    expect(proof.nullifier).toHaveLength(64)
  })

  it('never emits secret material through the phase channel (privacy)', async () => {
    const stages: ProofStage[] = []

    await generateSilentWitnessProof({
      ...validInput,
      onStage: (stage) => stages.push(stage),
    })

    for (const stage of stages) {
      expect(stage).not.toContain(validInput.credentialSecret)
      expect(stage).not.toContain(validInput.nullifierSecret)
    }
  })
})
