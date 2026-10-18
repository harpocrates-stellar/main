import { describe, expect, it } from 'vitest'
import benchLock from '../../zk/bench/bench.lock.json'
import browserArtifactManifest from '../../zk/browser.artifacts.manifest.json'
import { CircuitInputError } from './circuitInputSchema'
import {
  PROOF_WORKER_MEMORY_LIMITS,
  assertProofWorkerMemoryBudget,
  browserArtifactByteLimit,
  byteLengthOfProofWorkerValue,
  readBoundedCircuitArtifact,
} from './proofWorkerMemory'

describe('proof worker memory limits', () => {
  it('uses the canonical bench and browser artifact metadata', () => {
    const mainArtifact = browserArtifactManifest.artifacts.find((entry) =>
      entry.path === 'frontend/public/noir/silent_witness.json',
    )
    expect(PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes).toBe(
      benchLock.limits.max_witness_bytes,
    )
    expect(PROOF_WORKER_MEMORY_LIMITS.maxProofBytes).toBe(
      benchLock.limits.max_proof_bytes,
    )
    expect(browserArtifactByteLimit('/noir/silent_witness.json')).toBe(
      mainArtifact?.raw_bytes,
    )
  })

  it('accepts boundary-sized witness usage and rejects one byte over', () => {
    expect(() =>
      assertProofWorkerMemoryBudget({
        witnessBytes: PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes,
        proofBytes: PROOF_WORKER_MEMORY_LIMITS.maxProofBytes,
        publicInputBytes: PROOF_WORKER_MEMORY_LIMITS.maxPublicInputBytes,
      }),
    ).not.toThrow()

    expect(() =>
      assertProofWorkerMemoryBudget({
        witnessBytes: PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes + 1,
      }),
    ).toThrowError(new CircuitInputError('proof_worker_memory_exceeded'))
  })

  it('keeps single-proof public inputs tight while allowing explicit wider frames', () => {
    const aggregateFrameBytes = 32 + (8 * 128)

    expect(() =>
      assertProofWorkerMemoryBudget({
        publicInputBytes: aggregateFrameBytes,
      }),
    ).toThrowError(new CircuitInputError('proof_worker_memory_exceeded'))

    expect(() =>
      assertProofWorkerMemoryBudget({
        publicInputBytes: aggregateFrameBytes,
        publicInputLimitBytes: aggregateFrameBytes,
      }),
    ).not.toThrow()
  })

  it('estimates common witness containers without exposing values', () => {
    const secret = 'credentialSecret=never-log-me'
    const witness = new Map<unknown, unknown>([
      [1, new Uint8Array([1, 2, 3])],
      ['private', secret],
    ])

    const bytes = byteLengthOfProofWorkerValue(witness)
    expect(bytes).toBeGreaterThan(secret.length)
  })

  it('rejects oversized artifact content-length before parsing the body', async () => {
    const secret = 'nullifierSecret=should-not-appear'
    const response = new Response(JSON.stringify({ secret }), {
      headers: { 'content-length': '9' },
    })

    try {
      await readBoundedCircuitArtifact(response, '/noir/test.json', 8)
      expect.unreachable('expected memory-limit rejection')
    } catch (error) {
      expect(error).toBeInstanceOf(CircuitInputError)
      expect((error as CircuitInputError).code).toBe('proof_worker_memory_exceeded')
      expect(error instanceof Error ? error.message : String(error)).not.toContain(secret)
    }
  })

  it('rejects malformed artifact JSON as a dependency failure', async () => {
    const response = new Response('{not json}', {
      headers: { 'content-length': '10' },
    })

    await expect(
      readBoundedCircuitArtifact(response, '/noir/test.json', 64),
    ).rejects.toThrowError(new CircuitInputError('circuit_load_failed'))
  })
})
