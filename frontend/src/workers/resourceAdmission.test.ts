import { describe, expect, it } from 'vitest'
import {
  PROOF_WORKER_MEMORY_LIMITS,
  evaluateProofWorkerResourceAdmission,
} from '../proofWorkerMemory'
import { ProofWorkerManager } from './proof-worker-manager'
import { ProofWorkerClient } from './proofWorkerClient'

function buildGlobal(overrides: Record<string, unknown> = {}): typeof globalThis {
  return {
    Worker: function MockWorker() {},
    WebAssembly: { compile: () => {} },
    crypto: { subtle: {} },
    BigInt,
    ArrayBuffer,
    SharedArrayBuffer,
    crossOriginIsolated: true,
    navigator: { hardwareConcurrency: 4, deviceMemory: 8 },
    ...overrides,
  } as unknown as typeof globalThis
}

describe('proof-worker resource admission decisions', () => {
  it('admits optimal multithreaded proving and clamps thread counts above 8 with an explanation', () => {
    const decision = evaluateProofWorkerResourceAdmission({
      globalObj: buildGlobal({ navigator: { hardwareConcurrency: 16, deviceMemory: 16 } }),
      estimatedUsage: { witnessBytes: 1_024, proofBytes: 2_048, publicInputBytes: 128 },
    })

    expect(decision.admitted).toBe(true)
    expect(decision.outcome).toBe('admit_optimal')
    expect(decision.executionMode).toBe('multithreaded-worker')
    expect(decision.grantedThreads).toBe(8)
    expect(decision.restrictions).toEqual([
      expect.objectContaining({
        category: 'threads',
        code: 'THREAD_CAP_CLAMPED',
        severity: 'advisory',
      }),
    ])
  })

  it('explains thread and memory restrictions and preserves safe single-threaded fallback on constrained browsers', () => {
    // Non-isolated browser -> single-threaded worker fallback
    const nonIsolated = evaluateProofWorkerResourceAdmission({
      globalObj: buildGlobal({ crossOriginIsolated: false }),
    })
    expect(nonIsolated.admitted).toBe(true)
    expect(nonIsolated.outcome).toBe('admit_constrained')
    expect(nonIsolated.executionMode).toBe('single-threaded-worker')
    expect(nonIsolated.grantedThreads).toBe(1)
    expect(nonIsolated.restrictions).toContainEqual(
      expect.objectContaining({
        category: 'threads',
        code: 'CROSS_ORIGIN_ISOLATION_UNAVAILABLE',
        severity: 'fallback',
      }),
    )

    // iOS/iPadOS Safari + low deviceMemory -> single-threaded worker even when crossOriginIsolated
    const iosConstrained = evaluateProofWorkerResourceAdmission({
      globalObj: buildGlobal({ navigator: { hardwareConcurrency: 6, deviceMemory: 2 } }),
      browser: 'Safari',
      platform: 'iOS/iPadOS',
    })
    expect(iosConstrained.admitted).toBe(true)
    expect(iosConstrained.outcome).toBe('admit_constrained')
    expect(iosConstrained.executionMode).toBe('single-threaded-worker')
    expect(iosConstrained.grantedThreads).toBe(1)
    expect(iosConstrained.restrictions.map((r) => r.code)).toEqual([
      'LOW_DEVICE_MEMORY_CONSTRAINED',
      'BEST_EFFORT_SURFACE_MEMORY_CONSTRAINED',
    ])
  })

  it('preserves bounded main-thread fallback when only Worker is unavailable, but rejects missing crypto primitives', () => {
    const workerlessFallback = evaluateProofWorkerResourceAdmission({
      globalObj: buildGlobal({ Worker: undefined }),
      allowBoundedMainThreadFallback: true,
      estimatedUsage: { secretBytes: 64 },
    })
    expect(workerlessFallback.admitted).toBe(true)
    expect(workerlessFallback.outcome).toBe('admit_constrained')
    expect(workerlessFallback.executionMode).toBe('bounded-main-thread-fallback')
    expect(workerlessFallback.grantedThreads).toBe(1)
    expect(workerlessFallback.restrictions).toContainEqual(
      expect.objectContaining({
        category: 'environment',
        code: 'MAIN_THREAD_FALLBACK_REQUIRED',
        severity: 'fallback',
      }),
    )

    // Missing SubtleCrypto must fail closed (never downgrade cryptographic privacy)
    const missingCrypto = evaluateProofWorkerResourceAdmission({
      globalObj: buildGlobal({ crypto: {} }),
      allowBoundedMainThreadFallback: true,
    })
    expect(missingCrypto.admitted).toBe(false)
    expect(missingCrypto.outcome).toBe('reject')
    expect(missingCrypto.executionMode).toBe('rejected')
    expect(missingCrypto.restrictions).toContainEqual(
      expect.objectContaining({
        category: 'environment',
        code: 'WORKER_CAPABILITY_MISSING',
        severity: 'blocking',
      }),
    )
  })

  it('rejects concurrency saturation and memory over-budget before proving starts', () => {
    const saturated = evaluateProofWorkerResourceAdmission({
      globalObj: buildGlobal(),
      activeOperations: 1,
      maxConcurrentOperations: 1,
    })
    expect(saturated.admitted).toBe(false)
    expect(saturated.outcome).toBe('reject')
    expect(saturated.restrictions).toContainEqual(
      expect.objectContaining({
        category: 'concurrency',
        code: 'MAX_CONCURRENT_OPERATIONS_REACHED',
        severity: 'blocking',
      }),
    )

    const overMemory = evaluateProofWorkerResourceAdmission({
      globalObj: buildGlobal(),
      estimatedUsage: {
        witnessBytes: PROOF_WORKER_MEMORY_LIMITS.maxWitnessBytes + 1,
      },
    })
    expect(overMemory.admitted).toBe(false)
    expect(overMemory.outcome).toBe('reject')
    expect(overMemory.restrictions).toContainEqual(
      expect.objectContaining({
        category: 'memory',
        code: 'ESTIMATED_MEMORY_EXCEEDS_BUDGET',
        severity: 'blocking',
      }),
    )
  })

  it('exposes live concurrency and policy admission decisions on ProofWorkerManager and ProofWorkerClient', async () => {
    const manager = new ProofWorkerManager()
    await manager.init()

    const beforeTask = manager.evaluateResourceAdmission({ globalObj: buildGlobal() })
    expect(beforeTask.admitted).toBe(true)

    const inFlight = manager.verifyProof('ev', 'pf', 'C'.repeat(56), 500)
    inFlight.catch(() => {})
    const duringTask = manager.evaluateResourceAdmission({
      globalObj: buildGlobal(),
      maxConcurrentOperations: 1,
    })
    expect(duringTask.admitted).toBe(false)
    expect(duringTask.restrictions[0].code).toBe('MAX_CONCURRENT_OPERATIONS_REACHED')
    manager.destroy()

    const client = new ProofWorkerClient({
      runtime: 'worker',
      enableFallback: false,
      workerFactory: () =>
        ({
          onmessage: null,
          onerror: null,
          onmessageerror: null,
          postMessage: () => {},
          terminate: () => {},
        }) as unknown as Worker,
    })
    expect(client.evaluateAdmission({ globalObj: buildGlobal() }).admitted).toBe(true)
    const gen = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: '123',
      nullifierSecret: '456',
    })
    gen.result.catch(() => {})
    const busyAdmission = client.evaluateAdmission({ globalObj: buildGlobal() })
    expect(busyAdmission.admitted).toBe(false)
    expect(busyAdmission.restrictions[0].code).toBe('MAX_CONCURRENT_OPERATIONS_REACHED')
    client.destroy()
  })
})
