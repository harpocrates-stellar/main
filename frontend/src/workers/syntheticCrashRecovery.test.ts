import { describe, expect, it } from 'vitest'
import { CircuitInputError } from '../circuitInputSchema'
import {
  SYNTHETIC_FIXTURE_PROTOCOL_VERSION,
  SYNTHETIC_WORKER_FAULT_MODES,
  assertSyntheticFixtureOnly,
  createSyntheticNonSecretFixture,
  runSyntheticCrashRecoveryFixture,
} from '../proofWorkerMemory'
import {
  ProofWorkerManager,
  createSyntheticFaultWorkerFactory,
} from './proof-worker-manager'
import { ProofWorkerClient } from './proofWorkerClient'

describe('synthetic worker crash-recovery fixture protocol', () => {
  it('models initialization_failure, malformed_message, and interrupted_proving deterministically', () => {
    const manager = new ProofWorkerManager()
    const fixture = createSyntheticNonSecretFixture('rehearsal-case-01')

    for (const mode of SYNTHETIC_WORKER_FAULT_MODES) {
      const firstRun = manager.runSyntheticCrashRecovery(mode, fixture)
      const secondRun = runSyntheticCrashRecoveryFixture(mode, fixture)

      expect(firstRun).toEqual(secondRun)
      expect(firstRun.protocolVersion).toBe(SYNTHETIC_FIXTURE_PROTOCOL_VERSION)
      expect(firstRun.usedLiveSecrets).toBe(false)
      expect(firstRun.faultyWorkerTerminated).toBe(true)
      expect(firstRun.workerRespawnCount).toBe(1)
      expect(firstRun.uiBeforeRecovery.uiStage).toBe('error')
      expect(firstRun.uiBeforeRecovery.activeProofStage).toBeNull()
      expect(firstRun.uiBeforeRecovery.canRetry).toBe(true)
      expect(firstRun.uiAfterRecovery).toEqual({
        uiStage: 'ready',
        activeProofStage: null,
        canRetry: true,
        errorCode: null,
        statusMessage: 'Proof worker recovered and ready.',
      })
      expect(firstRun.postRecoveryVerificationSucceeded).toBe(true)
    }

    manager.destroy()
  })

  it('rejects live secret fields or unmarked fixtures fail-closed', () => {
    expect(() =>
      assertSyntheticFixtureOnly({
        syntheticOnly: true,
        fixtureId: 'bad-fixture',
        placeholderDigest: '0'.repeat(64),
        credentialSecret: 'real-user-secret',
      }),
    ).toThrowError(new CircuitInputError('invalid_input'))

    expect(() =>
      assertSyntheticFixtureOnly({
        syntheticOnly: false,
        fixtureId: 'unmarked',
        placeholderDigest: '0'.repeat(64),
      }),
    ).toThrowError(new CircuitInputError('invalid_input'))

    expect(() =>
      runSyntheticCrashRecoveryFixture('unknown_fault' as never),
    ).toThrowError(new CircuitInputError('invalid_input'))
  })

  it('drives ProofWorkerClient through malformed_message and interrupted_proving into clean recovery', async () => {
    const { workerFactory, spawnedWorkers } = createSyntheticFaultWorkerFactory([
      'malformed_message',
      'interrupted_proving',
    ])

    const client = new ProofWorkerClient({
      runtime: 'worker',
      enableFallback: false,
      workerFactory,
    })

    const syntheticInput = {
      videoHash: '0'.repeat(64),
      credentialSecret: '0',
      nullifierSecret: '0',
    }

    // 1. Malformed message fault -> CRASHED + faulty worker terminated + respawn
    const run1Stages: string[] = []
    const run1 = client.generate(syntheticInput, (s) => run1Stages.push(s))
    await expect(run1.result).rejects.toMatchObject({ code: 'CRASHED' })
    expect(spawnedWorkers[0].terminated).toBe(true)

    // 2. Interrupted proving fault -> emits early progress stages then CRASHED + respawn
    const run2Stages: string[] = []
    const run2 = client.generate(syntheticInput, (s) => run2Stages.push(s))
    await expect(run2.result).rejects.toMatchObject({ code: 'CRASHED' })
    expect(run2Stages).toEqual(['loading_circuits', 'executing_helper'])
    expect(spawnedWorkers[1].terminated).toBe(true)

    // 3. Recovered healthy synthetic worker completes deterministically
    const run3Stages: string[] = []
    const run3 = client.generate(syntheticInput, (s) => run3Stages.push(s))
    const proof = await run3.result
    expect(run3Stages).toEqual(['loading_circuits', 'generating_proof'])
    expect(proof.proofBytes).toBe(1)

    client.destroy()
    expect(spawnedWorkers[2].terminated).toBe(true)
  })

  it('handles synthetic initialization_failure at worker bootstrap cleanly', () => {
    const { workerFactory } = createSyntheticFaultWorkerFactory(['initialization_failure'])
    const client = new ProofWorkerClient({
      runtime: 'worker',
      enableFallback: false,
      workerFactory,
    })

    const attempt = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: '0',
      nullifierSecret: '0',
    })
    expect(attempt.requestId).toBe('')
    return expect(attempt.result).rejects.toMatchObject({ code: 'WORKER_UNAVAILABLE' })
  })
})
