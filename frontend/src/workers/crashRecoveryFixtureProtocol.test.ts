import { afterEach, describe, expect, it } from 'vitest'
import {
  CRASH_RECOVERY_MEMORY_CEILINGS,
  CrashRecoveryFixtureProtocol,
  createSyntheticProofFixture,
  isValidWorkerResponse,
} from './crashRecoveryFixtureProtocol'

const protocols: CrashRecoveryFixtureProtocol[] = []

function createProtocol(
  options: ConstructorParameters<typeof CrashRecoveryFixtureProtocol>[0],
): CrashRecoveryFixtureProtocol {
  const protocol = new CrashRecoveryFixtureProtocol(options)
  protocols.push(protocol)
  return protocol
}

afterEach(() => {
  while (protocols.length) {
    protocols.pop()?.destroy()
  }
})

describe('isValidWorkerResponse (fail-closed frame validation)', () => {
  it('accepts well-formed success and error responses with matching id', () => {
    expect(
      isValidWorkerResponse(
        { type: 'success', id: 'req-1', data: { valid: true } },
        'req-1',
      ),
    ).toBe(true)

    expect(
      isValidWorkerResponse(
        {
          type: 'error',
          id: 'req-1',
          error: { code: 'MEMORY_LIMIT_EXCEEDED', message: 'proof_worker_memory_exceeded', privacySafe: true },
        },
        'req-1',
      ),
    ).toBe(true)
  })

  it('rejects null, primitives, unknown types, mismatched ids, and missing valid booleans', () => {
    expect(isValidWorkerResponse(null, 'req-1')).toBe(false)
    expect(isValidWorkerResponse('success', 'req-1')).toBe(false)
    expect(isValidWorkerResponse([], 'req-1')).toBe(false)
    expect(isValidWorkerResponse({ type: 'unknown', id: 'req-1' }, 'req-1')).toBe(false)
    expect(isValidWorkerResponse({ type: 'success', id: 'req-2', data: { valid: true } }, 'req-1')).toBe(false)
    expect(isValidWorkerResponse({ type: 'success', id: 'req-1', data: { valid: 'yes' } }, 'req-1')).toBe(false)
    expect(isValidWorkerResponse({ type: 'success', id: 'req-1', data: null }, 'req-1')).toBe(false)
    expect(isValidWorkerResponse({ type: 'error', id: 'req-1', error: { code: 'E' } }, 'req-1')).toBe(false)
  })
})

describe('CrashRecoveryFixtureProtocol: initialization failure', () => {
  it('fails closed on init_failure and deterministically recovers for subsequent proving', async () => {
    const protocol = createProtocol({
      script: [
        { kind: 'init_failure', reason: 'wasm_instantiation_failed' },
        { kind: 'success', valid: true, message: 'recovered_ok' },
      ],
    })

    const initState = await protocol.init()
    expect(initState.phase).toBe('failed')
    expect(initState.lastScenario).toBe('init_failure')
    expect(initState.lastErrorCode).toBe('INIT_FAILED')
    expect(initState.canRetry).toBe(true)
    expect(initState.lastVerified).toBeNull()

    // Proving while failed must fail closed without touching a worker.
    const blocked = await protocol.prove(createSyntheticProofFixture())
    expect(blocked.ok).toBe(false)
    expect(blocked.errorCode).toBe('NOT_READY')

    const recoveredState = await protocol.recover()
    expect(recoveredState.phase).toBe('recovered')
    expect(recoveredState.generation).toBe(2)
    expect(recoveredState.retryCount).toBe(1)
    expect(recoveredState.lastErrorCode).toBeNull()

    const retryResult = await protocol.prove(createSyntheticProofFixture())
    expect(retryResult.ok).toBe(true)
    expect(retryResult.response?.data?.valid).toBe(true)
    expect(retryResult.uiState.phase).toBe('ready')
    expect(retryResult.uiState.lastVerified).toBe(true)

    expect(protocol.getTransitions().map((t) => `${t.from}->${t.to}`)).toEqual([
      'idle->initializing',
      'initializing->failed',
      'failed->recovering',
      'recovering->recovered',
      'recovered->proving',
      'proving->ready',
    ])
  })

  it('keeps failing closed when CSP origin policy rejects initialization', async () => {
    const protocol = createProtocol({
      origin: 'https://untrusted.example',
      script: [{ kind: 'success', valid: true }],
    })

    const initState = await protocol.init()
    expect(initState.phase).toBe('failed')
    expect(initState.lastErrorCode).toBe('ORIGIN_REJECTED')

    const recoveredState = await protocol.recover()
    expect(recoveredState.phase).toBe('failed')
    expect(recoveredState.lastErrorCode).toBe('ORIGIN_REJECTED')
    expect(protocol.getSpawnedWorkers()).toHaveLength(0)
  })
})

describe('CrashRecoveryFixtureProtocol: malformed messages', () => {
  it('quarantines a worker emitting malformed frames and recovers deterministically', async () => {
    const protocol = createProtocol({
      script: [
        { kind: 'malformed_message', rawPayload: { type: 'success', id: 'wrong-id', data: { valid: true } } },
        { kind: 'success', valid: true },
      ],
    })

    await protocol.init()
    const failed = await protocol.prove(createSyntheticProofFixture())
    expect(failed.ok).toBe(false)
    expect(failed.errorCode).toBe('MALFORMED_WORKER_MESSAGE')
    expect(failed.uiState.phase).toBe('failed')
    expect(failed.uiState.lastScenario).toBe('malformed_message')
    expect(failed.uiState.lastVerified).toBe(false)

    const [firstWorker] = protocol.getSpawnedWorkers()
    expect(firstWorker.terminated).toBe(true)

    const recovered = await protocol.recover()
    expect(recovered.phase).toBe('recovered')

    // Boundary case: a late/stale frame from the terminated generation must be ignored.
    firstWorker.emitStaleMessage({ type: 'success', id: 'synthetic_req_1_1', data: { valid: true } })
    expect(protocol.getUIState().phase).toBe('recovered')
    expect(protocol.getUIState().generation).toBe(2)

    const retried = await protocol.prove(createSyntheticProofFixture())
    expect(retried.ok).toBe(true)
    expect(retried.uiState.phase).toBe('ready')
    expect(retried.uiState.lastVerified).toBe(true)
  })

  it('handles worker message deserialization errors (onmessageerror) fail-closed', async () => {
    const protocol = createProtocol({
      script: [
        { kind: 'message_error' },
        { kind: 'success', valid: false },
      ],
    })

    await protocol.init()
    const failed = await protocol.prove(createSyntheticProofFixture())
    expect(failed.ok).toBe(false)
    expect(failed.errorCode).toBe('MALFORMED_WORKER_MESSAGE')
    expect(failed.uiState.lastVerified).toBe(false)

    await protocol.recover()
    const retried = await protocol.prove(createSyntheticProofFixture())
    expect(retried.ok).toBe(true)
    expect(retried.uiState.lastVerified).toBe(false)
  })
})

describe('CrashRecoveryFixtureProtocol: interrupted proving & memory ceilings', () => {
  it('recovers deterministically after a mid-proof worker crash', async () => {
    const protocol = createProtocol({
      script: [
        { kind: 'interrupted_proving', mode: 'crash' },
        { kind: 'success', valid: true },
      ],
    })

    await protocol.init()
    const crashed = await protocol.prove(createSyntheticProofFixture())
    expect(crashed.ok).toBe(false)
    expect(crashed.errorCode).toBe('WORKER_CRASHED')
    expect(crashed.uiState.phase).toBe('failed')
    expect(crashed.uiState.lastScenario).toBe('interrupted_proving')
    expect(crashed.uiState.lastVerified).toBe(false)
    expect(protocol.getSpawnedWorkers()[0].terminated).toBe(true)

    await protocol.recover()
    const recoveredRun = await protocol.prove(createSyntheticProofFixture())
    expect(recoveredRun.ok).toBe(true)
    expect(recoveredRun.uiState.phase).toBe('ready')
    expect(recoveredRun.uiState.lastVerified).toBe(true)
  })

  it('enforces proofWorkerMemory ceilings before proving and recovers with a bounded fixture', async () => {
    const protocol = createProtocol({
      script: [
        { kind: 'success', valid: true },
        { kind: 'success', valid: true },
      ],
    })

    await protocol.init()
    const oversizedFixture = createSyntheticProofFixture({
      memoryUsage: {
        witnessBytes: CRASH_RECOVERY_MEMORY_CEILINGS.maxWitnessBytes + 1,
      },
    })

    const overCap = await protocol.prove(oversizedFixture)
    expect(overCap.ok).toBe(false)
    expect(overCap.errorCode).toBe('MEMORY_LIMIT_EXCEEDED')
    expect(overCap.errorMessage).toBe('proof_worker_memory_exceeded')
    expect(overCap.uiState.phase).toBe('failed')

    await protocol.recover()
    const boundedRun = await protocol.prove(createSyntheticProofFixture())
    expect(boundedRun.ok).toBe(true)
    expect(boundedRun.uiState.lastVerified).toBe(true)
  })

  it('produces identical transition traces across repeated runs and never leaks fixture tags in errors', async () => {
    const runOnce = async () => {
      const protocol = createProtocol({
        script: [
          { kind: 'interrupted_proving', mode: 'terminate' },
          { kind: 'success', valid: true },
        ],
      })
      const fixture = createSyntheticProofFixture({
        syntheticEvidenceTag: 'synthetic-tag-do-not-echo',
        syntheticProofTag: 'synthetic-proof-do-not-echo',
      })
      await protocol.init()
      const failed = await protocol.prove(fixture)
      expect(failed.errorMessage).not.toContain('synthetic-tag-do-not-echo')
      expect(failed.errorMessage).not.toContain('synthetic-proof-do-not-echo')
      await protocol.recover()
      await protocol.prove(fixture)
      return protocol.getTransitions()
    }

    const firstTrace = await runOnce()
    const secondTrace = await runOnce()
    expect(firstTrace).toEqual(secondTrace)
  })
})
