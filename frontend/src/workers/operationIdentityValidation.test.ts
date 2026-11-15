import { describe, expect, it, vi } from 'vitest'
import { validateWorkerOperationEnvelope } from '../proofWorkerMemory'
import { ProofWorkerManager } from './proof-worker-manager'
import { ProofWorkerClient } from './proofWorkerClient'
import type { ProofWorkerResponse } from './proof.worker.types'
import type { SilentWitnessProof, WorkerResponse } from './proofWorker.types'

class ManualWorker {
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null = null
  onerror: ((event: ErrorEvent) => void) | null = null
  onmessageerror: ((event: MessageEvent) => void) | null = null
  terminated = false
  posted: unknown[] = []

  postMessage(message: unknown) {
    this.posted.push(message)
  }

  terminate() {
    this.terminated = true
  }
}

describe('worker message operation-identity validation', () => {
  it('validates envelope shape, identity match, and progress stage before accepting progress', () => {
    expect(validateWorkerOperationEnvelope(null, 'op-1')).toEqual({
      valid: false,
      code: 'MISMATCHED_OPERATION_IDENTITY',
      reason: 'malformed_envelope',
      expectedOperationId: 'op-1',
    })

    expect(validateWorkerOperationEnvelope({ type: 'PROGRESS', stage: 'loading_circuits' }, null)).toEqual({
      valid: false,
      code: 'MISMATCHED_OPERATION_IDENTITY',
      reason: 'no_active_operation',
      expectedOperationId: null,
    })

    expect(validateWorkerOperationEnvelope({ type: 'PROGRESS', stage: 'loading_circuits' }, 'op-1')).toEqual({
      valid: false,
      code: 'MISMATCHED_OPERATION_IDENTITY',
      reason: 'missing_operation_identity',
      expectedOperationId: 'op-1',
    })

    expect(
      validateWorkerOperationEnvelope(
        { type: 'PROGRESS', operationId: 'op-1', requestId: 'op-2', stage: 'loading_circuits' },
        'op-1',
      ),
    ).toEqual({
      valid: false,
      code: 'MISMATCHED_OPERATION_IDENTITY',
      reason: 'contradictory_operation_identity',
      expectedOperationId: 'op-1',
    })

    expect(
      validateWorkerOperationEnvelope(
        { type: 'PROGRESS', requestId: 'op-stale', stage: 'loading_circuits' },
        'op-1',
      ),
    ).toEqual({
      valid: false,
      code: 'MISMATCHED_OPERATION_IDENTITY',
      reason: 'mismatched_operation_identity',
      expectedOperationId: 'op-1',
    })

    expect(
      validateWorkerOperationEnvelope(
        { type: 'PROGRESS', requestId: 'op-1', stage: 'witness=0xdeadbeef' },
        'op-1',
      ),
    ).toEqual({
      valid: false,
      code: 'MISMATCHED_OPERATION_IDENTITY',
      reason: 'invalid_progress_stage',
      expectedOperationId: 'op-1',
    })

    expect(
      validateWorkerOperationEnvelope(
        { type: 'PROGRESS', requestId: 'op-1', stage: 'executing_main' },
        'op-1',
      ),
    ).toEqual({
      valid: true,
      operationId: 'op-1',
      stage: 'executing_main',
    })
  })

  it('rejects mismatched envelopes in ProofWorkerManager before progress callbacks and preserves active result', async () => {
    const manager = new ProofWorkerManager()
    await manager.init()

    const preservedProofResponse: ProofWorkerResponse = {
      type: 'success',
      id: 'op-prev',
      data: { valid: true, result: { root: 'preserved-root' } },
    }
    manager.beginActiveOperation('op-current', preservedProofResponse)

    const onProgress = vi.fn()
    const rejectedProgress = manager.applyOperationEnvelope(
      { type: 'PROGRESS', operationId: 'op-other', stage: 'generating_proof' },
      onProgress,
    )
    expect(rejectedProgress.valid).toBe(false)
    expect(onProgress).not.toHaveBeenCalled()

    const rejectedError = manager.applyOperationEnvelope(
      {
        type: 'error',
        id: 'op-other',
        error: { code: 'PROOF_ERROR', message: 'stale failure', privacySafe: true },
      },
      onProgress,
    )
    expect(rejectedError.valid).toBe(false)

    // Active operation stage and preserved proof result remain untouched
    expect(manager.getActiveOperationState()).toEqual({
      activeOperationId: 'op-current',
      currentStage: null,
      currentResult: preservedProofResponse,
      rejectedEnvelopeCount: 2,
    })

    // Matching progress envelope applies cleanly
    const acceptedProgress = manager.applyOperationEnvelope(
      { type: 'PROGRESS', operationId: 'op-current', stage: 'loading_circuits' },
      onProgress,
    )
    expect(acceptedProgress.valid).toBe(true)
    expect(onProgress).toHaveBeenCalledWith('loading_circuits')
    expect(manager.getActiveOperationState().currentResult).toEqual(preservedProofResponse)

    manager.destroy()
  })

  it('ignores mismatched handler responses in verifyProof until the matching operation id arrives', async () => {
    const manager = new ProofWorkerManager()
    await manager.init()

    const pending = manager.verifyProof('ev', 'pf', 'C'.repeat(56), 1000)
    const handlers = (
      manager as unknown as {
        messageHandlers: Map<string, (response: ProofWorkerResponse) => void>
      }
    ).messageHandlers
    const [expectedId, handler] = [...handlers.entries()][0]

    handler({
      type: 'error',
      id: 'wrong_msg_id',
      error: { code: 'PROOF_ERROR', message: 'wrong op', privacySafe: true },
    })
    expect(handlers.has(expectedId)).toBe(true)
    expect(manager.getActiveOperationState().rejectedEnvelopeCount).toBe(1)

    const validResponse: ProofWorkerResponse = {
      type: 'success',
      id: expectedId,
      data: { valid: true },
    }
    handler(validResponse)
    await expect(pending).resolves.toEqual(validResponse)
    expect(manager.getActiveOperationState().currentResult).toEqual(validResponse)

    manager.destroy()
  })

  it('preserves active and completed proof results in ProofWorkerClient against mismatched worker messages', async () => {
    const manualWorker = new ManualWorker()
    const client = new ProofWorkerClient({
      runtime: 'worker',
      enableFallback: false,
      workerFactory: () => manualWorker as unknown as Worker,
    })

    const observedStages: string[] = []
    const run = client.generate(
      {
        videoHash: '1'.repeat(64),
        credentialSecret: '123',
        nullifierSecret: '456',
      },
      (stage) => observedStages.push(stage),
    )

    // Inject mismatched progress, error, cancel, and result envelopes
    manualWorker.onmessage?.(
      new MessageEvent('message', {
        data: { type: 'PROGRESS', requestId: 'stale-req', stage: 'generating_proof' },
      }),
    )
    manualWorker.onmessage?.(
      new MessageEvent('message', {
        data: {
          type: 'ERROR',
          requestId: 'stale-req',
          code: 'PROOF_GENERATION_FAILED',
          message: 'proof_generation_failed',
        },
      }),
    )
    manualWorker.onmessage?.(
      new MessageEvent('message', {
        data: { type: 'CANCELLED', requestId: 'stale-req' },
      }),
    )
    expect(observedStages).toEqual([])
    expect(client.getRejectedMessageCount()).toBe(3)

    // Now deliver genuine progress and result for the active operation
    manualWorker.onmessage?.(
      new MessageEvent('message', {
        data: { type: 'PROGRESS', requestId: run.requestId, stage: 'loading_circuits' },
      }),
    )
    const activeProof: SilentWitnessProof = {
      credentialRoot: '11',
      nullifier: '22',
      proof: 'aabbcc',
      publicInputs: '["11","22"]',
      proofBytes: 3,
      publicInputBytes: 11,
    }
    manualWorker.onmessage?.(
      new MessageEvent('message', {
        data: { type: 'RESULT', requestId: run.requestId, proof: activeProof },
      }),
    )

    await expect(run.result).resolves.toEqual(activeProof)
    expect(observedStages).toEqual(['loading_circuits'])
    expect(client.getLastProofResult()).toEqual(activeProof)

    // Late mismatched result after completion must not overwrite preserved lastProofResult
    manualWorker.onmessage?.(
      new MessageEvent('message', {
        data: {
          type: 'RESULT',
          requestId: 'forged-req',
          proof: {
            credentialRoot: '99',
            nullifier: '99',
            proof: 'ff',
            publicInputs: '[]',
            proofBytes: 1,
            publicInputBytes: 2,
          },
        },
      }),
    )
    expect(client.getLastProofResult()).toEqual(activeProof)
    expect(client.getRejectedMessageCount()).toBe(4)

    client.destroy()
  })
})
