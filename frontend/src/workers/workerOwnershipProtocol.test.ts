import { describe, expect, it, vi } from 'vitest'
import {
  ProofWorkerOwnershipError,
  ProofWorkerOwnershipProtocol,
} from '../proofWorkerMemory'
import { ProofWorkerManager } from './proof-worker-manager'
import { ProofWorkerLogger } from './proof-worker-logger'
import { ProofWorkerClient, ProofWorkerError } from './proofWorkerClient'
import type { SilentWitnessProof, WorkerRequest, WorkerResponse } from './proofWorker.types'

class ControlledMockWorker {
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null = null
  onerror: ((event: ErrorEvent) => void) | null = null
  onmessageerror: ((event: MessageEvent) => void) | null = null
  posted: WorkerRequest[] = []
  terminated = false

  postMessage(msg: WorkerRequest) {
    this.posted.push(msg)
  }

  terminate() {
    this.terminated = true
  }

  emitMessage(msg: WorkerResponse) {
    this.onmessage?.(new MessageEvent('message', { data: msg }))
  }

  emitCrash() {
    this.onerror?.(new ErrorEvent('error', { message: 'worker crashed' }))
  }
}

const VALID_INPUT = {
  videoHash: 'a'.repeat(64),
  credentialSecret: 'owner-secret-credential',
  nullifierSecret: 'owner-secret-nullifier',
}

function makeProof(tag: string): SilentWitnessProof {
  return {
    credentialRoot: `0xroot_${tag}`,
    nullifier: `0xnull_${tag}`,
    proof: `0xproof_${tag}`,
    publicInputs: `0xpub_${tag}`,
    proofBytes: 128,
    publicInputBytes: 64,
  }
}

describe('browser proof-worker single ownership protocol', () => {
  it('enforces an exclusive single-owner lease and rejects competing owners until released', () => {
    const protocol = new ProofWorkerOwnershipProtocol()

    const leaseA = protocol.claimOwnership('evidence-studio')
    expect(leaseA).toEqual({
      leaseId: 'lease_1',
      ownerId: 'evidence-studio',
      acquiredAtEpoch: 1,
    })
    // Re-claiming by the same owner is idempotent
    expect(protocol.claimOwnership('evidence-studio')).toBe(leaseA)

    // Competing owner cannot steal the lease or release it
    expect(() => protocol.claimOwnership('batch-workspace')).toThrowError(
      ProofWorkerOwnershipError,
    )
    expect(() => protocol.claimOwnership('batch-workspace')).toThrow(
      expect.objectContaining({ code: 'WORKER_OWNERSHIP_CONFLICT' }),
    )
    expect(() => protocol.releaseOwnership('batch-workspace')).toThrow(
      expect.objectContaining({ code: 'WORKER_OWNERSHIP_CONFLICT' }),
    )

    // Unowned or competing-owner operations are rejected while leaseA is active
    expect(() => protocol.startOperation({ operationId: 'op-unowned' })).toThrow(
      expect.objectContaining({ code: 'UNOWNED_WORKER_OPERATION' }),
    )
    expect(() =>
      protocol.startOperation({ operationId: 'op-competing', ownerId: 'batch-workspace' }),
    ).toThrow(expect.objectContaining({ code: 'WORKER_OWNERSHIP_CONFLICT' }))

    // Active owner can run an operation and then release ownership cleanly
    const stamp = protocol.startOperation({
      operationId: 'op-owned-1',
      ownerId: 'evidence-studio',
    })
    expect(stamp.ownerId).toBe('evidence-studio')
    expect(protocol.completeOperation('op-owned-1')).toBe(true)

    protocol.releaseOwnership('evidence-studio', leaseA.leaseId)
    const leaseB = protocol.claimOwnership('batch-workspace')
    expect(leaseB.ownerId).toBe('batch-workspace')
    expect(leaseB.leaseId).toBe('lease_2')
  })

  it('tracks monotonic workerEpoch and operationGeneration across worker replacement on ProofWorkerManager', async () => {
    const logSpy = vi.spyOn(ProofWorkerLogger.prototype, 'log')
    vi.spyOn(console, 'info').mockImplementation(() => {})
    const manager = new ProofWorkerManager()
    await manager.init()

    const lease = manager.claimOwnership('studio-tab-1')
    const op1 = manager.beginOwnedOperation({
      operationId: 'verify-op-1',
      ownerId: 'studio-tab-1',
    })
    expect(op1.workerEpoch).toBe(1)
    expect(op1.operationGeneration).toBe(1)

    // Replace worker due to crash: both workerEpoch and operationGeneration advance,
    // while explicit owner lease stays bound to studio-tab-1.
    const replaced = manager.replaceWorker(null, 'crash_restart')
    expect(replaced).toEqual({ workerEpoch: 2, operationGeneration: 2 })
    expect(manager.getOwnershipSnapshot().activeLease).toEqual(lease)
    expect(manager.getOwnershipSnapshot().activeOperation).toBeNull()

    const op2 = manager.beginOwnedOperation({
      operationId: 'verify-op-2',
      ownerId: 'studio-tab-1',
    })
    expect(op2.workerEpoch).toBe(2)
    expect(op2.operationGeneration).toBe(3)
    expect(op2.operationGeneration).toBeGreaterThan(op1.operationGeneration)

    manager.destroy()
    expect(manager.getOwnershipSnapshot().activeLease).toBeNull()

    for (const call of logSpy.mock.calls) {
      const ctx = call[2] as Record<string, unknown> | undefined
      if (!ctx) continue
      for (const key of Object.keys(ctx)) {
        expect(key).not.toMatch(/evidence|proof|witness|secret|nullifier/i)
      }
    }
    vi.restoreAllMocks()
  })

  it('rejects stale progress and proof messages after cancellation and restart on ProofWorkerManager', async () => {
    vi.spyOn(console, 'info').mockImplementation(() => {})
    const manager = new ProofWorkerManager()
    await manager.init()

    const op1 = manager.beginOwnedOperation({ operationId: 'op-1' })
    const progressStages: string[] = []

    // Cancel op-1 before any new operation starts
    const afterCancel = manager.cancelOwnedOperation('op-1')
    expect(afterCancel.operationGeneration).toBe(2)

    const staleProgressAfterCancel = manager.acceptOwnedWorkerMessage({
      kind: 'progress',
      operationId: op1.operationId,
      workerEpoch: op1.workerEpoch,
      operationGeneration: op1.operationGeneration,
      stage: 'generating_proof',
      onProgress: (s) => progressStages.push(s),
    })
    expect(staleProgressAfterCancel).toEqual({
      accepted: false,
      reason: 'no_active_operation',
      kind: 'progress',
    })

    const staleProofAfterCancel = manager.acceptOwnedWorkerMessage({
      kind: 'proof',
      operationId: op1.operationId,
      workerEpoch: op1.workerEpoch,
      operationGeneration: op1.operationGeneration,
      response: { type: 'success', id: op1.operationId, data: { valid: true } },
    })
    expect(staleProofAfterCancel).toEqual({
      accepted: false,
      reason: 'no_active_operation',
      kind: 'proof',
    })
    expect(progressStages).toEqual([])

    // Now start op-2 on the same worker epoch, then test stale generation vs replaced epoch
    const op2 = manager.beginOwnedOperation({ operationId: 'op-2' })
    expect(op2.workerEpoch).toBe(1)
    expect(op2.operationGeneration).toBe(3)

    // Late message on same workerEpoch (1) but stale operationGeneration (1) -> rejected!
    const staleGenVerdict = manager.acceptOwnedWorkerMessage({
      kind: 'progress',
      operationId: op2.operationId,
      workerEpoch: 1,
      operationGeneration: 1,
      stage: 'executing_main',
      onProgress: (s) => progressStages.push(s),
    })
    expect(staleGenVerdict).toEqual({
      accepted: false,
      reason: 'stale_operation_generation',
      kind: 'progress',
    })

    // Replace worker -> start op-3 (workerEpoch: 2, operationGeneration: 5)
    manager.replaceWorker(null, 'cancel_restart')
    const op3 = manager.beginOwnedOperation({ operationId: 'op-3' })
    expect(op3.workerEpoch).toBe(2)
    expect(op3.operationGeneration).toBe(5)

    // Late proof from old workerEpoch (1) -> rejected!
    const staleEpochProof = manager.acceptOwnedWorkerMessage({
      kind: 'proof',
      operationId: op3.operationId,
      workerEpoch: 1,
      operationGeneration: op3.operationGeneration,
    })
    expect(staleEpochProof).toEqual({
      accepted: false,
      reason: 'stale_worker_epoch',
      kind: 'proof',
    })

    // Malformed stamp boundary case -> rejected!
    const malformed = manager.acceptOwnedWorkerMessage({
      kind: 'proof',
      operationId: op3.operationId,
      workerEpoch: 0,
      operationGeneration: -1,
    })
    expect(malformed).toEqual({
      accepted: false,
      reason: 'malformed_stamp',
      kind: 'proof',
    })

    // Current op-3 progress and proof messages -> accepted!
    const validProgress = manager.acceptOwnedWorkerMessage({
      kind: 'progress',
      operationId: op3.operationId,
      workerEpoch: op3.workerEpoch,
      operationGeneration: op3.operationGeneration,
      stage: 'generating_proof',
      onProgress: (s) => progressStages.push(s),
    })
    expect(validProgress.accepted).toBe(true)
    expect(progressStages).toEqual(['generating_proof'])

    const validProof = manager.acceptOwnedWorkerMessage({
      kind: 'proof',
      operationId: op3.operationId,
      workerEpoch: op3.workerEpoch,
      operationGeneration: op3.operationGeneration,
    })
    expect(validProof.accepted).toBe(true)

    const snap = manager.getOwnershipSnapshot()
    expect(snap.rejectedStaleProgressCount).toBe(2)
    expect(snap.rejectedStaleProofCount).toBe(3)
    expect(snap.activeOperation).toBeNull()

    manager.destroy()
    vi.restoreAllMocks()
  })

  it('drops stale progress and proof messages across cancel/crash replacement in ProofWorkerClient while enforcing owner leases', async () => {
    const spawnedWorkers: ControlledMockWorker[] = []
    const client = new ProofWorkerClient({
      runtime: 'worker',
      enableFallback: false,
      workerFactory: () => {
        const w = new ControlledMockWorker()
        spawnedWorkers.push(w)
        return w as unknown as Worker
      },
    })

    client.claimOwnership('owner-alpha')

    // Competing owner is rejected with BUSY before posting anything to worker 0
    const competing = client.generate(VALID_INPUT, undefined, undefined, {
      ownerId: 'owner-beta',
    })
    await expect(competing.result).rejects.toMatchObject({
      code: 'BUSY',
    })
    await competing.result.catch((err: ProofWorkerError) => {
      expect(err.message).not.toContain(VALID_INPUT.credentialSecret)
      expect(err.message).not.toContain(VALID_INPUT.nullifierSecret)
    })
    expect(spawnedWorkers[0].posted).toHaveLength(0)

    // Owner alpha starts generation 1 on worker 0 (workerEpoch 1, operationGeneration 1)
    const stages1: string[] = []
    const run1 = client.generate(
      VALID_INPUT,
      (stage) => stages1.push(stage),
      undefined,
      { ownerId: 'owner-alpha' },
    )
    expect(run1.workerEpoch).toBe(1)
    expect(run1.operationGeneration).toBe(1)
    expect(spawnedWorkers[0].posted[0]).toMatchObject({
      type: 'GENERATE_PROOF',
      requestId: run1.requestId,
      workerEpoch: 1,
      operationGeneration: 1,
    })

    // Cancel run1 -> terminates worker 0, spawns worker 1 (workerEpoch 2, operationGeneration 2)
    client.cancel(run1.requestId)
    await expect(run1.result).rejects.toMatchObject({ code: 'CANCELLED' })
    expect(spawnedWorkers).toHaveLength(2)
    expect(spawnedWorkers[0].terminated).toBe(true)

    // Owner alpha starts run2 on worker 1 (workerEpoch 2, operationGeneration 3)
    const stages2: string[] = []
    const run2 = client.generate(
      VALID_INPUT,
      (stage) => stages2.push(stage),
      undefined,
      { ownerId: 'owner-alpha' },
    )
    expect(run2.workerEpoch).toBe(2)
    expect(run2.operationGeneration).toBe(3)

    // Stale progress & proof from terminated worker 0 (epoch 1) MUST be rejected
    spawnedWorkers[0].emitMessage({
      type: 'PROGRESS',
      requestId: run1.requestId,
      stage: 'generating_proof',
      workerEpoch: 1,
      operationGeneration: 1,
    })
    spawnedWorkers[0].emitMessage({
      type: 'RESULT',
      requestId: run1.requestId,
      proof: makeProof('stale-epoch-1'),
      workerEpoch: 1,
      operationGeneration: 1,
    })

    // Stale generation message on current worker 1 (epoch 2, stale generation 1) MUST also be rejected
    spawnedWorkers[1].emitMessage({
      type: 'PROGRESS',
      requestId: run2.requestId,
      stage: 'executing_helper',
      workerEpoch: 2,
      operationGeneration: 1,
    })
    spawnedWorkers[1].emitMessage({
      type: 'RESULT',
      requestId: run2.requestId,
      proof: makeProof('stale-gen-1'),
      workerEpoch: 2,
      operationGeneration: 1,
    })

    expect(stages1).toEqual([])
    expect(stages2).toEqual([])
    expect(client.getOwnershipSnapshot().rejectedStaleProgressCount).toBe(2)
    expect(client.getOwnershipSnapshot().rejectedStaleProofCount).toBe(2)

    // Valid progress and proof for run2 (epoch 2, generation 3) succeed cleanly!
    spawnedWorkers[1].emitMessage({
      type: 'PROGRESS',
      requestId: run2.requestId,
      stage: 'generating_proof',
      workerEpoch: 2,
      operationGeneration: 3,
    })
    const expectedProof = makeProof('fresh-gen-3')
    spawnedWorkers[1].emitMessage({
      type: 'RESULT',
      requestId: run2.requestId,
      proof: expectedProof,
      workerEpoch: 2,
      operationGeneration: 3,
    })

    await expect(run2.result).resolves.toEqual(expectedProof)
    expect(stages2).toEqual(['generating_proof'])

    client.releaseOwnership('owner-alpha')
    client.destroy()
  })
})
