import { describe, expect, it } from 'vitest'
import { CircuitInputError } from '../circuitInputSchema'
import {
  WorkerSessionBufferGuard,
  WorkerSessionReuseError,
} from '../proofWorkerMemory'
import { ProofWorkerManager } from './proof-worker-manager'

describe('session buffer clearing before reusing a worker session', () => {
  it('zeroes witness and proof buffers, releases references after export, and enables clean session reuse', () => {
    const guard = new WorkerSessionBufferGuard()
    guard.beginOperation('op-1')

    const witnessBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    const proofExportBytes = new Uint8Array([0xca, 0xfe, 0xba, 0xbe])

    const witnessSlot = guard.registerBuffer('op-1', 'witness', witnessBytes)
    const proofSlot = guard.registerBuffer('op-1', 'proof', proofExportBytes)
    expect(guard.isReadyForReuse()).toBe(false)

    // Release proof buffer right after export
    const exportRelease = guard.releaseAfterTransferOrExport('op-1', proofSlot)
    expect(exportRelease).toEqual({
      zeroedBytes: 4,
      detached: false,
      released: true,
    })
    expect([...proofExportBytes]).toEqual([0, 0, 0, 0])

    // Complete operation and sweep remaining witness buffer before session reuse
    const summary = guard.clearCompletedOperation('op-1')
    expect(summary).toEqual({
      operationId: 'op-1',
      clearedSlots: 1,
      zeroedBytes: 8,
      detachedSlotsSkipped: 0,
      referencesReleased: true,
      reusable: true,
    })
    expect([...witnessBytes]).toEqual([0, 0, 0, 0])
    expect(guard.isReadyForReuse()).toBe(true)

    // Subsequent operation on the reused session sees zero prior witness material
    guard.beginOperation('op-2')
    const secondWitness = new Uint8Array([1, 2, 3])
    const secondSlot = guard.registerBuffer('op-2', 'witness', secondWitness)
    expect(secondSlot).not.toBe(witnessSlot)
    guard.clearCompletedOperation('op-2')
    expect([...secondWitness]).toEqual([0, 0, 0])
  })

  it('blocks worker session reuse when previous operation buffers have not been cleared', () => {
    const guard = new WorkerSessionBufferGuard()
    const privateWitness = new Uint8Array([42, 43, 44, 45])
    guard.registerBuffer('op-uncleared', 'witness', privateWitness)

    expect(() => guard.assertReadyForReuse()).toThrowError(WorkerSessionReuseError)
    expect(() => guard.beginOperation('op-next')).toThrowError(WorkerSessionReuseError)
    expect(() =>
      guard.registerBuffer('op-next', 'witness', new Uint8Array([9])),
    ).toThrowError(WorkerSessionReuseError)

    try {
      guard.beginOperation('op-next')
      expect.unreachable('expected session reuse rejection')
    } catch (err) {
      expect(err).toBeInstanceOf(WorkerSessionReuseError)
      expect((err as WorkerSessionReuseError).code).toBe('UNCLEARED_SESSION_BUFFERS')
      expect((err as Error).message).not.toContain('42')
    }
  })

  it('handles detached ArrayBuffers after structuredClone transfer without throwing', () => {
    const guard = new WorkerSessionBufferGuard()
    const rawTransfer = new Uint8Array([7, 8, 9, 10]).buffer
    const slotId = guard.registerBuffer('op-transfer', 'transfer', rawTransfer)

    // Detach rawTransfer as postMessage(..., [rawTransfer]) does
    const received = structuredClone(rawTransfer, { transfer: [rawTransfer] })
    expect(rawTransfer.byteLength).toBe(0)
    expect(received.byteLength).toBe(4)

    const release = guard.releaseAfterTransferOrExport('op-transfer', slotId)
    expect(release).toEqual({
      zeroedBytes: 0,
      detached: true,
      released: true,
    })

    const summary = guard.clearCompletedOperation('op-transfer')
    expect(summary.detachedSlotsSkipped).toBe(1)
    expect(summary.reusable).toBe(true)
  })

  it('rejects invalid operation identifiers and mismatched cleanup calls fail-closed', () => {
    const guard = new WorkerSessionBufferGuard()
    expect(() => guard.beginOperation('invalid op id with spaces')).toThrowError(
      new CircuitInputError('invalid_input'),
    )

    guard.beginOperation('op-valid')
    expect(() => guard.clearCompletedOperation('op-other')).toThrowError(
      new CircuitInputError('invalid_input'),
    )
  })

  it('integrates session buffer clearing with ProofWorkerManager reuse and destroy()', () => {
    const manager = new ProofWorkerManager()
    expect(manager.isSessionReadyForReuse()).toBe(true)

    const secretView = new Uint8Array([0xaa, 0xbb, 0xcc])
    manager.beginWorkerSessionOperation('mgr-session-1')
    const slot = manager.registerSessionBuffer('mgr-session-1', 'witness', secretView)
    expect(manager.isSessionReadyForReuse()).toBe(false)

    manager.releaseSessionBufferAfterExport('mgr-session-1', slot)
    expect([...secretView]).toEqual([0, 0, 0])

    const cleared = manager.clearCompletedSessionBuffers('mgr-session-1')
    expect(cleared.reusable).toBe(true)
    expect(manager.isSessionReadyForReuse()).toBe(true)

    // Force-clear on destroy also zeroes active buffers if destroyed mid-session
    const midSessionSecret = new Uint8Array([0x11, 0x22])
    manager.registerSessionBuffer('mgr-session-2', 'witness', midSessionSecret)
    manager.destroy()
    expect([...midSessionSecret]).toEqual([0, 0])
    expect(manager.isSessionReadyForReuse()).toBe(true)
  })
})
