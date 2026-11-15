import { describe, expect, it } from 'vitest'
import { CircuitInputError } from './circuitInputSchema'
import {
  PROOF_BUFFER_CLASSES,
  PROOF_MEMORY_PRECISION_NOTE,
  PROOF_WORKER_MEMORY_LIMITS,
  ProofOperationMemoryTracker,
} from './proofWorkerMemory'
import { ProofWorkerManager } from './workers/proof-worker-manager'

describe('per-operation proof memory accounting', () => {
  it('tracks allocated, released, active, and peak bytes per buffer class', () => {
    const tracker = new ProofOperationMemoryTracker()
    tracker.startOperation('op-1')

    tracker.recordAllocation('op-1', 'artifact', 4_096)
    tracker.recordAllocation('op-1', 'witness', 2_048)
    tracker.recordAllocation('op-1', 'transfer', 512)
    tracker.recordRelease('op-1', 'transfer', 512)
    tracker.recordAllocation('op-1', 'proof', 1_024)
    tracker.recordAllocation('op-1', 'public_input', 128)
    tracker.recordRelease('op-1', 'witness', 2_048)

    const activeReport = tracker.getReport('op-1')
    expect(activeReport).not.toBeNull()
    expect(activeReport?.status).toBe('active')
    expect(activeReport?.classes.artifact).toEqual({
      allocatedBytes: 4_096,
      releasedBytes: 0,
      activeBytes: 4_096,
      peakBytes: 4_096,
      allocationCount: 1,
      releaseCount: 0,
    })
    expect(activeReport?.classes.witness).toEqual({
      allocatedBytes: 2_048,
      releasedBytes: 2_048,
      activeBytes: 0,
      peakBytes: 2_048,
      allocationCount: 1,
      releaseCount: 1,
    })
    expect(activeReport?.classes.transfer).toEqual({
      allocatedBytes: 512,
      releasedBytes: 512,
      activeBytes: 0,
      peakBytes: 512,
      allocationCount: 1,
      releaseCount: 1,
    })
    expect(activeReport?.totals).toEqual({
      allocatedBytes: 7_808,
      releasedBytes: 2_560,
      activeBytes: 5_248,
      peakBytes: 7_296,
      allocationCount: 5,
      releaseCount: 2,
    })

    const completed = tracker.completeOperation('op-1')
    expect(completed.status).toBe('completed')
    expect(completed.totals.activeBytes).toBe(5_248)
  })

  it('marks reports explicitly as tracked-buffer estimates without witness exposure', () => {
    const tracker = new ProofOperationMemoryTracker()
    const report = tracker.recordAllocation('op-privacy', 'witness', 64)

    expect(report.measurementScope).toBe('tracked-operation-buffers')
    expect(report.browserHeapPrecise).toBe(false)
    expect(report.precisionNote).toBe(PROOF_MEMORY_PRECISION_NOTE)
    expect(Object.keys(report.classes).sort()).toEqual([...PROOF_BUFFER_CLASSES].sort())

    const serialized = JSON.stringify(report)
    expect(serialized).not.toContain('credentialSecret')
    expect(serialized).not.toContain('nullifierSecret')
    expect(Object.isFrozen(report)).toBe(true)
    expect(Object.isFrozen(report.totals)).toBe(true)
    expect(Object.isFrozen(report.classes)).toBe(true)
  })

  it('enforces bounded class, budget, counter, and event limits without partial mutation', () => {
    const tracker = new ProofOperationMemoryTracker({
      budgetLimitBytes: 1_000,
      classLimits: { witness: 600 },
      maxAllocationEventsPerOperation: 3,
      counterCeilingBytes: 1_200,
    })

    tracker.recordAllocation('op-bounds', 'witness', 600)
    // 1 byte over witness class limit
    expect(() => tracker.recordAllocation('op-bounds', 'witness', 1)).toThrowError(
      new CircuitInputError('proof_worker_memory_exceeded'),
    )
    expect(tracker.getReport('op-bounds')?.classes.witness.activeBytes).toBe(600)

    // Exceeds per-operation budget (600 + 401 > 1000)
    expect(() => tracker.recordAllocation('op-bounds', 'artifact', 401)).toThrowError(
      new CircuitInputError('proof_worker_memory_exceeded'),
    )
    expect(tracker.getReport('op-bounds')?.totals.activeBytes).toBe(600)

    // Release 500 so activeBytes = 100, allocate 500 (allocatedBytes = 1100, event 2)
    tracker.recordRelease('op-bounds', 'witness', 500)
    tracker.recordAllocation('op-bounds', 'witness', 500)
    expect(tracker.getReport('op-bounds')?.totals.allocatedBytes).toBe(1_100)

    // Exceeds cumulative counterCeilingBytes (1100 + 200 > 1200)
    expect(() => tracker.recordAllocation('op-bounds', 'artifact', 200)).toThrowError(
      new CircuitInputError('proof_worker_memory_exceeded'),
    )

    // Event 3 succeeds (1100 + 50 <= 1200), event 4 exceeds maxAllocationEventsPerOperation (3)
    tracker.recordAllocation('op-bounds', 'artifact', 50)
    expect(() => tracker.recordAllocation('op-bounds', 'artifact', 10)).toThrowError(
      new CircuitInputError('proof_worker_memory_exceeded'),
    )
  })

  it('rejects over-release, negative/non-integer sizes, invalid operation ids, and post-complete edits', () => {
    const tracker = new ProofOperationMemoryTracker()
    tracker.recordAllocation('op-guard', 'proof', 256)

    expect(() => tracker.recordRelease('op-guard', 'proof', 257)).toThrowError(
      new CircuitInputError('invalid_input'),
    )
    expect(() => tracker.recordAllocation('op-guard', 'proof', -1)).toThrowError(
      new CircuitInputError('invalid_input'),
    )
    expect(() => tracker.recordAllocation('op-guard', 'proof', Number.NaN)).toThrowError(
      new CircuitInputError('invalid_input'),
    )
    expect(() => tracker.recordAllocation('op-guard', 'proof', 1.5)).toThrowError(
      new CircuitInputError('invalid_input'),
    )
    expect(() =>
      tracker.recordAllocation('bad id with spaces and witness=0xdeadbeef', 'witness', 16),
    ).toThrowError(new CircuitInputError('invalid_input'))

    tracker.completeOperation('op-guard')
    expect(() => tracker.recordAllocation('op-guard', 'proof', 1)).toThrowError(
      new CircuitInputError('invalid_input'),
    )
    expect(() => tracker.recordRelease('op-guard', 'proof', 1)).toThrowError(
      new CircuitInputError('invalid_input'),
    )
  })

  it('bounds tracked operation slots by evicting completed entries and rejecting active overflow', () => {
    const tracker = new ProofOperationMemoryTracker({ maxTrackedOperations: 2 })
    tracker.recordAllocation('op-a', 'witness', 32)
    tracker.completeOperation('op-a')

    tracker.recordAllocation('op-b', 'witness', 32)
    // Evicts completed op-a to admit op-c
    tracker.recordAllocation('op-c', 'witness', 32)
    expect(tracker.getReport('op-a')).toBeNull()
    expect(tracker.getReport('op-b')?.status).toBe('active')
    expect(tracker.getReport('op-c')?.status).toBe('active')

    // Both slots are active -> must fail closed rather than dropping active accounting
    expect(() => tracker.recordAllocation('op-d', 'witness', 32)).toThrowError(
      new CircuitInputError('proof_worker_memory_exceeded'),
    )
  })

  it('integrates per-operation accounting with ProofWorkerManager lifecycle', () => {
    const manager = new ProofWorkerManager()
    const started = manager.startOperationMemory('mgr-op-1')
    expect(started.budgetLimitBytes).toBeLessThanOrEqual(PROOF_WORKER_MEMORY_LIMITS.maxRuntimeBytes)

    manager.recordOperationAllocation('mgr-op-1', 'witness', 512)
    manager.recordOperationAllocation('mgr-op-1', 'public_input', 128)
    manager.recordOperationRelease('mgr-op-1', 'witness', 512)
    const finalReport = manager.completeOperationMemory('mgr-op-1')

    expect(finalReport.status).toBe('completed')
    expect(finalReport.totals.allocatedBytes).toBe(640)
    expect(finalReport.totals.releasedBytes).toBe(512)
    expect(finalReport.totals.activeBytes).toBe(128)
    expect(finalReport.browserHeapPrecise).toBe(false)

    manager.destroy()
    expect(manager.getOperationMemoryReport('mgr-op-1')).toBeNull()
  })
})
