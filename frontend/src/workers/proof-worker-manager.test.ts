import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_TEARDOWN_TIMEOUT_MS, ProofWorkerManager } from './proof-worker-manager'
import { ProofWorkerLogger } from './proof-worker-logger'
import type { ProofWorkerMessage, ProofWorkerResponse } from './proof.worker.types'

/**
 * `ProofWorkerManager` does not spawn a real worker yet: `init` only flips
 * the initialized flag, and the `postMessage` calls are commented out, so a
 * verify request settles only through its timeout. These tests pin that
 * behaviour, so wiring up a real worker later will show up as a test change.
 * A fake `Worker` is injected where the manager does touch one (`destroy`).
 */

const ALLOWED_ORIGIN = 'https://evidence-studio.example.com'

// Distinctive values; they must never appear in anything the logger receives.
const EVIDENCE = 'evidence-WITNESS-7f3a9c'
const PROOF = 'proof-SECRET-b81d2e'
const CONTRACT = 'C'.repeat(56)

type Internals = {
  worker: Worker | null
  messageHandlers: Map<string, (response: ProofWorkerResponse) => void>
  isInitialized: boolean
}

function internals(manager: ProofWorkerManager): Internals {
  return manager as unknown as Internals
}

class FakeWorker {
  static live = new Set<FakeWorker>()
  terminated = false
  listeners = new Map<string, Set<EventListener>>()
  posted: unknown[] = []
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: ErrorEvent) => void) | null = null

  constructor() {
    FakeWorker.live.add(this)
  }

  postMessage(message: unknown) {
    this.posted.push(message)
  }

  addEventListener(type: string, listener: EventListener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set())
    this.listeners.get(type)!.add(listener)
  }

  removeEventListener(type: string, listener: EventListener) {
    this.listeners.get(type)?.delete(listener)
  }

  emit(type: string, event: Event) {
    this.listeners.get(type)?.forEach((listener) => listener(event))
  }

  terminate() {
    this.terminated = true
    this.listeners.clear()
    FakeWorker.live.delete(this)
  }

  listenerCount() {
    let n = 0
    this.listeners.forEach((set) => (n += set.size))
    return n
  }
}

const managers: ProofWorkerManager[] = []
let logSpy: ReturnType<typeof vi.spyOn>

function createManager(config?: ConstructorParameters<typeof ProofWorkerManager>[0]) {
  const manager = new ProofWorkerManager(config)
  managers.push(manager)
  return manager
}

function loggedText(): string {
  return JSON.stringify(logSpy.mock.calls)
}

beforeEach(() => {
  logSpy = vi.spyOn(ProofWorkerLogger.prototype, 'log')
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'debug').mockImplementation(() => {})
})

afterEach(() => {
  while (managers.length) managers.pop()?.destroy()
  vi.useRealTimers()
  vi.restoreAllMocks()
  // No fake worker may outlive its test.
  expect(FakeWorker.live.size).toBe(0)
  FakeWorker.live.clear()
})

describe('ProofWorkerManager construction', () => {
  it('rejects an invalid CSP config', () => {
    expect(() => new ProofWorkerManager({ maxMemoryMB: 0 })).toThrow('Invalid maxMemoryMB')
    expect(() => new ProofWorkerManager({ maxExecutionTimeMs: 300001 })).toThrow('Invalid maxExecutionTimeMs')
  })
})

describe('init', () => {
  it('initializes without an origin and logs the CSP config only', async () => {
    const manager = createManager()

    await manager.init()

    expect(internals(manager).isInitialized).toBe(true)
    expect(logSpy).toHaveBeenCalledWith('info', 'Worker manager initialized', expect.objectContaining({ cspConfig: expect.any(Object) }))
  })

  it('accepts an allowed origin', async () => {
    const manager = createManager()

    await expect(manager.init(ALLOWED_ORIGIN)).resolves.toBeUndefined()
    expect(internals(manager).isInitialized).toBe(true)
  })

  it('rejects an origin that is not allowed and stays uninitialized', async () => {
    const manager = createManager()

    await expect(manager.init('https://evil.example')).rejects.toThrow('Origin not allowed: https://evil.example')
    expect(internals(manager).isInitialized).toBe(false)
    await expect(manager.verifyProof(EVIDENCE, PROOF, CONTRACT)).rejects.toThrow('Worker manager not initialized')
  })

  it('warns and does nothing on a second init', async () => {
    const manager = createManager()
    await manager.init()
    logSpy.mockClear()

    await manager.init()

    expect(logSpy).toHaveBeenCalledTimes(1)
    expect(logSpy).toHaveBeenCalledWith('warn', 'Worker already initialized', undefined)
  })
})

describe('verifyProof', () => {
  it('refuses to run before init', async () => {
    const manager = createManager()

    await expect(manager.verifyProof(EVIDENCE, PROOF, CONTRACT)).rejects.toThrow('Worker manager not initialized')
  })

  it('registers a handler, then times out and removes it', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const pending = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 500)
    const assertion = expect(pending).rejects.toThrow('Verification timed out')
    expect(internals(manager).messageHandlers.size).toBe(1)

    await vi.advanceTimersByTimeAsync(499)
    expect(internals(manager).messageHandlers.size).toBe(1)
    await vi.advanceTimersByTimeAsync(1)

    await assertion
    expect(internals(manager).messageHandlers.size).toBe(0)
  })

  it('falls back to the CSP maxExecutionTimeMs when no timeout is given', async () => {
    vi.useFakeTimers()
    const manager = createManager({ maxExecutionTimeMs: 2000 })
    await manager.init()

    const pending = manager.verifyProof(EVIDENCE, PROOF, CONTRACT)
    const assertion = expect(pending).rejects.toThrow('Verification timed out')

    await vi.advanceTimersByTimeAsync(1999)
    expect(internals(manager).messageHandlers.size).toBe(1)
    await vi.advanceTimersByTimeAsync(1)
    await assertion
  })

  it('resolves with the response and clears its timer when its handler is called', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const pending = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 1000)
    const [id, handler] = [...internals(manager).messageHandlers.entries()][0]
    const response: ProofWorkerResponse = { type: 'success', id, data: { valid: true } }
    handler(response)

    await expect(pending).resolves.toEqual(response)
    expect(internals(manager).messageHandlers.size).toBe(0)
    // The timeout was cleared: advancing past it must not reject anything.
    await vi.advanceTimersByTimeAsync(5000)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('keeps concurrent requests independent, each with its own id and timeout', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const short = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 100)
    const long = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 300)
    const shortDone = expect(short).rejects.toThrow('Verification timed out')
    const ids = [...internals(manager).messageHandlers.keys()]
    expect(ids).toHaveLength(2)
    expect(new Set(ids).size).toBe(2)

    await vi.advanceTimersByTimeAsync(100)
    await shortDone
    expect([...internals(manager).messageHandlers.keys()]).toEqual([ids[1]])

    const longDone = expect(long).rejects.toThrow('Verification timed out')
    await vi.advanceTimersByTimeAsync(200)
    await longDone
    expect(internals(manager).messageHandlers.size).toBe(0)
  })

  it('is not settled by unexpected worker messages or worker errors (no listener is attached)', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()
    const fake = new FakeWorker()
    internals(manager).worker = fake as unknown as Worker

    const pending = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 200)
    const assertion = expect(pending).rejects.toThrow('Verification timed out')
    fake.emit('message', new MessageEvent('message', { data: { type: 'bogus', id: 'nope' } }))
    fake.emit('error', new Event('error'))

    expect(fake.listenerCount()).toBe(0)
    expect(fake.posted).toEqual([])
    expect(internals(manager).messageHandlers.size).toBe(1)

    await vi.advanceTimersByTimeAsync(200)
    await assertion
  })

  it('never passes evidence or proof material to the logger', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const pending = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 50)
    const assertion = expect(pending).rejects.toThrow()
    await vi.advanceTimersByTimeAsync(50)
    await assertion
    await manager.cancelProof()
    manager.destroy()

    const text = loggedText()
    expect(text).toContain('Sending verify message')
    expect(text).not.toContain(EVIDENCE)
    expect(text).not.toContain(PROOF)
    for (const call of logSpy.mock.calls) {
      const context = call[2] as Record<string, unknown> | undefined
      if (!context) continue
      for (const key of Object.keys(context)) {
        expect(key).not.toMatch(/evidence|proof|witness|secret|nullifier/i)
      }
    }
  })
})

describe('cancelProof', () => {
  it('refuses to run before init', async () => {
    const manager = createManager()

    await expect(manager.cancelProof()).rejects.toThrow('Worker manager not initialized')
  })

  it('logs a cancel message id and leaves pending verify handlers alone', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()
    const pending = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 100)
    const assertion = expect(pending).rejects.toThrow('Verification timed out')

    await expect(manager.cancelProof()).resolves.toBeUndefined()

    expect(logSpy).toHaveBeenCalledWith('info', 'Sending cancel message', { id: expect.stringMatching(/^cancel_\d+$/) })
    expect(internals(manager).messageHandlers.size).toBe(1)
    await vi.advanceTimersByTimeAsync(100)
    await assertion
  })
})

describe('getStatus and getCSPHeaders', () => {
  it('reports an idle worker', () => {
    expect(createManager().getStatus()).toEqual({ isRunning: false, currentTaskId: undefined, memoryUsage: undefined })
  })

  it('returns the sandbox CSP headers', () => {
    const headers = createManager().getCSPHeaders()

    expect(headers['Content-Security-Policy']).toContain("default-src 'none'")
    expect(headers['Content-Security-Policy']).toContain("worker-src 'self'")
    expect(headers['X-Frame-Options']).toBe('DENY')
    expect(headers['X-Content-Type-Options']).toBe('nosniff')
  })

  it('omits the CSP header when sandbox is off', () => {
    const headers = createManager({ sandbox: false }).getCSPHeaders()

    expect(headers['Content-Security-Policy']).toBeUndefined()
    expect(headers['X-Frame-Options']).toBe('DENY')
  })
})

describe('offline worker capability report', () => {
  const capableGlobal = {
    Worker: FakeWorker,
    WebAssembly: function WebAssembly() {},
    crypto: { subtle: {} },
    BigInt,
    ArrayBuffer,
  } as unknown as typeof globalThis

  it('inspects required browser features and configured artifact metadata offline without network or worker init', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('fetch must not be called during offline capability inspection')
    })
    const manager = createManager({ maxMemoryMB: 256, maxExecutionTimeMs: 45000 })

    const report = manager.getOfflineCapabilityReport({ globalObj: capableGlobal })

    expect(report.offline).toBe(true)
    expect(report.ready).toBe(true)
    expect(report.issues).toEqual([])
    expect(report.browser.ok).toBe(true)
    expect(report.browser.tier).toBe('supported')
    expect(report.browser.missing).toEqual([])
    expect(report.artifacts.publishedArtifactCount).toBeGreaterThan(0)
    expect(report.artifacts.allArtifactsWithinLimit).toBe(true)
    expect(report.csp).toEqual({
      sandbox: true,
      maxMemoryMB: 256,
      maxExecutionTimeMs: 45000,
      allowedOriginsCount: 2,
    })
    expect(internals(manager).isInitialized).toBe(false)
    expect(internals(manager).worker).toBeNull()
    expect(FakeWorker.live.size).toBe(0)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('fails closed when required browser capabilities are missing', () => {
    const missingCapabilitiesGlobal = {
      BigInt,
      ArrayBuffer,
    } as unknown as typeof globalThis

    const report = createManager().getOfflineCapabilityReport({
      globalObj: missingCapabilitiesGlobal,
    })

    expect(report.offline).toBe(true)
    expect(report.ready).toBe(false)
    expect(report.browser.ok).toBe(false)
    expect(report.browser.tier).toBe('unsupported')
    expect(report.browser.missing).toEqual(['Worker', 'moduleWorkerType', 'WebAssembly', 'SubtleCrypto'])
    expect(report.issues).toContain(report.browser.reason)
  })

  it('fails closed when configured artifact metadata is empty or exceeds limits', () => {
    const emptyManifestReport = buildOfflineWorkerCapabilityReport({
      globalObj: capableGlobal,
      manifest: { format: 'test', version: 1, artifacts: [] },
    })
    expect(emptyManifestReport.ready).toBe(false)
    expect(emptyManifestReport.issues).toContain(
      'No published proving artifacts configured in manifest.',
    )

    const oversizedArtifactReport = buildOfflineWorkerCapabilityReport({
      globalObj: capableGlobal,
      cspConfig: { maxMemoryMB: 1 },
      manifest: {
        format: 'test',
        version: 1,
        artifacts: [
          {
            path: 'frontend/public/noir/oversized.json',
            raw_bytes: PROOF_WORKER_MEMORY_LIMITS.maxArtifactBytes + 1,
          },
        ],
      },
    })
    expect(oversizedArtifactReport.ready).toBe(false)
    expect(oversizedArtifactReport.artifacts.allArtifactsWithinLimit).toBe(false)
    expect(oversizedArtifactReport.issues).toContain(
      'One or more configured proving artifacts exceed the worker artifact byte limit.',
    )
  })
})

describe('destroy', () => {
  it('terminates the worker, clears handlers and resets initialization', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()
    const fake = new FakeWorker()
    fake.addEventListener('message', () => {})
    internals(manager).worker = fake as unknown as Worker
    const pending = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 100)
    pending.catch(() => {})

    manager.destroy()

    expect(fake.terminated).toBe(true)
    expect(fake.listenerCount()).toBe(0)
    expect(internals(manager).worker).toBeNull()
    expect(internals(manager).messageHandlers.size).toBe(0)
    expect(internals(manager).isInitialized).toBe(false)
    await expect(manager.verifyProof(EVIDENCE, PROOF, CONTRACT)).rejects.toThrow('Worker manager not initialized')
    await vi.advanceTimersByTimeAsync(100)
  })

  it('is safe without a worker and can be re-initialized afterwards', async () => {
    const manager = createManager()
    await manager.init()

    expect(() => manager.destroy()).not.toThrow()
    expect(() => manager.destroy()).not.toThrow()
    await manager.init()
    expect(internals(manager).isInitialized).toBe(true)
  })
})


describe('single ownership protocol and operation generations', () => {
  it('enforces single ownership and advances generation monotonically', async () => {
    const manager = createManager()
    await manager.init()

    const first = manager.acquireOwnership('op-1')
    expect(first).toEqual({ generation: 1, operationId: 'op-1' })
    expect(manager.getActiveOwner()).toEqual(first)
    expect(manager.getGeneration()).toBe(1)

    expect(() => manager.acquireOwnership('op-2')).toThrow('Worker ownership already held by an active operation')

    // Mismatched token cannot release ownership
    expect(manager.releaseOwnership({ generation: 99, operationId: 'op-1' })).toBe(false)
    expect(manager.releaseOwnership({ generation: 1, operationId: 'op-other' })).toBe(false)
    expect(manager.getActiveOwner()).toEqual(first)

    // Matching token releases ownership and allows the next owner
    expect(manager.releaseOwnership(first)).toBe(true)
    expect(manager.getActiveOwner()).toBeNull()

    const second = manager.acquireOwnership('op-2')
    expect(second).toEqual({ generation: 2, operationId: 'op-2' })
    expect(manager.getGeneration()).toBe(2)
  })

  it('tracks operation generations across worker replacement and restart', async () => {
    const manager = createManager()
    await manager.init()

    const worker1 = new FakeWorker()
    const worker2 = new FakeWorker()
    const worker3 = new FakeWorker()

    internals(manager).worker = worker1 as unknown as Worker
    const owner1 = manager.acquireOwnership('op-gen-1')
    expect(owner1.generation).toBe(1)

    const genAfterReplace = manager.replaceWorker(worker2 as unknown as Worker)
    expect(worker1.terminated).toBe(true)
    expect(worker2.terminated).toBe(false)
    expect(manager.getActiveOwner()).toBeNull()
    expect(genAfterReplace).toBe(2)
    expect(manager.getGeneration()).toBe(2)

    const owner2 = manager.acquireOwnership('op-gen-2')
    expect(owner2.generation).toBe(3)

    const genAfterRestart = manager.restartWorker(worker3 as unknown as Worker)
    expect(worker2.terminated).toBe(true)
    expect(worker3.terminated).toBe(false)
    expect(manager.getActiveOwner()).toBeNull()
    expect(genAfterRestart).toBe(4)
  })

  it('accepts progress and proof messages for the active owner generation', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const progressEvents: ProofWorkerResponse[] = []
    const pending = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 1000, (event) => {
      progressEvents.push(event)
    })
    const [messageId] = [...internals(manager).messageHandlers.keys()]
    const gen = manager.getGeneration()

    const progressResult = manager.handleWorkerMessage({
      type: 'progress',
      id: messageId,
      generation: gen,
      data: { stage: 'generating_proof', percent: 50 },
    })
    expect(progressResult).toEqual({ accepted: true, generation: gen, operationId: messageId })
    expect(progressEvents).toHaveLength(1)
    expect(progressEvents[0].data?.stage).toBe('generating_proof')

    const proofResponse: ProofWorkerResponse = {
      type: 'success',
      id: messageId,
      generation: gen,
      data: { valid: true },
    }
    const proofResult = manager.handleWorkerMessage(proofResponse)
    expect(proofResult).toEqual({ accepted: true, generation: gen, operationId: messageId })
    await expect(pending).resolves.toEqual(proofResponse)
  })

  it('rejects stale progress and proof messages after cancellation', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const progressEvents: ProofWorkerResponse[] = []
    const pending = manager.verifyProof(EVIDENCE, PROOF, CONTRACT, 500, (event) => {
      progressEvents.push(event)
    })
    const [messageId] = [...internals(manager).messageHandlers.keys()]
    const staleGen = manager.getGeneration()

    await manager.cancelProof()
    expect(manager.getGeneration()).toBeGreaterThan(staleGen)

    const staleProgress = manager.handleWorkerMessage({
      type: 'progress',
      id: messageId,
      generation: staleGen,
      data: { stage: 'executing_main', percent: 75 },
    })
    expect(staleProgress).toEqual({
      accepted: false,
      reason: 'cancelled',
      expectedGeneration: manager.getGeneration(),
      receivedGeneration: staleGen,
    })

    const staleProof = manager.handleWorkerMessage({
      type: 'success',
      id: messageId,
      generation: staleGen,
      data: { valid: true },
    })
    expect(staleProof).toEqual({
      accepted: false,
      reason: 'cancelled',
      expectedGeneration: manager.getGeneration(),
      receivedGeneration: staleGen,
    })
    expect(progressEvents).toHaveLength(0)

    const assertion = expect(pending).rejects.toThrow('Verification timed out')
    await vi.advanceTimersByTimeAsync(500)
    await assertion
  })

  it('rejects stale progress and proof messages after worker restart', async () => {
    const manager = createManager()
    await manager.init()

    const worker1 = new FakeWorker()
    const worker2 = new FakeWorker()
    internals(manager).worker = worker1 as unknown as Worker

    const oldOwner = manager.acquireOwnership('op-before-restart')
    manager.restartWorker(worker2 as unknown as Worker)
    const newOwner = manager.acquireOwnership('op-after-restart')

    // Stale progress from the replaced worker's generation is rejected
    const staleProgress = manager.handleWorkerMessage({
      type: 'progress',
      id: oldOwner.operationId,
      generation: oldOwner.generation,
      data: { stage: 'loading_circuits', percent: 20 },
    })
    expect(staleProgress).toEqual({
      accepted: false,
      reason: 'cancelled',
      expectedGeneration: newOwner.generation,
      receivedGeneration: oldOwner.generation,
    })

    // Stale proof result from the replaced worker's generation is rejected
    const staleProof = manager.handleWorkerMessage({
      type: 'success',
      id: oldOwner.operationId,
      generation: oldOwner.generation,
      data: { valid: true },
    })
    expect(staleProof).toEqual({
      accepted: false,
      reason: 'cancelled',
      expectedGeneration: newOwner.generation,
      receivedGeneration: oldOwner.generation,
    })

    // Active owner's generation is accepted
    const activeProgress = manager.handleWorkerMessage({
      type: 'progress',
      id: newOwner.operationId,
      generation: newOwner.generation,
      data: { stage: 'generating_proof', percent: 60 },
    })
    expect(activeProgress).toEqual({
      accepted: true,
      generation: newOwner.generation,
      operationId: newOwner.operationId,
    })
  })

  it('fails closed for uninitialized manager, missing generation, or unowned operation', async () => {
    const manager = createManager()

    expect(
      manager.handleWorkerMessage({ type: 'progress', id: 'op-1', generation: 1 }),
    ).toEqual({
      accepted: false,
      reason: 'not_initialized',
      expectedGeneration: 0,
      receivedGeneration: 1,
    })

    await manager.init()
    const owner = manager.acquireOwnership('op-owned')

    expect(
      manager.handleWorkerMessage({ type: 'progress', id: 'op-owned' }),
    ).toEqual({
      accepted: false,
      reason: 'stale_generation',
      expectedGeneration: owner.generation,
      receivedGeneration: undefined,
    })

    expect(
      manager.handleWorkerMessage({
        type: 'success',
        id: 'op-wrong',
        generation: owner.generation,
        data: { valid: true },
      }),
    ).toEqual({
      accepted: false,
      reason: 'unowned_operation',
      expectedGeneration: owner.generation,
      receivedGeneration: owner.generation,
    })
  })
})

describe('explicit worker teardown acknowledgement', () => {
  it('confirms teardown when teardown_ack arrives within the bounded interval', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const fake = new FakeWorker()
    internals(manager).worker = fake as unknown as Worker
    const owner = manager.acquireOwnership('op-teardown-confirmed')

    const teardownPromise = manager.cancelAndTeardown({ timeoutMs: 250 })
    expect(fake.posted).toHaveLength(1)
    const cancelMsg = fake.posted[0] as ProofWorkerMessage
    expect(cancelMsg.type).toBe('cancel')
    expect(cancelMsg.id).toMatch(/^cancel_/)
    expect(cancelMsg.generation).toBe(owner.generation + 1)
    expect(fake.terminated).toBe(false)

    // Acknowledge before the bounded interval expires
    await vi.advanceTimersByTimeAsync(100)
    const dispatch = manager.handleWorkerMessage({
      type: 'teardown_ack',
      id: cancelMsg.id,
      generation: cancelMsg.generation,
      data: { message: 'Teardown acknowledged' },
    })
    expect(dispatch).toEqual({
      accepted: true,
      generation: cancelMsg.generation,
      operationId: cancelMsg.id,
    })

    const result = await teardownPromise
    expect(result).toEqual({
      status: 'confirmed',
      confirmed: true,
      forced: false,
      generation: cancelMsg.generation,
      cancelId: cancelMsg.id,
      timeoutMs: 250,
    })
    expect(manager.getLastTeardownResult()).toEqual(result)
    expect(fake.terminated).toBe(false)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('forcibly terminates the worker when teardown_ack does not arrive within the bounded interval', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const fake = new FakeWorker()
    internals(manager).worker = fake as unknown as Worker
    const owner = manager.acquireOwnership('op-teardown-forced')

    const teardownPromise = manager.cancelAndTeardown({ timeoutMs: 300 })
    const cancelMsg = fake.posted[0] as ProofWorkerMessage

    await vi.advanceTimersByTimeAsync(299)
    expect(fake.terminated).toBe(false)

    await vi.advanceTimersByTimeAsync(1)
    const result = await teardownPromise
    expect(result).toEqual({
      status: 'forced',
      confirmed: false,
      forced: true,
      generation: owner.generation + 1,
      cancelId: cancelMsg.id,
      timeoutMs: 300,
    })
    expect(manager.getLastTeardownResult()).toEqual(result)
    expect(fake.terminated).toBe(true)
    expect(internals(manager).worker).toBeNull()
  })

  it('uses DEFAULT_TEARDOWN_TIMEOUT_MS when no timeoutMs option is provided', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const fake = new FakeWorker()
    internals(manager).worker = fake as unknown as Worker

    const teardownPromise = manager.cancelAndTeardown()
    await vi.advanceTimersByTimeAsync(DEFAULT_TEARDOWN_TIMEOUT_MS - 1)
    expect(fake.terminated).toBe(false)

    await vi.advanceTimersByTimeAsync(1)
    const result = await teardownPromise
    expect(result.status).toBe('forced')
    expect(result.timeoutMs).toBe(DEFAULT_TEARDOWN_TIMEOUT_MS)
    expect(fake.terminated).toBe(true)
  })

  it('fails closed on mismatched or unknown teardown_ack and rejects invalid inputs', async () => {
    vi.useFakeTimers()
    const uninitialized = createManager()
    await expect(uninitialized.cancelAndTeardown()).rejects.toThrow('Worker manager not initialized')

    const manager = createManager()
    await manager.init()
    await expect(manager.cancelAndTeardown({ timeoutMs: 0 })).rejects.toThrow('Invalid teardown timeoutMs')
    await expect(manager.cancelAndTeardown({ timeoutMs: -50 })).rejects.toThrow('Invalid teardown timeoutMs')
    await expect(manager.cancelAndTeardown({ timeoutMs: Number.NaN })).rejects.toThrow('Invalid teardown timeoutMs')

    const fake = new FakeWorker()
    internals(manager).worker = fake as unknown as Worker
    const teardownPromise = manager.cancelAndTeardown({ timeoutMs: 100 })
    const cancelMsg = fake.posted[0] as ProofWorkerMessage

    // Unknown cancelId is rejected
    expect(
      manager.handleWorkerMessage({
        type: 'teardown_ack',
        id: 'cancel_unknown',
        generation: cancelMsg.generation,
      }),
    ).toEqual({
      accepted: false,
      reason: 'unowned_operation',
      expectedGeneration: cancelMsg.generation,
      receivedGeneration: cancelMsg.generation,
    })

    // Mismatched generation is rejected and does not confirm teardown
    expect(
      manager.handleWorkerMessage({
        type: 'teardown_ack',
        id: cancelMsg.id,
        generation: (cancelMsg.generation ?? 0) + 99,
      }),
    ).toEqual({
      accepted: false,
      reason: 'stale_generation',
      expectedGeneration: cancelMsg.generation,
      receivedGeneration: (cancelMsg.generation ?? 0) + 99,
    })

    await vi.advanceTimersByTimeAsync(100)
    const result = await teardownPromise
    expect(result.status).toBe('forced')
    expect(result.forced).toBe(true)
    expect(fake.terminated).toBe(true)
  })

  it('settles pending teardown as forced if destroy() is called before timeout', async () => {
    vi.useFakeTimers()
    const manager = createManager()
    await manager.init()

    const fake = new FakeWorker()
    internals(manager).worker = fake as unknown as Worker

    const teardownPromise = manager.cancelAndTeardown({ timeoutMs: 500 })
    manager.destroy()

    const result = await teardownPromise
    expect(result.status).toBe('forced')
    expect(result.confirmed).toBe(false)
    expect(result.forced).toBe(true)
    expect(fake.terminated).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
})
