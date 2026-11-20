import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ProofWorkerManager } from './proof-worker-manager'
import { ProofWorkerLogger } from './proof-worker-logger'
import type { ProofWorkerResponse } from './proof.worker.types'

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
