import { afterEach, describe, expect, it, vi } from 'vitest'
import { CircuitInputError } from '../circuitInputSchema'
import {
  DEFAULT_WORKER_TEARDOWN_TIMEOUT_MS,
  ProofWorkerManager,
  coordinateBoundedWorkerTeardown,
} from './proof-worker-manager'
import { ProofWorkerClient } from './proofWorkerClient'

class FakeTeardownWorker {
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: ErrorEvent) => void) | null = null
  onmessageerror: ((event: MessageEvent) => void) | null = null
  private listeners = new Set<EventListener>()
  terminated = false
  posted: unknown[] = []
  private readonly mode: 'ack_immediately' | 'ack_wrong_id' | 'hang' | 'throw_on_post'

  constructor(mode: 'ack_immediately' | 'ack_wrong_id' | 'hang' | 'throw_on_post') {
    this.mode = mode
  }

  addEventListener(type: string, listener: EventListener) {
    if (type === 'message') this.listeners.add(listener)
  }

  removeEventListener(type: string, listener: EventListener) {
    if (type === 'message') this.listeners.delete(listener)
  }

  private emitMessage(data: unknown) {
    const evt = new MessageEvent('message', { data })
    for (const listener of [...this.listeners]) {
      listener(evt)
    }
    this.onmessage?.(evt)
  }

  postMessage(message: unknown) {
    if (this.mode === 'throw_on_post') {
      throw new Error('worker channel closed')
    }
    this.posted.push(message)
    const record = message as { type?: string; id?: string; teardownId?: string }

    if (this.mode === 'ack_immediately') {
      if (record.type === 'teardown' && typeof record.id === 'string') {
        queueMicrotask(() => {
          if (!this.terminated) {
            this.emitMessage({
              type: 'teardown_ack',
              id: record.id,
              data: { resourcesCleaned: true },
            })
          }
        })
      } else if (record.type === 'TEARDOWN' && typeof record.teardownId === 'string') {
        queueMicrotask(() => {
          if (!this.terminated) {
            this.emitMessage({
              type: 'TEARDOWN_ACK',
              teardownId: record.teardownId,
              resourcesCleaned: true,
            })
          }
        })
      }
    } else if (this.mode === 'ack_wrong_id') {
      queueMicrotask(() => {
        if (!this.terminated) {
          this.emitMessage({
            type: 'teardown_ack',
            id: 'stale_teardown_id',
            data: { resourcesCleaned: true },
          })
        }
      })
    }
  }

  terminate() {
    this.terminated = true
    this.listeners.clear()
  }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('explicit worker teardown acknowledgement', () => {
  it('confirms teardown promptly when worker acknowledges resource cleanup within timeout', async () => {
    const manager = new ProofWorkerManager()
    await manager.init()
    const fakeWorker = new FakeTeardownWorker('ack_immediately')
    ;(manager as unknown as { worker: Worker }).worker = fakeWorker as unknown as Worker

    const result = await manager.cancelAndTeardown({
      timeoutMs: DEFAULT_WORKER_TEARDOWN_TIMEOUT_MS,
      teardownId: 'td-ack-1',
    })

    expect(result.outcome).toBe('acknowledged')
    expect(result.cleanupConfirmed).toBe(true)
    expect(result.forcedTermination).toBe(false)
    expect(result.terminated).toBe(true)
    expect(result.teardownId).toBe('td-ack-1')
    expect(fakeWorker.terminated).toBe(true)

    manager.destroy()
  })

  it('distinguishes forced termination when worker hangs past the bounded interval', async () => {
    vi.useFakeTimers()
    const manager = new ProofWorkerManager()
    await manager.init()
    const hungWorker = new FakeTeardownWorker('hang')
    ;(manager as unknown as { worker: Worker }).worker = hungWorker as unknown as Worker

    const pending = manager.cancelAndTeardown({
      timeoutMs: 120,
      teardownId: 'td-hung-1',
    })

    await vi.advanceTimersByTimeAsync(119)
    expect(hungWorker.terminated).toBe(false)

    await vi.advanceTimersByTimeAsync(1)
    const result = await pending

    expect(result.outcome).toBe('forced_termination')
    expect(result.cleanupConfirmed).toBe(false)
    expect(result.forcedTermination).toBe(true)
    expect(result.terminated).toBe(true)
    expect(hungWorker.terminated).toBe(true)

    manager.destroy()
  })

  it('ignores mismatched teardown acknowledgements and forces termination at deadline', async () => {
    vi.useFakeTimers()
    const wrongIdWorker = new FakeTeardownWorker('ack_wrong_id')
    const pending = coordinateBoundedWorkerTeardown(wrongIdWorker, {
      timeoutMs: 50,
      teardownId: 'expected-id',
    })

    await vi.advanceTimersByTimeAsync(50)
    const result = await pending
    expect(result.outcome).toBe('forced_termination')
    expect(result.cleanupConfirmed).toBe(false)
    expect(result.forcedTermination).toBe(true)
    expect(wrongIdWorker.terminated).toBe(true)
  })

  it('rejects unbounded or invalid teardown timeout intervals fail-closed', async () => {
    const manager = new ProofWorkerManager()
    await manager.init()

    await expect(manager.cancelAndTeardown({ timeoutMs: 0 })).rejects.toThrowError(
      new CircuitInputError('invalid_input'),
    )
    await expect(manager.cancelAndTeardown({ timeoutMs: -50 })).rejects.toThrowError(
      new CircuitInputError('invalid_input'),
    )
    await expect(manager.cancelAndTeardown({ timeoutMs: 60_000 })).rejects.toThrowError(
      new CircuitInputError('invalid_input'),
    )

    manager.destroy()
  })

  it('integrates bounded TEARDOWN_ACK into ProofWorkerClient cancellation and respawn', async () => {
    const workers: FakeTeardownWorker[] = []
    const modes: Array<'ack_immediately' | 'hang'> = ['ack_immediately', 'hang']
    let idx = 0

    const client = new ProofWorkerClient({
      runtime: 'worker',
      enableFallback: false,
      workerFactory: () => {
        const w = new FakeTeardownWorker(modes[idx++] ?? 'ack_immediately')
        workers.push(w)
        return w as unknown as Worker
      },
    })

    const run1 = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: '123',
      nullifierSecret: '456',
    })
    const ackResult = await client.cancelWithTeardownAck(run1.requestId, 100)
    await expect(run1.result).rejects.toMatchObject({ code: 'CANCELLED' })
    expect(ackResult.outcome).toBe('acknowledged')
    expect(ackResult.cleanupConfirmed).toBe(true)
    expect(workers[0].terminated).toBe(true)

    // Second worker is hung -> forced_termination after bounded timeout
    vi.useFakeTimers()
    const run2 = client.generate({
      videoHash: 'a'.repeat(64),
      credentialSecret: '123',
      nullifierSecret: '456',
    })
    const forcedPromise = client.cancelWithTeardownAck(run2.requestId, 80)
    await expect(run2.result).rejects.toMatchObject({ code: 'CANCELLED' })
    await vi.advanceTimersByTimeAsync(80)
    const forcedResult = await forcedPromise
    expect(forcedResult.outcome).toBe('forced_termination')
    expect(forcedResult.forcedTermination).toBe(true)
    expect(workers[1].terminated).toBe(true)

    client.destroy()
  })
})
