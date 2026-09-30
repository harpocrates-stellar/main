import { afterEach, describe, expect, it, vi } from 'vitest'
import { hashFileInWorker } from './fileHashWorkerClient'
import type { FileHashWorkerResponse } from './fileHashWorker.types'

class MockWorker {
  static latest: MockWorker
  onmessage: ((event: MessageEvent<FileHashWorkerResponse>) => void) | null = null
  onerror: ((event: ErrorEvent) => void) | null = null
  onmessageerror: (() => void) | null = null
  postMessage = vi.fn()
  terminate = vi.fn()

  constructor() {
    MockWorker.latest = this
  }

  send(data: FileHashWorkerResponse) {
    this.onmessage?.({ data } as MessageEvent<FileHashWorkerResponse>)
  }
}

describe('hashFileInWorker', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    MockWorker.latest = undefined as unknown as MockWorker
  })

  it('forwards progress and resolves the worker digest', async () => {
    vi.stubGlobal('Worker', MockWorker)
    const onProgress = vi.fn()
    const file = new File(['evidence'], 'evidence.mp4')
    const result = hashFileInWorker(file, onProgress)
    const worker = MockWorker.latest
    const progress = { processedBytes: 8, totalBytes: 8, percentage: 100 }

    worker.send({ type: 'PROGRESS', progress })
    worker.send({ type: 'RESULT', hash: 'a'.repeat(64) })

    await expect(result).resolves.toBe('a'.repeat(64))
    expect(onProgress).toHaveBeenCalledWith(progress)
    expect(worker.postMessage).toHaveBeenCalledWith({ type: 'HASH', file })
    expect(worker.terminate).toHaveBeenCalledOnce()
  })

  it('terminates the worker and rejects with AbortError when cancelled', async () => {
    vi.stubGlobal('Worker', MockWorker)
    const controller = new AbortController()
    const result = hashFileInWorker(
      new File(['evidence'], 'evidence.mp4'),
      vi.fn(),
      controller.signal,
    )
    const worker = MockWorker.latest

    controller.abort()

    await expect(result).rejects.toMatchObject({ name: 'AbortError' })
    expect(worker.terminate).toHaveBeenCalledOnce()
  })

  it('does not expose worker error details', async () => {
    vi.stubGlobal('Worker', MockWorker)
    const result = hashFileInWorker(new File(['evidence'], 'private-name.mp4'), vi.fn())
    MockWorker.latest.send({
      type: 'ERROR',
      message: 'Evidence hashing failed.',
    })

    await expect(result).rejects.toThrow('Evidence hashing failed.')
    expect(MockWorker.latest.terminate).toHaveBeenCalledOnce()
  })

  it('rejects with AbortError without spawning a worker when the signal is already aborted', async () => {
    vi.stubGlobal('Worker', MockWorker)
    const controller = new AbortController()
    controller.abort()

    await expect(
      hashFileInWorker(new File(['evidence'], 'evidence.mp4'), vi.fn(), controller.signal),
    ).rejects.toMatchObject({ name: 'AbortError' })
    expect(MockWorker.latest).toBeUndefined()
  })

  it('ignores stale messages that arrive after the promise settles', async () => {
    vi.stubGlobal('Worker', MockWorker)
    const onProgress = vi.fn()
    const result = hashFileInWorker(new File(['evidence'], 'evidence.mp4'), onProgress)
    const worker = MockWorker.latest

    worker.send({ type: 'RESULT', hash: 'a'.repeat(64) })
    await expect(result).resolves.toBe('a'.repeat(64))

    worker.send({
      type: 'PROGRESS',
      progress: { processedBytes: 1, totalBytes: 4, percentage: 25 },
    })
    worker.send({ type: 'ERROR', message: 'Evidence hashing failed.' })

    expect(onProgress).not.toHaveBeenCalled()
    expect(worker.terminate).toHaveBeenCalledOnce()
  })

  it('removes its abort listener once the hash settles', async () => {
    vi.stubGlobal('Worker', MockWorker)
    const controller = new AbortController()
    const removeListener = vi.spyOn(controller.signal, 'removeEventListener')
    const result = hashFileInWorker(new File(['evidence'], 'evidence.mp4'), vi.fn(), controller.signal)
    const worker = MockWorker.latest

    worker.send({ type: 'RESULT', hash: 'b'.repeat(64) })
    await expect(result).resolves.toBe('b'.repeat(64))

    expect(removeListener).toHaveBeenCalledWith('abort', expect.any(Function))
    expect(worker.terminate).toHaveBeenCalledOnce()
  })
})
