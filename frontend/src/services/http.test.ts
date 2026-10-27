import { afterEach, describe, expect, it, vi } from 'vitest'
import { fetchWithTimeout } from './http'

const originalTimeoutDescriptor = Object.getOwnPropertyDescriptor(AbortSignal, 'timeout')
const originalAnyDescriptor = Object.getOwnPropertyDescriptor(AbortSignal, 'any')

function restoreDescriptor(key: 'timeout' | 'any', descriptor: PropertyDescriptor | undefined) {
  if (descriptor) Object.defineProperty(AbortSignal, key, descriptor)
  else Reflect.deleteProperty(AbortSignal, key)
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  restoreDescriptor('timeout', originalTimeoutDescriptor)
  restoreDescriptor('any', originalAnyDescriptor)
})

describe('fetchWithTimeout', () => {
  it('rejects a stalled fetch with a distinct timeout code', async () => {
    vi.useFakeTimers()
    Object.defineProperty(AbortSignal, 'timeout', {
      configurable: true,
      value: (timeoutMs: number) => {
        const controller = new AbortController()
        setTimeout(() => controller.abort(new DOMException('Timed out', 'TimeoutError')), timeoutMs)
        return controller.signal
      },
    })
    const fetchMock = vi.fn(() => new Promise<Response>(() => undefined))
    vi.stubGlobal('fetch', fetchMock)

    const pending = fetchWithTimeout('/api/stalled', {}, 250)
    const timeoutExpectation = expect(pending).rejects.toMatchObject({ name: 'RequestTimeoutError', code: 'timeout' })
    await vi.advanceTimersByTimeAsync(250)

    await timeoutExpectation
    expect(fetchMock).toHaveBeenCalledOnce()
  })

  it('preserves caller cancellation when AbortSignal.any is unavailable', async () => {
    vi.useFakeTimers()
    Object.defineProperty(AbortSignal, 'timeout', {
      configurable: true,
      value: (timeoutMs: number) => {
        const controller = new AbortController()
        setTimeout(() => controller.abort(new DOMException('Timed out', 'TimeoutError')), timeoutMs)
        return controller.signal
      },
    })
    Object.defineProperty(AbortSignal, 'any', { configurable: true, value: undefined })
    const fetchMock = vi.fn(() => new Promise<Response>(() => undefined))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()

    const pending = fetchWithTimeout('/api/cancelled', { signal: controller.signal }, 1_000)
    controller.abort()

    await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(init.signal).not.toBe(controller.signal)
    expect(init.signal?.aborted).toBe(true)
  })

  it('keeps caller cancellation connected after response headers arrive', async () => {
    Object.defineProperty(AbortSignal, 'any', { configurable: true, value: undefined })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => new Promise<unknown>(() => undefined),
    } as Response))
    const controller = new AbortController()

    const response = await fetchWithTimeout('/api/body', { signal: controller.signal }, 1_000)
    const pendingBody = response.json()
    controller.abort()

    await expect(pendingBody).rejects.toMatchObject({ name: 'AbortError' })
  })
})