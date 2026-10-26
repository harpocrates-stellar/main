/** Error raised when a backend request exceeds its configured deadline. */
export class RequestTimeoutError extends Error {
  readonly code = 'timeout' as const

  constructor(timeoutMs: number) {
    super(`Request timed out after ${timeoutMs} ms.`)
    this.name = 'RequestTimeoutError'
  }
}

function createTimeoutSignal(timeoutMs: number): { signal: AbortSignal; cleanup: () => void } {
  if (typeof AbortSignal.timeout === 'function') {
    return { signal: AbortSignal.timeout(timeoutMs), cleanup: () => undefined }
  }

  const controller = new AbortController()
  const timeoutId = setTimeout(
    () => controller.abort(new DOMException(`Timed out after ${timeoutMs} ms.`, 'TimeoutError')),
    timeoutMs,
  )
  return { signal: controller.signal, cleanup: () => clearTimeout(timeoutId) }
}

function combineSignals(signals: AbortSignal[]): { signal: AbortSignal; cleanup: () => void } {
  if (typeof AbortSignal.any === 'function') {
    return { signal: AbortSignal.any(signals), cleanup: () => undefined }
  }

  const controller = new AbortController()
  const abortFrom = (signal: AbortSignal) => {
    if (!controller.signal.aborted) controller.abort(signal.reason)
  }
  const listeners = signals.map((signal) => {
    const listener = () => abortFrom(signal)
    if (signal.aborted) listener()
    else signal.addEventListener('abort', listener, { once: true })
    return { signal, listener }
  })

  return {
    signal: controller.signal,
    cleanup: () => listeners.forEach(({ signal, listener }) => signal.removeEventListener('abort', listener)),
  }
}

/** Fetch with a deadline while preserving a caller-provided cancellation signal. */
export async function fetchWithTimeout(
  url: string | URL | Request,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError('timeoutMs must be a positive number.')
  }

  const callerSignal = init.signal ?? undefined
  if (callerSignal?.aborted) {
    throw callerSignal.reason ?? new DOMException('Aborted', 'AbortError')
  }

  const timeout = createTimeoutSignal(timeoutMs)
  const combined = callerSignal
    ? combineSignals([timeout.signal, callerSignal])
    : { signal: timeout.signal, cleanup: () => undefined }
  let abortListener: (() => void) | undefined
  let cleanedUp = false
  const cleanup = () => {
    if (cleanedUp) return
    cleanedUp = true
    if (abortListener) combined.signal.removeEventListener('abort', abortListener)
    combined.cleanup()
    timeout.cleanup()
  }
  const aborted = new Promise<never>((_resolve, reject) => {
    abortListener = () => {
      if (callerSignal?.aborted) {
        reject(callerSignal.reason ?? new DOMException('Aborted', 'AbortError'))
      } else if (timeout.signal.aborted) {
        reject(new RequestTimeoutError(timeoutMs))
      }
      cleanup()
    }
    if (combined.signal.aborted) abortListener()
    else combined.signal.addEventListener('abort', abortListener, { once: true })
  })
  // A caller may use only response status/headers and never invoke a body reader.
  // Mark the shared rejection handled while preserving it for the races below.
  void aborted.catch(() => undefined)

  try {
    const response = await Promise.race([
      fetch(url, { ...init, signal: combined.signal }),
      aborted,
    ])
    const bodyMethods = new Set(['arrayBuffer', 'blob', 'formData', 'json', 'text'])
    return new Proxy(response, {
      get(target, property) {
        const value = Reflect.get(target, property, target)
        if (typeof property === 'string' && bodyMethods.has(property) && typeof value === 'function') {
          return (...args: unknown[]) =>
            Promise.race([
              Promise.resolve().then(() => Reflect.apply(value, target, args)),
              aborted,
            ]).finally(cleanup)
        }
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
  } catch (error) {
    cleanup()
    throw error
  }
}

export const JSON_REQUEST_TIMEOUT_MS = 15_000
const DEFAULT_UPLOAD_TIMEOUT_MS = 300_000
const configuredUploadTimeout = Number(import.meta.env.VITE_UPLOAD_TIMEOUT_MS)
export const UPLOAD_TIMEOUT_MS = Number.isFinite(configuredUploadTimeout) && configuredUploadTimeout > 0
  ? configuredUploadTimeout
  : DEFAULT_UPLOAD_TIMEOUT_MS