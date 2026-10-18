import type { HashProgress } from '../utils'
import type { FileHashWorkerRequest, FileHashWorkerResponse } from './fileHashWorker.types'

function cancelledError(): DOMException {
  return new DOMException('Evidence hashing cancelled.', 'AbortError')
}

/**
 * Hash a file incrementally in a dedicated Web Worker.
 *
 * Each call owns its own worker, so concurrent requests stay isolated.
 * Cancellation terminates the worker outright, and any message that arrives
 * after the promise settles is ignored (no stale progress or results).
 */
export function hashFileInWorker(
  file: File,
  onProgress?: (progress: HashProgress) => void,
  signal?: AbortSignal,
): Promise<string> {
  if (signal?.aborted) return Promise.reject(cancelledError())

  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./fileHashWorker.ts', import.meta.url), {
      type: 'module',
    })
    let settled = false

    const finish = (settle: () => void) => {
      if (settled) return
      settled = true
      signal?.removeEventListener('abort', handleAbort)
      worker.terminate()
      settle()
    }

    const handleAbort = () => finish(() => reject(cancelledError()))

    worker.onmessage = (event: MessageEvent<FileHashWorkerResponse>) => {
      if (settled) return
      const response = event.data
      if (response.type === 'PROGRESS') {
        onProgress?.(response.progress)
      } else if (response.type === 'RESULT') {
        finish(() => resolve(response.hash))
      } else {
        finish(() => reject(new Error(response.message)))
      }
    }
    worker.onerror = (event) => {
      event.preventDefault()
      finish(() => reject(new Error('Evidence hashing failed.')))
    }
    worker.onmessageerror = () => finish(() => reject(new Error('Evidence hashing failed.')))

    signal?.addEventListener('abort', handleAbort, { once: true })
    if (signal?.aborted) {
      handleAbort()
      return
    }

    try {
      const request: FileHashWorkerRequest = { type: 'HASH', file }
      worker.postMessage(request)
    } catch {
      finish(() => reject(new Error('Evidence hashing failed.')))
    }
  })
}
