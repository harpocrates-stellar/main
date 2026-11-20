/// <reference lib="webworker" />
import { sha256Blob } from '../utils'
import type { FileHashWorkerRequest, FileHashWorkerResponse } from './fileHashWorker.types'

/**
 * Cooperative cancel + stale-result guard. The client's hard stop is
 * worker.terminate(), but a second HASH request in this worker supersedes the
 * previous run so only the active request may post progress or results.
 */
let activeRun: AbortController | null = null

function post(message: FileHashWorkerResponse) {
  ;(self as unknown as Worker).postMessage(message)
}

self.onmessage = (event: MessageEvent<FileHashWorkerRequest>) => {
  if (event.data.type !== 'HASH') return

  activeRun?.abort()
  const controller = new AbortController()
  activeRun = controller
  const isCurrent = () => activeRun === controller && !controller.signal.aborted

  void sha256Blob(
    event.data.file,
    (progress) => {
      if (isCurrent()) post({ type: 'PROGRESS', progress })
    },
    controller.signal,
  ).then(
    (hash) => {
      if (isCurrent()) post({ type: 'RESULT', hash })
    },
    () => {
      // Aborted runs stay silent; real failures report a privacy-safe message.
      if (isCurrent()) post({ type: 'ERROR', message: 'Evidence hashing failed.' })
    },
  ).finally(() => {
    if (activeRun === controller) activeRun = null
  })
}
