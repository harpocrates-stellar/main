import { createReadStream } from 'node:fs'
import type { Readable } from 'node:stream'
import process from 'node:process'

export const MAX_MANIFEST_INPUT_BYTES = 1024 * 1024

export class InputSizeLimitError extends Error {
  readonly code = 'INPUT_LIMIT_EXCEEDED' as const
  readonly maxBytes: number
  readonly label: string

  constructor(label = 'input', maxBytes = MAX_MANIFEST_INPUT_BYTES) {
    const limitLabel =
      maxBytes === MAX_MANIFEST_INPUT_BYTES ? '1 MiB' : `${maxBytes}-byte`
    super(`${label} exceeds the ${limitLabel} input limit`)
    this.name = 'InputSizeLimitError'
    this.maxBytes = maxBytes
    this.label = label
  }
}

export type BoundedStreamOptions = {
  maxBytes?: number
  label?: string
  destroyOnOverflow?: boolean
}

/**
 * Read a UTF-8 text stream up to `maxBytes` (default 1 MiB), aborting
 * immediately when the cumulative byte count exceeds the bound — before buffer
 * concatenation or `JSON.parse` can run.
 */
export function readBoundedStream(
  stream: Readable,
  options: BoundedStreamOptions = {},
): Promise<string> {
  const maxBytes = options.maxBytes ?? MAX_MANIFEST_INPUT_BYTES
  const label = options.label ?? 'input'
  const destroyOnOverflow = options.destroyOnOverflow ?? false

  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    return Promise.reject(new RangeError('maxBytes must be a positive safe integer'))
  }

  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = []
    let totalBytes = 0
    let settled = false

    const cleanup = () => {
      stream.removeListener('data', onData)
      stream.removeListener('end', onEnd)
      stream.removeListener('error', onError)
      stream.removeListener('close', onClose)
    }

    const fail = (err: Error) => {
      if (settled) return
      settled = true
      chunks.length = 0
      cleanup()
      reject(err)
    }

    const onData = (chunk: Buffer | string) => {
      if (settled) return
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf-8')
      totalBytes += buf.byteLength
      if (totalBytes > maxBytes) {
        const overflowErr = new InputSizeLimitError(label, maxBytes)
        if (destroyOnOverflow) {
          fail(overflowErr)
          stream.destroy()
        } else {
          stream.pause()
          fail(overflowErr)
        }
        return
      }
      chunks.push(buf)
    }

    const onEnd = () => {
      if (settled) return
      settled = true
      cleanup()
      resolve(Buffer.concat(chunks, totalBytes).toString('utf-8'))
    }

    const onError = (err: Error) => {
      fail(err)
    }

    const onClose = () => {
      if (!settled) {
        fail(new Error(`stream closed before end while reading ${label}`))
      }
    }

    stream.on('data', onData)
    stream.on('end', onEnd)
    stream.on('error', onError)
    stream.on('close', onClose)
    stream.resume()
  })
}

/**
 * Read bounded UTF-8 text from a stream and parse JSON only after confirming
 * the entire payload fits within `maxBytes`.
 */
export async function readBoundedJson<T = unknown>(
  stream: Readable,
  options: BoundedStreamOptions = {},
): Promise<T> {
  const raw = await readBoundedStream(stream, options)
  return JSON.parse(raw) as T
}

/**
 * Read bounded UTF-8 text from either standard input (`"-"`) or a file path.
 */
export async function readBoundedTextInput(
  path: string,
  options: { maxBytes?: number; label?: string; stdin?: Readable } = {},
): Promise<string> {
  const isStdin = path === '-'
  const source = isStdin ? (options.stdin ?? process.stdin) : createReadStream(path)
  return readBoundedStream(source, {
    maxBytes: options.maxBytes,
    label: options.label,
    destroyOnOverflow: !isStdin,
  })
}
