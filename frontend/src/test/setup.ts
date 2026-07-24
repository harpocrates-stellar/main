import { createHash, randomUUID, webcrypto } from 'node:crypto'
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

const subtle = Object.create(webcrypto.subtle)
Object.defineProperty(subtle, 'digest', {
  configurable: true,
  value: vi.fn(async (algorithm, data) => {
    const name = typeof algorithm === 'string' ? algorithm : algorithm.name
    if (name.toUpperCase() !== 'SHA-256') {
      throw new Error(`${name} is not supported by the test crypto polyfill`)
    }

    const bytes =
      data instanceof ArrayBuffer
        ? new Uint8Array(data)
        : new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    const digest = createHash('sha256').update(bytes).digest()

    return digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength)
  }),
})

const testCrypto = {
  getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
  randomUUID,
  subtle,
}

Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: testCrypto,
})

Object.defineProperty(window, 'crypto', {
  configurable: true,
  value: testCrypto,
})

Object.defineProperty(window, 'scrollTo', {
  configurable: true,
  value: vi.fn(),
})

afterEach(() => {
  cleanup()
})
