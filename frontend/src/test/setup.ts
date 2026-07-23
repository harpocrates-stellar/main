import { webcrypto } from 'node:crypto'
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: webcrypto,
  })
}

Object.defineProperty(window, 'scrollTo', {
  configurable: true,
  value: vi.fn(),
})

afterEach(() => {
  cleanup()
})
