import { describe, expect, it } from 'vitest'
import {
  InvalidVideoHashError,
  assertValidVideoHash,
  isValidVideoHash,
} from '../videoHash'

const VALID_HASH = 'a'.repeat(64)

describe('videoHash', () => {
  describe('isValidVideoHash', () => {
    it('accepts 64 lowercase hex characters', () => {
      expect(isValidVideoHash(VALID_HASH)).toBe(true)
      expect(isValidVideoHash('0123456789abcdef'.repeat(4))).toBe(true)
    })

    it('rejects path traversal inputs', () => {
      expect(isValidVideoHash('../')).toBe(false)
      expect(isValidVideoHash(`${VALID_HASH}/../`)).toBe(false)
    })

    it('rejects query string injection', () => {
      expect(isValidVideoHash('?x=1')).toBe(false)
      expect(isValidVideoHash(`${VALID_HASH}?x=1`)).toBe(false)
    })

    it('rejects uppercase hex', () => {
      expect(isValidVideoHash('A'.repeat(64))).toBe(false)
    })

    it('rejects short inputs', () => {
      expect(isValidVideoHash('abc')).toBe(false)
      expect(isValidVideoHash('a'.repeat(63))).toBe(false)
    })

    it('rejects non-string values', () => {
      expect(isValidVideoHash(undefined)).toBe(false)
      expect(isValidVideoHash(null)).toBe(false)
      expect(isValidVideoHash(123)).toBe(false)
    })
  })

  describe('assertValidVideoHash', () => {
    it('returns the URL-encoded hash for valid input', () => {
      expect(assertValidVideoHash(VALID_HASH)).toBe(VALID_HASH)
    })

    it('throws InvalidVideoHashError for invalid input', () => {
      expect(() => assertValidVideoHash('../')).toThrow(InvalidVideoHashError)
      expect(() => assertValidVideoHash('?x=1')).toThrow(InvalidVideoHashError)
    })
  })
})
