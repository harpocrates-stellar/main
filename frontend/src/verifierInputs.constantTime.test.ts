/**
 * Constant-time comparison coverage for the browser verifier-input codec
 * (`hpx-vi/1`).
 *
 * Domain bindings and zero sentinels must be compared without an early exit so
 * that rejecting a tampered value does not reveal how many leading bytes
 * matched. Mirrors `backend/test_constant_time_compare.py`. All values are
 * synthetic.
 */

import { describe, expect, it } from 'vitest'

import {
  FIELD_LEN,
  REVOCATION_DOMAIN_SEPARATOR_HEX,
  SILENT_WITNESS_DOMAIN_TAG_HEX,
  VerifierInputError,
  constantTimeEquals,
  decodeHex,
  parseRevocationWitnessInputs,
  parseSilentWitnessInputs,
} from './verifierInputs'

const SILENT_DOMAIN = decodeHex(SILENT_WITNESS_DOMAIN_TAG_HEX)
const REVOCATION_DOMAIN = decodeHex(REVOCATION_DOMAIN_SEPARATOR_HEX)

function field(lastByte: number): Uint8Array {
  const out = new Uint8Array(FIELD_LEN)
  out[FIELD_LEN - 1] = lastByte
  return out
}

function half(): Uint8Array {
  const out = new Uint8Array(FIELD_LEN)
  out.fill(0x11, 16)
  return out
}

function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.length * FIELD_LEN)
  parts.forEach((part, index) => out.set(part, index * FIELD_LEN))
  return out
}

function flip(value: Uint8Array, index: number): Uint8Array {
  const out = value.slice()
  out[index] ^= 0x01
  return out
}

const silentFrame = (domain: Uint8Array = SILENT_DOMAIN) =>
  join(half(), half(), field(7), field(9), domain)
const revocationFrame = (domain: Uint8Array = REVOCATION_DOMAIN) =>
  join(field(5), field(9), domain, field(7))

function rejection(run: () => unknown): VerifierInputError {
  try {
    run()
  } catch (error) {
    expect(error).toBeInstanceOf(VerifierInputError)
    return error as VerifierInputError
  }
  throw new Error('expected a VerifierInputError')
}

describe('constantTimeEquals', () => {
  it('accepts identical values, including empty', () => {
    expect(constantTimeEquals(SILENT_DOMAIN, SILENT_DOMAIN.slice())).toBe(true)
    expect(constantTimeEquals(new Uint8Array(0), new Uint8Array(0))).toBe(true)
  })

  it('rejects a length mismatch', () => {
    expect(constantTimeEquals(new Uint8Array(31), new Uint8Array(32))).toBe(false)
    expect(constantTimeEquals(new Uint8Array(0), new Uint8Array(1))).toBe(false)
  })

  it.each(Array.from({ length: FIELD_LEN }, (_, index) => index))(
    'rejects a single-bit flip at byte %i',
    (index) => {
      expect(constantTimeEquals(SILENT_DOMAIN, flip(SILENT_DOMAIN, index))).toBe(false)
    },
  )
})

describe('domain binding checks', () => {
  it('accepts the canonical frames', () => {
    expect(() => parseSilentWitnessInputs(silentFrame())).not.toThrow()
    expect(() => parseRevocationWitnessInputs(revocationFrame())).not.toThrow()
  })

  it.each(Array.from({ length: FIELD_LEN }, (_, index) => index))(
    'rejects a silent-witness domain_tag flip at byte %i',
    (index) => {
      const error = rejection(() => parseSilentWitnessInputs(silentFrame(flip(SILENT_DOMAIN, index))))
      expect(error.code).toBe('domain_mismatch')
      expect(error.field).toBe('domain_tag')
    },
  )

  it.each(Array.from({ length: FIELD_LEN }, (_, index) => index))(
    'rejects a revocation domain_separator flip at byte %i',
    (index) => {
      const error = rejection(() =>
        parseRevocationWitnessInputs(revocationFrame(flip(REVOCATION_DOMAIN, index))),
      )
      expect(error.code).toBe('domain_mismatch')
      expect(error.field).toBe('domain_separator')
    },
  )

  it('keeps stable codes for zero and padding rejections', () => {
    const zeroRoot = join(half(), half(), new Uint8Array(FIELD_LEN), field(9), SILENT_DOMAIN)
    expect(rejection(() => parseSilentWitnessInputs(zeroRoot)).code).toBe('zero_field')

    const badPadding = half()
    badPadding[15] = 0x01
    const padded = join(badPadding, half(), field(7), field(9), SILENT_DOMAIN)
    expect(rejection(() => parseSilentWitnessInputs(padded)).code).toBe('padding')
  })

  it('never puts compared bytes in the rejection message', () => {
    const tampered = flip(SILENT_DOMAIN, 0)
    const error = rejection(() => parseSilentWitnessInputs(silentFrame(tampered)))
    expect(error.message).toBe('domain_mismatch:domain_tag')
    expect(error.message).not.toContain(SILENT_WITNESS_DOMAIN_TAG_HEX)
  })
})
