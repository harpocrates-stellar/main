/**
 * Depth-bound checks for revocation_witness/v1 (#357).
 */
import { describe, expect, it } from 'vitest'

import {
  MAX_REVOCATION_LEAVES,
  MAX_REVOCATION_WITNESS_DEPTH,
  VerifierInputError,
  checkRevocationWitnessDepth,
} from './verifierInputs'

describe('revocation witness depth bound', () => {
  it('exposes protocol constants', () => {
    expect(MAX_REVOCATION_WITNESS_DEPTH).toBe(3)
    expect(MAX_REVOCATION_LEAVES).toBe(8)
    expect(MAX_REVOCATION_LEAVES).toBe(2 ** MAX_REVOCATION_WITNESS_DEPTH)
  })

  it('accepts depths within the bound', () => {
    for (let depth = 1; depth <= MAX_REVOCATION_WITNESS_DEPTH; depth += 1) {
      expect(() => checkRevocationWitnessDepth(depth)).not.toThrow()
    }
  })

  it('rejects oversized depth without leaking witness material', () => {
    let caught: unknown
    try {
      checkRevocationWitnessDepth(MAX_REVOCATION_WITNESS_DEPTH + 1)
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(VerifierInputError)
    const rejection = caught as VerifierInputError
    expect(rejection.code).toBe('proof_oversize')
    expect(rejection.field).toBe('depth')
    expect(rejection.signal()).toEqual({
      codec: 'hpx-vi/1',
      rejectCode: 'proof_oversize',
      field: 'depth',
    })
    expect(rejection.message).not.toMatch(/leaf|secret|witness/i)
  })

  it('rejects undersized and non-integer depth', () => {
    expect(() => checkRevocationWitnessDepth(0)).toThrow(VerifierInputError)
    expect(() => checkRevocationWitnessDepth(1.5)).toThrow(VerifierInputError)
  })
})
