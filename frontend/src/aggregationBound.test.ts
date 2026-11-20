/**
 * Aggregation proof count bound checks for silent witness batch aggregation (#497).
 */
import { describe, expect, it } from 'vitest'

import {
  MAX_AGGREGATION_SIZE,
  MIN_AGGREGATION_SIZE,
  VerifierInputError,
  checkAggregationBatchSize,
} from './verifierInputs'

describe('aggregation proof count bound', () => {
  it('exposes protocol constants', () => {
    expect(MAX_AGGREGATION_SIZE).toBe(8)
    expect(MIN_AGGREGATION_SIZE).toBe(1)
  })

  it('accepts batch sizes within the bound', () => {
    for (let size = MIN_AGGREGATION_SIZE; size <= MAX_AGGREGATION_SIZE; size += 1) {
      expect(checkAggregationBatchSize(size)).toBe(size)
    }
  })

  it('rejects oversized batch size without leaking secret or video material', () => {
    let caught: unknown
    try {
      checkAggregationBatchSize(MAX_AGGREGATION_SIZE + 1)
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(VerifierInputError)
    const rejection = caught as VerifierInputError
    expect(rejection.code).toBe('proof_oversize')
    expect(rejection.field).toBe('batch_size')
    expect(rejection.signal()).toEqual({
      codec: 'hpx-vi/1',
      rejectCode: 'proof_oversize',
      field: 'batch_size',
    })
    expect(rejection.message).not.toMatch(/video|secret|witness|hash/i)
  })

  it('rejects undersized and non-integer batch size', () => {
    expect(() => checkAggregationBatchSize(0)).toThrow(VerifierInputError)
    expect(() => checkAggregationBatchSize(-1)).toThrow(VerifierInputError)
    expect(() => checkAggregationBatchSize(1.5)).toThrow(VerifierInputError)
    expect(() => checkAggregationBatchSize(NaN)).toThrow(VerifierInputError)
  })
})
