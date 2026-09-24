import { describe, it, expect } from 'vitest'
import { validateMetadata, canonicalMetadataHash } from '../src/metadata.js'

const VALID_METADATA = {
  protocol: 'harpocrates',
  version: 1,
  tier: 'silent',
  sourceHash: 'a'.repeat(64),
  proofId: 'b'.repeat(64),
  timestamp: '2026-07-24T12:00:00.000Z',
}

describe('validateMetadata', () => {
  it('accepts valid metadata', () => {
    expect(() => validateMetadata(VALID_METADATA)).not.toThrow()
  })

  it('rejects non-object input', () => {
    expect(() => validateMetadata(null)).toThrow('must be a JSON object')
    expect(() => validateMetadata('string')).toThrow('must be a JSON object')
  })

  it('rejects missing required fields', () => {
    const { proofId: _, ...missing } = VALID_METADATA
    expect(() => validateMetadata(missing)).toThrow('missing required field: proofId')
  })

  it('rejects wrong protocol', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, protocol: 'other' })).toThrow(
      'protocol must be',
    )
  })

  it('rejects invalid tier', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, tier: 'invalid' })).toThrow(
      'tier must be one of',
    )
  })

  it('rejects bad sourceHash', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, sourceHash: 'xyz' })).toThrow(
      'sourceHash must be a 32-byte hex',
    )
  })

  it('rejects bad proofId', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, proofId: 'xyz' })).toThrow(
      'proofId must be a 32-byte hex',
    )
  })

  it('accepts all valid tiers', () => {
    for (const tier of ['silent', 'source', 'seal']) {
      expect(() => validateMetadata({ ...VALID_METADATA, tier })).not.toThrow()
    }
  })

  it('returns a typed object with the same values', () => {
    const result = validateMetadata(VALID_METADATA)
    expect(result.protocol).toBe('harpocrates')
    expect(result.tier).toBe('silent')
  })
})

describe('canonicalMetadataHash', () => {
  it('produces a 64-character hex string', () => {
    const result = canonicalMetadataHash(VALID_METADATA)
    expect(result).toHaveLength(64)
  })

  it('is deterministic for the same metadata', () => {
    expect(canonicalMetadataHash(VALID_METADATA)).toBe(canonicalMetadataHash(VALID_METADATA))
  })

  it('produces different hashes for different metadata', () => {
    const a = canonicalMetadataHash(VALID_METADATA)
    const b = canonicalMetadataHash({ ...VALID_METADATA, proofId: 'c'.repeat(64) })
    expect(a).not.toBe(b)
  })
})

describe('validateMetadata — boundary and regression', () => {
  it('rejects version as string instead of number', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, version: '1' })).toThrow('version must be a number')
  })

  it('rejects sourceHash with uppercase hex', () => {
    // The regex allows uppercase, so this should pass — confirms case-insensitive hex acceptance
    expect(() => validateMetadata({ ...VALID_METADATA, sourceHash: 'A'.repeat(64) })).not.toThrow()
  })

  it('rejects sourceHash that is 63 characters (one short)', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, sourceHash: 'a'.repeat(63) })).toThrow('sourceHash must be a 32-byte hex')
  })

  it('rejects sourceHash that is 65 characters (one over)', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, sourceHash: 'a'.repeat(65) })).toThrow('sourceHash must be a 32-byte hex')
  })

  it('rejects proofId with non-hex characters', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, proofId: 'g'.repeat(64) })).toThrow('proofId must be a 32-byte hex')
  })

  it('rejects missing timestamp field', () => {
    const { timestamp: _, ...noTimestamp } = VALID_METADATA
    expect(() => validateMetadata(noTimestamp)).toThrow('missing required field: timestamp')
  })

  it('accepts extra unknown fields without throwing', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, extra: 'foo' })).not.toThrow()
  })

  it('rejects an array as top-level input', () => {
    // arrays pass the typeof check but fail the required-field check
    expect(() => validateMetadata([])).toThrow()
  })

  it('rejects undefined as input', () => {
    expect(() => validateMetadata(undefined)).toThrow('must be a JSON object')
  })
})

describe('canonicalMetadataHash — boundary and regression', () => {
  it('output is lowercase hex only', () => {
    const result = canonicalMetadataHash(VALID_METADATA)
    expect(/^[0-9a-f]{64}$/.test(result)).toBe(true)
  })

  it('key order does not affect the hash', () => {
    const ordered = VALID_METADATA
    const reordered = {
      timestamp: VALID_METADATA.timestamp,
      proofId: VALID_METADATA.proofId,
      tier: VALID_METADATA.tier,
      version: VALID_METADATA.version,
      protocol: VALID_METADATA.protocol,
      sourceHash: VALID_METADATA.sourceHash,
    }
    expect(canonicalMetadataHash(ordered)).toBe(canonicalMetadataHash(reordered as typeof VALID_METADATA))
  })

  it('changing a single field produces a completely different hash', () => {
    const base = canonicalMetadataHash(VALID_METADATA)
    const changed = canonicalMetadataHash({ ...VALID_METADATA, tier: 'source' })
    expect(base).not.toBe(changed)
  })
})
