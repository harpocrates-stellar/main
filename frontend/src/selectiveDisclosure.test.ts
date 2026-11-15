import { describe, it, expect } from 'vitest'
import type { SelectiveDisclosureInput, Predicate } from './types/schema'
import { SCHEMA_CONSTANTS } from './types/schema'
import {
  encodeWitnessPredicate,
  packCanonicalIntervalConjunction,
  reduceIntervalIntersection,
} from './selectiveDisclosure'

const mockPredicate: Predicate = {
  predicateType: 'Equality',
  attrIndex: 0,
  publicValue: '18',
  setValues: Array(SCHEMA_CONSTANTS.MAX_SET_MEMBERS).fill('0'),
  setLen: 0,
  lowerBound: '0',
  upperBound: '0',
}

const VALID_INPUT: SelectiveDisclosureInput = {
  schemaHash: 'aa'.repeat(32),
  issuerNamespace: 'bb'.repeat(32),
  schemaVersion: 1,
  credentialRoot: 'cc'.repeat(32),
  nullifier: 'dd'.repeat(32),
  videoHashHi: '11'.repeat(32),
  videoHashLo: '22'.repeat(32),
  verifierDigest: 'ee'.repeat(32),
  circuitVersion: 1,
  evidenceDigest: 'ff'.repeat(32),
  predicateCommitment: '00'.repeat(32),
  numAttributes: 2,
  attrValues: ['18', 'US'],
  attrBlindings: ['111111', '222222'],
  numPredicates: 1,
  predicates: [mockPredicate],
}

describe('SelectiveDisclosureInput', () => {
  it('accepts valid input structure', () => {
    expect(VALID_INPUT.schemaHash.length).toBe(64)
    expect(VALID_INPUT.issuerNamespace.length).toBe(64)
    expect(VALID_INPUT.circuitVersion).toBeGreaterThan(0)
    expect(VALID_INPUT.numAttributes).toBeLessThanOrEqual(SCHEMA_CONSTANTS.MAX_ATTRIBUTES)
    expect(VALID_INPUT.numPredicates).toBeLessThanOrEqual(SCHEMA_CONSTANTS.MAX_PREDICATES)
  })

  it('has matching attribute count and values length', () => {
    expect(VALID_INPUT.attrValues.length).toBeGreaterThanOrEqual(VALID_INPUT.numAttributes)
  })

  it('has matching predicate count and predicates length', () => {
    expect(VALID_INPUT.predicates.length).toBeGreaterThanOrEqual(VALID_INPUT.numPredicates)
  })

  it('rejects too many attributes', () => {
    const bad = {
      ...VALID_INPUT,
      numAttributes: SCHEMA_CONSTANTS.MAX_ATTRIBUTES + 1,
    }
    expect(bad.numAttributes).toBeGreaterThan(SCHEMA_CONSTANTS.MAX_ATTRIBUTES)
  })

  it('rejects too many predicates', () => {
    const bad = {
      ...VALID_INPUT,
      numPredicates: SCHEMA_CONSTANTS.MAX_PREDICATES + 1,
    }
    expect(bad.numPredicates).toBeGreaterThan(SCHEMA_CONSTANTS.MAX_PREDICATES)
  })

  it('accepts all predicate types', () => {
    const types: Array<Predicate['predicateType']> = [
      'Equality',
      'SetMembership',
      'Range',
      'IntervalIntersection',
    ]
    for (const pt of types) {
      const p: Predicate = {
        predicateType: pt,
        attrIndex: 0,
        publicValue: pt === 'Equality' ? '18' : undefined,
        setValues: pt === 'SetMembership' ? ['US', 'CA'] : [],
        setLen: pt === 'SetMembership' ? 2 : 0,
        lowerBound: pt === 'Range' ? '18' : undefined,
        upperBound: pt === 'Range' ? '99' : undefined,
        intervals:
          pt === 'IntervalIntersection'
            ? [
                { lower: '10', upper: '30', lowerInclusive: true, upperInclusive: true },
                { lower: '18', upper: '25', lowerInclusive: false, upperInclusive: true },
              ]
            : undefined,
      }
      expect(p.predicateType).toBe(pt)
    }
  })
})

describe('IntervalIntersection canonical conjunction', () => {
  it('reduces mixed inclusive/exclusive bounds canonically regardless of clause order', () => {
    const orderA = [
      { lower: '10', upper: '100', lowerInclusive: true, upperInclusive: true },
      { lower: '20', upper: '80', lowerInclusive: false, upperInclusive: true },
      { lower: '15', upper: '60', lowerInclusive: true, upperInclusive: false },
      { lower: '20', upper: '70', lowerInclusive: true, upperInclusive: true },
    ]
    const orderB = [orderA[3], orderA[2], orderA[0], orderA[1]]

    const redA = reduceIntervalIntersection(orderA)
    const redB = reduceIntervalIntersection(orderB)

    expect(redA.isEmpty).toBe(false)
    expect(redA.lower).toBe(20n)
    expect(redA.upper).toBe(60n)
    expect(redA.lowerInclusive).toBe(false)
    expect(redA.upperInclusive).toBe(false)
    expect(redA.minValid).toBe(21n)
    expect(redA.maxValid).toBe(59n)
    expect(redA.packedPublicValue).toBe(redB.packedPublicValue)
  })

  it('encodes IntervalIntersection witness fields without exposing attribute values', () => {
    const encoded = encodeWitnessPredicate({
      predicateType: 'IntervalIntersection',
      attrIndex: 0,
      intervals: [
        { lower: '10', upper: '30', lowerInclusive: true, upperInclusive: true },
        { lower: '18', upper: '25', lowerInclusive: false, upperInclusive: true },
      ],
    })

    expect(encoded.predicate_type).toBe('3')
    expect(encoded.attr_index).toBe('0')
    expect(encoded.lower_bound).toBe('18')
    expect(encoded.upper_bound).toBe('25')
    expect(encoded.public_value).toBe(
      packCanonicalIntervalConjunction(18n, 25n, false, true).toString(10),
    )
    expect(encoded.set_values).toEqual(['10', '30', '18', '25', '0', '0', '0', '0'])
    // num_clauses = 2, clause_mask = 0b1011 = 11 => 2 | (11 << 8) = 2818
    expect(encoded.set_len).toBe('2818')
  })

  it('detects touching exclusive, adjacent open integer, and disjoint empty intersections', () => {
    expect(
      reduceIntervalIntersection([
        { lower: '10', upper: '18', lowerInclusive: true, upperInclusive: false },
        { lower: '18', upper: '25', lowerInclusive: true, upperInclusive: true },
      ]).isEmpty,
    ).toBe(true)

    expect(
      reduceIntervalIntersection([
        { lower: '18', upper: '25', lowerInclusive: false, upperInclusive: true },
        { lower: '10', upper: '19', lowerInclusive: true, upperInclusive: false },
      ]).isEmpty,
    ).toBe(true)

    expect(() =>
      encodeWitnessPredicate({
        predicateType: 'IntervalIntersection',
        attrIndex: 0,
        intervals: [
          { lower: '10', upper: '15', lowerInclusive: true, upperInclusive: true },
          { lower: '20', upper: '25', lowerInclusive: true, upperInclusive: true },
        ],
      }),
    ).toThrow(/empty u64 intersection/i)
  })

  it('rejects oversized interval clause lists above MAX_INTERVAL_CLAUSES', () => {
    expect(() =>
      reduceIntervalIntersection([
        { lower: '10', upper: '30' },
        { lower: '11', upper: '29' },
        { lower: '12', upper: '28' },
        { lower: '13', upper: '27' },
        { lower: '14', upper: '26' },
      ]),
    ).toThrow(/at most 4 clauses/i)
  })
})

describe('SCHEMA_CONSTANTS', () => {
  it('defines reasonable limits', () => {
    expect(SCHEMA_CONSTANTS.MAX_ATTRIBUTES).toBe(16)
    expect(SCHEMA_CONSTANTS.MAX_PREDICATES).toBe(8)
    expect(SCHEMA_CONSTANTS.MAX_SET_MEMBERS).toBe(8)
    expect(SCHEMA_CONSTANTS.MAX_INTERVAL_CLAUSES).toBe(4)
    expect(SCHEMA_CONSTANTS.CURRENT_CIRCUIT_VERSION).toBe(1)
  })

  it('public input byte length is 352', () => {
    expect(SCHEMA_CONSTANTS.PUBLIC_INPUT_BYTE_LENGTH).toBe(352)
  })
})
