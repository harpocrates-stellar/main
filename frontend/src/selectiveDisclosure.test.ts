import { describe, it, expect, vi } from 'vitest'
import type { SelectiveDisclosureInput, Predicate } from './types/schema'
import { SCHEMA_CONSTANTS } from './types/schema'
import {
  DisclosureWitnessError,
  encodePredicateType,
  generateSelectiveDisclosureProof,
  padPredicates,
  prepareSelectiveDisclosureWitness,
} from './selectiveDisclosure'

const mockPredicate: Predicate = {
  predicateType: 'Equality',
  attrIndex: 0,
  publicValue: '12',
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
  attrValues: ['0x12', '0xbc614e'],
  attrBlindings: ['0x1b207', '0x3640e'],
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

  it('rejects too many attributes in witness preparation', () => {
    const bad = {
      ...VALID_INPUT,
      numAttributes: SCHEMA_CONSTANTS.MAX_ATTRIBUTES + 1,
      attrValues: Array(SCHEMA_CONSTANTS.MAX_ATTRIBUTES + 1).fill('0x01'),
      attrBlindings: Array(SCHEMA_CONSTANTS.MAX_ATTRIBUTES + 1).fill('0x02'),
    }
    expect(() => prepareSelectiveDisclosureWitness(bad)).toThrowError(DisclosureWitnessError)
  })

  it('rejects oversized predicate lists before circuit fetch or proving', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const oversizedPredicates = Array.from(
      { length: SCHEMA_CONSTANTS.MAX_PREDICATES + 1 },
      () => ({ ...mockPredicate }),
    )
    const bad: SelectiveDisclosureInput = {
      ...VALID_INPUT,
      numPredicates: SCHEMA_CONSTANTS.MAX_PREDICATES + 1,
      predicates: oversizedPredicates,
    }

    expect(() => padPredicates(oversizedPredicates)).toThrowError(DisclosureWitnessError)
    await expect(generateSelectiveDisclosureProof(bad)).rejects.toMatchObject({
      code: 'predicates_oversize',
      field: 'predicates',
    })
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })

  it('preserves supported predicate order and canonical type encoding up to MAX_PREDICATES', () => {
    const ordered: Predicate[] = [
      { predicateType: 'Range', attrIndex: 0, lowerBound: '0x12', upperBound: '0x63' },
      {
        predicateType: 'SetMembership',
        attrIndex: 1,
        setValues: ['0xbc614e', '0x5397fb1'],
        setLen: 2,
      },
      { predicateType: 'Equality', attrIndex: 0, publicValue: '0x12' },
    ]
    const prepared = prepareSelectiveDisclosureWitness({
      ...VALID_INPUT,
      numPredicates: ordered.length,
      predicates: ordered,
    })

    expect(prepared.num_predicates).toBe('3')
    expect(prepared.predicates).toHaveLength(SCHEMA_CONSTANTS.MAX_PREDICATES)
    expect(prepared.predicates[0].predicate_type).toBe('2')
    expect(prepared.predicates[0].lower_bound).toBe('18')
    expect(prepared.predicates[0].upper_bound).toBe('99')
    expect(prepared.predicates[1].predicate_type).toBe('1')
    expect(prepared.predicates[1].attr_index).toBe('1')
    expect(prepared.predicates[1].set_len).toBe('2')
    expect(prepared.predicates[1].set_values.slice(0, 2)).toEqual(['12345678', '87654321'])
    expect(prepared.predicates[2].predicate_type).toBe('0')
    expect(prepared.predicates[2].public_value).toBe('18')
    // Trailing padding slots remain zeroed Equality entries
    for (let idx = 3; idx < SCHEMA_CONSTANTS.MAX_PREDICATES; idx++) {
      expect(prepared.predicates[idx].predicate_type).toBe('0')
      expect(prepared.predicates[idx].public_value).toBe('0')
      expect(prepared.predicates[idx].set_len).toBe('0')
    }
  })

  it('rejects oversized setValues and unsupported predicate types without leaking values', () => {
    expect(encodePredicateType('Equality')).toBe('0')
    expect(encodePredicateType('SetMembership')).toBe('1')
    expect(encodePredicateType('Range')).toBe('2')
    expect(() =>
      encodePredicateType('RegexMatch' as unknown as Predicate['predicateType']),
    ).toThrowError(DisclosureWitnessError)

    const oversizedSet: Predicate = {
      predicateType: 'SetMembership',
      attrIndex: 1,
      setValues: Array(SCHEMA_CONSTANTS.MAX_SET_MEMBERS + 1).fill('0xdeadbeef'),
      setLen: SCHEMA_CONSTANTS.MAX_SET_MEMBERS + 1,
    }
    try {
      prepareSelectiveDisclosureWitness({
        ...VALID_INPUT,
        numPredicates: 1,
        predicates: [oversizedSet],
      })
      expect.unreachable('expected oversized setValues to throw')
    } catch (err) {
      expect(err).toBeInstanceOf(DisclosureWitnessError)
      expect((err as DisclosureWitnessError).code).toBe('set_members_oversize')
      expect(String(err)).not.toContain('deadbeef')
    }
  })
})

describe('SCHEMA_CONSTANTS', () => {
  it('defines reasonable limits', () => {
    expect(SCHEMA_CONSTANTS.MAX_ATTRIBUTES).toBe(16)
    expect(SCHEMA_CONSTANTS.MAX_PREDICATES).toBe(8)
    expect(SCHEMA_CONSTANTS.MAX_SET_MEMBERS).toBe(8)
    expect(SCHEMA_CONSTANTS.CURRENT_CIRCUIT_VERSION).toBe(1)
  })

  it('public input byte length is 352', () => {
    expect(SCHEMA_CONSTANTS.PUBLIC_INPUT_BYTE_LENGTH).toBe(352)
  })
})
