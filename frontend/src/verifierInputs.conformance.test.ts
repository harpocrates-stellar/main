/**
 * Cross-layer verifier conformance runner (browser side, codecs `hpx-vi/1`
 * and `hpx-vi/2`).
 *
 * Drives the shared corpora in `zk/vectors/verifier_conformance_v1.json` and
 * `zk/vectors/verifier_conformance_v2.json` through `src/verifierInputs.ts`.
 * The Python runner (`backend/test_conformance_vectors.py`) and the Rust
 * runner (`contracts/contracts/harpocrates-registry/src/test_conformance.rs`)
 * drive the same files, so a divergence in any layer fails exactly one of the
 * three suites and names the offending case id.
 *
 * See docs/zk-conformance-vectors.md.
 */

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
  BN254_SCALAR_FIELD_MODULUS,
  CODEC_ID,
  CODEC_ID_V2,
  EXPECTED_CIRCUIT_VERSION,
  MAX_PROOF_BYTES,
  MIN_PROOF_BYTES,
  PUBLIC_INPUTS_LEN,
  REVOCATION_DOMAIN_SEPARATOR_HEX,
  SCHEMA_SILENT_WITNESS_V2,
  SILENT_WITNESS_DOMAIN_TAG_HEX,
  SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN,
  VerifierInputError,
  classify,
  decodeHex,
  encodeFieldToBytes32Hex,
  encodePublicInputs,
  parsePublicInputs,
} from './verifierInputs'

type ConformanceCase = {
  id: string
  schema: string
  description: string
  public_inputs_hex: string
  proof_hex: string
  expect: { accept: boolean; reject_code: string | null }
}

type Corpus = {
  format: string
  version: number
  codec: string
  constants: Record<string, number | string>
  reject_codes: string[]
  cases: ConformanceCase[]
}

const here = dirname(fileURLToPath(import.meta.url))
const corpusPath = resolve(here, '../../zk/vectors/verifier_conformance_v1.json')
const corpus = JSON.parse(readFileSync(corpusPath, 'utf-8')) as Corpus

const corpusV2Path = resolve(here, '../../zk/vectors/verifier_conformance_v2.json')
const corpusV2 = JSON.parse(readFileSync(corpusV2Path, 'utf-8')) as Corpus

type MalformedCase = {
  id: string
  field: string
  description: string
  value: string
  expect: { reject_code: string }
}

type MalformedCorpus = {
  format: string
  version: number
  codec: string
  reject_codes: string[]
  cases: MalformedCase[]
}

const malformedPath = resolve(here, '../../zk/vectors/malformed_public_inputs_v1.json')
const malformedCorpus = JSON.parse(readFileSync(malformedPath, 'utf-8')) as MalformedCorpus

describe('conformance corpus integrity', () => {
  it('is versioned and matches this codec', () => {
    expect(corpus.format).toBe('harpocrates.verifier-conformance')
    expect(corpus.version).toBe(1)
    expect(corpus.codec).toBe(CODEC_ID)
  })

  it('declares constants matching the implementation', () => {
    expect(corpus.constants.public_inputs_len).toBe(PUBLIC_INPUTS_LEN)
    expect(corpus.constants.min_proof_bytes).toBe(MIN_PROOF_BYTES)
    expect(corpus.constants.max_proof_bytes).toBe(MAX_PROOF_BYTES)
    expect(BigInt(`0x${corpus.constants.bn254_scalar_field_modulus_hex}`)).toBe(
      BN254_SCALAR_FIELD_MODULUS,
    )
    expect(corpus.constants.revocation_domain_separator_hex).toBe(
      REVOCATION_DOMAIN_SEPARATOR_HEX,
    )
  })

  it('contains both positive and negative cases with unique ids', () => {
    expect(corpus.cases.length).toBeGreaterThanOrEqual(20)
    expect(corpus.cases.some((entry) => entry.expect.accept)).toBe(true)
    expect(corpus.cases.some((entry) => !entry.expect.accept)).toBe(true)
    expect(new Set(corpus.cases.map((entry) => entry.id)).size).toBe(corpus.cases.length)
  })
})

describe('conformance cases', () => {
  for (const entry of corpus.cases) {
    it(`${entry.id} — ${entry.description}`, () => {
      const expected = entry.expect.accept ? null : entry.expect.reject_code
      const actual = classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)
      expect(actual, `${entry.id} mismatched`).toBe(expected)
    })
  }

  it('classifies deterministically on repeat evaluation', () => {
    for (const entry of corpus.cases) {
      const first = classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)
      const second = classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)
      expect(second, `${entry.id} was not deterministic`).toBe(first)
    }
  })
})

describe('v2 conformance corpus (hpx-vi/2, circuit-versioned envelope)', () => {
  it('is versioned and matches this codec', () => {
    expect(corpusV2.format).toBe('harpocrates.verifier-conformance')
    expect(corpusV2.version).toBe(2)
    expect(corpusV2.codec).toBe(CODEC_ID_V2)
    expect(corpusV2.reject_codes).toContain('version_mismatch')
  })

  it('declares constants matching the implementation', () => {
    expect(corpusV2.constants.silent_witness_v2_public_inputs_len).toBe(
      SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN,
    )
    expect(corpusV2.constants.expected_circuit_version).toBe(EXPECTED_CIRCUIT_VERSION)
    expect(corpusV2.constants.silent_witness_domain_tag_hex).toBe(SILENT_WITNESS_DOMAIN_TAG_HEX)
    expect(BigInt(`0x${corpusV2.constants.bn254_scalar_field_modulus_hex}`)).toBe(
      BN254_SCALAR_FIELD_MODULUS,
    )
  })

  it('contains positive, negative, and version-mismatch cases with unique ids', () => {
    expect(corpusV2.cases.length).toBeGreaterThanOrEqual(10)
    expect(corpusV2.cases.some((entry) => entry.expect.accept)).toBe(true)
    expect(corpusV2.cases.some((entry) => !entry.expect.accept)).toBe(true)
    expect(corpusV2.cases.some((entry) => entry.expect.reject_code === 'version_mismatch')).toBe(
      true,
    )
    expect(new Set(corpusV2.cases.map((entry) => entry.id)).size).toBe(corpusV2.cases.length)
    for (const entry of corpusV2.cases) {
      expect(entry.schema).toBe(SCHEMA_SILENT_WITNESS_V2)
    }
  })

  for (const entry of corpusV2.cases) {
    it(`${entry.id} — ${entry.description}`, () => {
      const expected = entry.expect.accept ? null : entry.expect.reject_code
      const actual = classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)
      expect(actual, `${entry.id} mismatched`).toBe(expected)
    })
  }

  it('classifies deterministically on repeat evaluation', () => {
    for (const entry of corpusV2.cases) {
      const first = classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)
      const second = classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)
      expect(second, `${entry.id} was not deterministic`).toBe(first)
    }
  })
})

describe('boundary behaviour outside the corpus', () => {
  const positive = corpus.cases.find((entry) => entry.expect.accept)!

  it('rejects an unknown schema', () => {
    expect(classify('silent_witness/v9', positive.public_inputs_hex, positive.proof_hex)).toBe(
      'unknown_schema',
    )
  })

  it('loads a versioned malformed public-input corpus for this codec', () => {
    expect(malformedCorpus.format).toBe('harpocrates.malformed-public-inputs')
    expect(malformedCorpus.version).toBe(1)
    expect(malformedCorpus.codec).toBe(CODEC_ID)
    expect(malformedCorpus.reject_codes).toEqual(['malformed_hex'])
    expect(malformedCorpus.cases.length).toBeGreaterThanOrEqual(10)
    expect(new Set(malformedCorpus.cases.map((entry) => entry.id)).size).toBe(
      malformedCorpus.cases.length,
    )
  })

  it.each(malformedCorpus.cases.map((entry) => [entry.id, entry] as const))(
    'rejects malformed public-input hex %s',
    (_id, entry) => {
      expect(() => decodeHex(entry.value, entry.field, 'length')).toThrow(VerifierInputError)
      try {
        decodeHex(entry.value, entry.field, 'length')
      } catch (error) {
        const captured = error as VerifierInputError
        expect(captured.code).toBe(entry.expect.reject_code)
        expect(captured.field).toBe(entry.field)
        const signal = captured.signal()
        const rendered = JSON.stringify(signal)
        expect(rendered).not.toContain(entry.value)
        expect(Object.keys(signal).sort()).toEqual(['codec', 'field', 'rejectCode'])
      }
    },
  )

  it('never carries input material in a rejection signal', () => {
    const tampered = 'ff'.repeat(32) + positive.public_inputs_hex.slice(64)

    let captured: VerifierInputError | undefined
    try {
      parsePublicInputs(positive.schema, decodeHex(tampered, 'public_inputs', 'length'))
    } catch (error) {
      captured = error as VerifierInputError
    }

    expect(captured).toBeInstanceOf(VerifierInputError)
    const signal = captured!.signal()
    const rendered = JSON.stringify(signal)
    expect(signal.codec).toBe(CODEC_ID)
    expect(rendered).not.toContain(tampered)
    expect(rendered).not.toContain('ff'.repeat(8))
    expect(Object.keys(signal).sort()).toEqual(['codec', 'field', 'rejectCode'])
  })

  it('encodes Noir fields canonically and deterministically', () => {
    expect(encodeFieldToBytes32Hex('0x2a')).toBe('00'.repeat(31) + '2a')
    expect(encodeFieldToBytes32Hex('42')).toBe('00'.repeat(31) + '2a')
    expect(encodePublicInputs(['1', '2'], ['first', 'second'])).toBe(
      '00'.repeat(31) + '01' + '00'.repeat(31) + '02',
    )
  })

  it.each(['-1', BN254_SCALAR_FIELD_MODULUS.toString(), '0x' + 'ff'.repeat(32)])(
    'rejects non-canonical Noir field %j without reducing it',
    (value) => {
      expect(() => encodeFieldToBytes32Hex(value, 'witness')).toThrow(VerifierInputError)
      try {
        encodeFieldToBytes32Hex(value, 'witness')
      } catch (error) {
        expect((error as VerifierInputError).code).toBe('non_canonical_field')
        expect((error as VerifierInputError).signal()).toEqual({
          codec: CODEC_ID,
          rejectCode: 'non_canonical_field',
          field: 'witness',
        })
      }
    },
  )
})
