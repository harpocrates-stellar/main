import { describe, expect, it } from 'vitest'
import vectors from '../../zk/vectors/circuit_input_schema_v1.json'
import schema from '../../zk/noir/circuit_input_schema_v1.json'
import helper from '../public/noir/silent_witness_helper.json'
import main from '../public/noir/silent_witness.json'
import type { CompiledCircuit } from '@noir-lang/types'
import {
  assertArtifactPair,
  assertProofOutput,
  CircuitInputError,
  CIRCUIT_INPUT_SCHEMA_VERSION,
  prepareSilentWitnessInputs,
  PUBLIC_FRAMES,
} from './circuitInputSchema'
import type { SilentWitnessInput } from './circuitInputSchema'

const expected = {
  video_hash_hi: '1', video_hash_lo: '2', credential_root: '3', nullifier: '4',
  verifier_scope: '7', epoch: '2', domain_tag: '5',
}

function syntheticArtifact(names: string[], publicStart: number, returns: number): CompiledCircuit {
  return {
    bytecode: 'synthetic',
    noir_version: `${schema.noir_version}+synthetic`,
    abi: {
      parameters: names.map((name, index) => ({
        name, visibility: index < publicStart ? 'private' : 'public', type: { kind: 'field' },
      })),
      return_type: returns ? {
        visibility: 'public',
        abi_type: { kind: 'tuple', fields: Array.from({ length: returns }, () => ({ kind: 'field' })) },
      } : null,
    },
  } as unknown as CompiledCircuit
}

describe('silent witness input schema v1', () => {
  it('matches the versioned synthetic vectors, including scoped inputs', () => {
    expect(vectors.version).toBe(CIRCUIT_INPUT_SCHEMA_VERSION)
    expect(vectors.schema).toBe(schema.id)
    for (const vector of vectors.cases) {
      const input = vector.input as SilentWitnessInput
      if (vector.accept) {
        const prepared = prepareSilentWitnessInputs(input)
        expect(Object.keys(prepared)).toEqual(schema.input_fields)
        expect(prepared.verifier_scope).toBe(input.verifierScope ?? '0')
        expect(prepared.epoch).toBe(String(input.epoch ?? 0))
      } else {
        expect(() => prepareSilentWitnessInputs(input)).toThrowError(
          new CircuitInputError(vector.reject_code as CircuitInputError['code']),
        )
      }
    }
  })

  it('splits a 32-byte hash into two 128-bit fields', () => {
    const prepared = prepareSilentWitnessInputs(vectors.cases[0].input)
    expect(prepared.video_hash_hi).toBe(BigInt('0x' + '11'.repeat(16)).toString())
    expect(prepared.video_hash_lo).toBe(BigInt('0x' + '22'.repeat(16)).toString())
  })

  it('normalizes previously accepted hexadecimal field inputs', () => {
    const prepared = prepareSilentWitnessInputs({
      ...vectors.cases[0].input,
      credentialSecret: '0x3039',
      nullifierSecret: '0x10932',
      verifierScope: '0x07',
    })
    expect(prepared.credential_secret).toBe('12345')
    expect(prepared.nullifier_secret).toBe('67890')
    expect(prepared.verifier_scope).toBe('7')
  })

  it('accepts the existing five-field and seven-field verifier orders', () => {
    const unscoped = PUBLIC_FRAMES.unscoped_v1.map((field) => expected[field as keyof typeof expected])
    const scoped = PUBLIC_FRAMES.scoped_v2.map((field) => expected[field as keyof typeof expected])
    expect(() => assertProofOutput(64, unscoped, expected, 'unscoped_v1')).not.toThrow()
    expect(() => assertProofOutput(64, unscoped.map((field) => `0x${BigInt(field).toString(16)}`), expected, 'unscoped_v1')).not.toThrow()
    expect(() => assertProofOutput(65536, scoped, expected, 'scoped_v2')).not.toThrow()
  })

  it('rejects a five-field proof for a scoped request and changed public values', () => {
    const unscoped = PUBLIC_FRAMES.unscoped_v1.map((field) => expected[field as keyof typeof expected])
    expect(() => assertProofOutput(64, unscoped, expected, 'scoped_v2')).toThrowError(
      new CircuitInputError('invalid_proof_output'),
    )
    const changed = [...unscoped]
    changed[3] = '8'
    expect(() => assertProofOutput(64, changed, expected, 'unscoped_v1')).toThrowError(
      new CircuitInputError('invalid_proof_output'),
    )
  })

  it('rejects truncated or oversized proof output without echoing private values', () => {
    const unscoped = PUBLIC_FRAMES.unscoped_v1.map((field) => expected[field as keyof typeof expected])
    for (const bytes of [63, 65537]) {
      expect(() => assertProofOutput(bytes, unscoped, expected, 'unscoped_v1')).toThrowError(
        new CircuitInputError('invalid_proof_output'),
      )
    }
    const secret = '9'.repeat(80)
    try {
      prepareSilentWitnessInputs({ ...vectors.cases[0].input, credentialSecret: secret })
      throw new Error('expected rejection')
    } catch (error) {
      expect(error).toBeInstanceOf(CircuitInputError)
      expect((error as Error).message).not.toContain(secret)
    }
  })

  it('rejects the stale four-field browser artifacts and recognizes both versioned ABI shapes', () => {
    expect(() => assertArtifactPair(helper as CompiledCircuit, main as CompiledCircuit)).toThrowError(
      new CircuitInputError('artifact_mismatch'),
    )
    for (const frame of ['unscoped_v1', 'scoped_v2'] as const) {
      const abi = schema.artifact_abis[frame]
      expect(assertArtifactPair(
        syntheticArtifact(abi.helper_parameters, abi.helper_parameters.length, 3),
        syntheticArtifact(abi.main_parameters, 2, 0),
      )).toBe(frame)
    }
  })
})
