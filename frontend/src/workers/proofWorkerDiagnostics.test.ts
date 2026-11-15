import { describe, expect, it, vi } from 'vitest'
import { CircuitInputError } from '../circuitInputSchema'
import {
  DEFAULT_DIAGNOSTIC_MAX_BYTES,
  boundProofWorkerDiagnostic,
} from '../proofWorkerMemory'
import { ProofWorkerManager } from './proof-worker-manager'

describe('bounded proof-worker telemetry diagnostics', () => {
  it('redacts inline witness-shaped values and sensitive context fields while retaining stage and errorCode', () => {
    const rawHex = '0x01a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708'
    const rawField = '21888242871839275222246405745257275088548364400416034343698204186575808495616'
    const rawSecret = 'my-ultra-private-credential-seed'

    const result = boundProofWorkerDiagnostic({
      stage: 'executing_main',
      errorCode: 'PROOF_GENERATION_FAILED',
      level: 'error',
      message: `Constraint failure at w_0=${rawHex} field=${rawField} credentialSecret=${rawSecret}`,
      context: {
        request_id: 'req-42',
        witness_input: rawField,
        note: `failed near ${rawHex}`,
      },
    })

    expect(result.payload.stage).toBe('executing_main')
    expect(result.payload.errorCode).toBe('PROOF_GENERATION_FAILED')
    expect(result.payload.redactionsApplied).toBeGreaterThanOrEqual(4)
    expect(result.payloadBytes).toBeLessThanOrEqual(DEFAULT_DIAGNOSTIC_MAX_BYTES)
    expect(new TextEncoder().encode(result.serialized).byteLength).toBe(result.payloadBytes)

    expect(result.serialized).not.toContain(rawHex)
    expect(result.serialized).not.toContain(rawField)
    expect(result.serialized).not.toContain(rawSecret)
    expect(result.payload.context?.request_id).toBe('req-42')
  })

  it('caps serialized UTF-8 bytes strictly, even with multibyte Unicode, without losing stage or errorCode', () => {
    const oversizedMessage = '🔥'.repeat(300) + ' prover diagnostic detail '.repeat(20)
    const bounded = boundProofWorkerDiagnostic(
      {
        stage: 'generating_proof',
        errorCode: 'MEMORY_LIMIT_EXCEEDED',
        level: 'warn',
        message: oversizedMessage,
        context: {
          duration_ms: 1234,
          extra: 'additional metadata that is dropped first under byte pressure',
        },
      },
      { maxBytes: 240 },
    )

    expect(bounded.maxBytes).toBe(240)
    expect(bounded.payloadBytes).toBeLessThanOrEqual(240)
    expect(new TextEncoder().encode(bounded.serialized).byteLength).toBe(bounded.payloadBytes)
    expect(bounded.payload.truncated).toBe(true)
    expect(bounded.payload.stage).toBe('generating_proof')
    expect(bounded.payload.errorCode).toBe('MEMORY_LIMIT_EXCEEDED')
    expect(bounded.payload.context).toBeUndefined()
    // Valid JSON and valid UTF-8 (no broken surrogate pairs)
    expect(JSON.parse(bounded.serialized)).toMatchObject({
      stage: 'generating_proof',
      errorCode: 'MEMORY_LIMIT_EXCEEDED',
      truncated: true,
    })
  })

  it('normalizes unrecognized or witness-bearing stage and errorCode inputs to stable identifiers', () => {
    const hostileSecret = 'credentialSecret=0xdeadbeefcafebabe1234567890abcdef'
    const bounded = boundProofWorkerDiagnostic({
      stage: hostileSecret,
      errorCode: `ERR_${hostileSecret}`,
      message: 'worker reported unexpected diagnostic',
    })

    expect(bounded.payload.stage).toBe('unknown_stage')
    expect(bounded.payload.errorCode).toBe('UNCLASSIFIED_WORKER_ERROR')
    expect(bounded.serialized).not.toContain('deadbeef')
  })

  it('rejects out-of-range maxBytes configuration fail-closed', () => {
    expect(() =>
      boundProofWorkerDiagnostic({ stage: 'idle', message: 'ok' }, { maxBytes: 64 }),
    ).toThrowError(new CircuitInputError('invalid_input'))

    expect(() =>
      boundProofWorkerDiagnostic({ stage: 'idle', message: 'ok' }, { maxBytes: 10_000 }),
    ).toThrowError(new CircuitInputError('invalid_input'))
  })

  it('forwards only the bounded redacted payload through ProofWorkerManager telemetry sink', () => {
    const manager = new ProofWorkerManager()
    const sink = vi.fn()
    const witnessHex = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'

    const forwarded = manager.forwardDiagnosticToTelemetry(
      {
        stage: 'loading_circuits',
        errorCode: 'CIRCUIT_LOAD_FAILED',
        level: 'error',
        message: `artifact check failed for ${witnessHex}`,
      },
      { maxBytes: 256, sink },
    )

    expect(sink).toHaveBeenCalledTimes(1)
    expect(sink).toHaveBeenCalledWith(forwarded.payload)
    expect(forwarded.payload.stage).toBe('loading_circuits')
    expect(forwarded.payload.errorCode).toBe('CIRCUIT_LOAD_FAILED')
    expect(forwarded.payloadBytes).toBeLessThanOrEqual(256)
    expect(JSON.stringify(sink.mock.calls[0][0])).not.toContain(witnessHex)

    manager.destroy()
  })
})
