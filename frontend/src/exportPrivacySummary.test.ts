import { describe, expect, it } from 'vitest'
import {
  buildExportPrivacySummary,
  EXPORT_PRIVACY_SUMMARY_VERSION,
  exportPrivacyErrorMessage,
  MAX_EXPORT_PRIVACY_SUMMARY_BYTES,
} from './exportPrivacySummary'
import type { ProofPackage } from './types'

function makeProof(overrides: Partial<ProofPackage> = {}): ProofPackage {
  return {
    fileName: 'harpocrates-synthetic-clip.mp4',
    sourceHash: 'a'.repeat(64),
    videoHash: 'b'.repeat(64),
    metadataHash: 'c'.repeat(64),
    proofId: 'd'.repeat(64),
    timestamp: '2026-01-01T00:00:00.000Z',
    tier: 'silent',
    ...overrides,
  }
}

describe('buildExportPrivacySummary', () => {
  it('lists included metadata classes and public identifiers for silent tier without requiring acknowledgement', () => {
    const result = buildExportPrivacySummary({
      proof: makeProof({ tier: 'silent' }),
      wallet: 'GSOURCEPUBLICKEYEXAMPLE1234567890',
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(result.version).toBe(EXPORT_PRIVACY_SUMMARY_VERSION)
    expect(result.tier).toBe('silent')
    expect(result.metadataClasses.map((c) => c.key)).toEqual([
      'container_file',
      'cryptographic_digests',
      'packaging_timestamp',
      'identity_tier',
    ])
    expect(result.publicIdentifiers.map((id) => id.key)).toEqual([
      'proofId',
      'videoHash',
      'metadataHash',
      'sourceHash',
    ])
    expect(result.sensitiveFields).toHaveLength(0)
    expect(result.newlyExposedSensitiveFields).toHaveLength(0)
    expect(result.requiresAcknowledgement).toBe(false)
    // Wallet must not leak into silent-tier public identifiers
    expect(JSON.stringify(result)).not.toContain('GSOURCEPUBLICKEYEXAMPLE')
  })

  it('requires explicit acknowledgement for newly exposed public identity on source and seal tiers', () => {
    for (const tier of ['source', 'seal'] as const) {
      const unacknowledged = buildExportPrivacySummary({
        proof: makeProof({ tier }),
        wallet: 'GACCOUNTEXAMPLE1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      })

      expect(unacknowledged.ok).toBe(true)
      if (!unacknowledged.ok) continue

      expect(unacknowledged.requiresAcknowledgement).toBe(true)
      expect(unacknowledged.newlyExposedSensitiveFields.map((f) => f.key)).toEqual([
        'publicIdentity',
      ])

      const acknowledged = buildExportPrivacySummary({
        proof: makeProof({ tier }),
        wallet: 'GACCOUNTEXAMPLE1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        acknowledgedSensitiveKeys: ['publicIdentity'],
      })

      expect(acknowledged.ok).toBe(true)
      if (!acknowledged.ok) continue

      expect(acknowledged.requiresAcknowledgement).toBe(false)
      expect(acknowledged.newlyExposedSensitiveFields).toHaveLength(0)
      expect(acknowledged.sensitiveFields).toHaveLength(1)
      expect(acknowledged.sensitiveFields[0].newlyExposed).toBe(false)
    }
  })

  it('only requires acknowledgement for newly exposed sensitive fields when new metadata is added', () => {
    const proofWithAttestation = makeProof({
      tier: 'source',
      timeAttestation: {
        version: 1,
        protocol: 'rfc3161_tsa',
        evidenceDigest: 'e'.repeat(64),
        stellarAnchors: [],
        rfc3161Anchors: [],
      },
    })

    const result = buildExportPrivacySummary({
      proof: proofWithAttestation,
      wallet: 'GACCOUNTEXAMPLE1234567890',
      acknowledgedSensitiveKeys: ['publicIdentity'],
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(result.requiresAcknowledgement).toBe(true)
    expect(result.sensitiveFields.map((f) => f.key)).toEqual(['publicIdentity', 'timeAttestation'])
    expect(result.newlyExposedSensitiveFields.map((f) => f.key)).toEqual(['timeAttestation'])
  })

  it('includes silent witness nullifier and credential root when attached without leaking raw proof bytes', () => {
    const rawProofSecret = 'SECRET_RAW_WITNESS_PROOF_BYTES_DO_NOT_LEAK'
    const result = buildExportPrivacySummary({
      proof: makeProof({
        tier: 'silent',
        silentWitness: {
          credentialRoot: '1'.repeat(64),
          nullifier: '2'.repeat(64),
          proof: rawProofSecret,
          publicInputs: 'PUBLIC_INPUTS_RAW',
          proofBytes: 128,
          publicInputBytes: 64,
        },
      }),
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(result.metadataClasses.map((c) => c.key)).toContain('silent_witness_proof')
    expect(result.newlyExposedSensitiveFields.map((f) => f.key)).toEqual([
      'silentWitness.nullifier',
      'silentWitness.credentialRoot',
    ])
    expect(result.requiresAcknowledgement).toBe(true)
    expect(JSON.stringify(result)).not.toContain(rawProofSecret)
  })

  it('fails closed on missing, malformed, unsupported tier, and oversized payloads', () => {
    const missing = buildExportPrivacySummary({ proof: null })
    expect(missing).toEqual({
      ok: false,
      code: 'MISSING_EVIDENCE',
      message: exportPrivacyErrorMessage('MISSING_EVIDENCE'),
    })

    const malformed = buildExportPrivacySummary({
      proof: { fileName: 'clip.mp4', tier: 'silent' } as unknown as ProofPackage,
    })
    expect(malformed).toEqual({
      ok: false,
      code: 'MALFORMED_EVIDENCE',
      message: exportPrivacyErrorMessage('MALFORMED_EVIDENCE'),
    })

    const unsupported = buildExportPrivacySummary({
      proof: makeProof({ tier: 'unknown-tier' as unknown as ProofPackage['tier'] }),
    })
    expect(unsupported).toEqual({
      ok: false,
      code: 'UNSUPPORTED_TIER',
      message: exportPrivacyErrorMessage('UNSUPPORTED_TIER'),
    })

    const oversized = buildExportPrivacySummary({
      proof: makeProof({ fileName: 'x'.repeat(MAX_EXPORT_PRIVACY_SUMMARY_BYTES + 1024) }),
    })
    expect(oversized).toEqual({
      ok: false,
      code: 'OVERSIZED_PAYLOAD',
      message: exportPrivacyErrorMessage('OVERSIZED_PAYLOAD'),
    })
  })
})
