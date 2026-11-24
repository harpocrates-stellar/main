import { describe, expect, it } from 'vitest'
import {
  buildVerificationExportPreview,
  evaluateVerificationFreshness,
  serializeVerificationExportPreview,
} from './verificationFlow'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'

const SAMPLE_HASH = 'a'.repeat(64)
const SAMPLE_META_HASH = 'b'.repeat(64)
const SAMPLE_PROOF_ID = 'c'.repeat(64)

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: SAMPLE_HASH,
    metadataHash: SAMPLE_META_HASH,
    tier: 1,
    status: 1,
    createdAt: '2026-11-19T12:00:00.000Z',
    expiresAt: 0,
    ...overrides,
  }
}

function makeEvent(overrides: Partial<ProofEvent> = {}): ProofEvent {
  return {
    id: 1,
    event_type: 'proof_registered',
    file_name: null,
    video_hash: SAMPLE_HASH,
    proof_id: SAMPLE_PROOF_ID,
    tier: 'source',
    tx_hash: 'tx123',
    tx_status: 'confirmed',
    created_at: '2026-11-19T12:01:00.000Z',
    ...overrides,
  }
}

describe('verificationFlow export preview', () => {
  it('builds a complete snapshot with included fields, freshness, and zero unresolved checks for a confirmed online result', () => {
    const capturedAt = '2026-11-19T12:05:00.000Z'
    const now = new Date('2026-11-19T12:06:00.000Z')

    const preview = buildVerificationExportPreview({
      videoHash: SAMPLE_HASH,
      proofId: SAMPLE_PROOF_ID,
      metadataHash: SAMPLE_META_HASH,
      status: 'success',
      summary: 'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
      errorCode: null,
      offline: false,
      events: [makeEvent()],
      chainProof: makeChainProof(),
      contractId: 'CDUMMYCONTRACTID',
      network: 'Test SDF Future Network ; October 2022',
      capturedAt,
      now,
    })

    expect(preview.schema).toBe('harpocrates-verification-export-preview')
    expect(preview.version).toBe(1)
    expect(preview.trustContextRefreshedOnExport).toBe(false)
    expect(preview.includedFields).toEqual({
      videoHash: SAMPLE_HASH,
      proofId: SAMPLE_PROOF_ID,
      metadataHash: SAMPLE_META_HASH,
      mode: 'online',
      status: 'success',
      summary: 'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
      errorCode: null,
      chainStatus: 'confirmed',
      tier: 'source',
      eventCount: 1,
      contractId: 'CDUMMYCONTRACTID',
      network: 'Test SDF Future Network ; October 2022',
    })
    expect(preview.freshness.state).toBe('fresh')
    expect(preview.freshness.capturedAt).toBe(capturedAt)
    expect(preview.freshness.chainRecordCreatedAt).toBe('2026-11-19T12:00:00.000Z')
    expect(preview.freshness.latestEventAt).toBe('2026-11-19T12:01:00.000Z')
    expect(preview.unresolvedChecks).toEqual([])

    const serialized = serializeVerificationExportPreview(preview)
    expect(JSON.parse(serialized)).toEqual(preview)
  })

  it('marks freshness as stale once elapsed time exceeds maxAgeMs', () => {
    const capturedAt = '2026-11-19T12:00:00.000Z'
    const freshNow = new Date('2026-11-19T12:05:00.000Z')
    const staleNow = new Date('2026-11-19T12:05:00.001Z')

    expect(evaluateVerificationFreshness(capturedAt, freshNow, 5 * 60 * 1000, false)).toBe('fresh')
    expect(evaluateVerificationFreshness(capturedAt, staleNow, 5 * 60 * 1000, false)).toBe('stale')
    expect(evaluateVerificationFreshness(capturedAt, freshNow, 5 * 60 * 1000, true)).toBe('unverified')
  })

  it('reports unresolved checks for offline mode and missing identifiers', () => {
    const preview = buildVerificationExportPreview({
      videoHash: SAMPLE_HASH,
      status: 'success',
      summary: 'Locally verified: the artifact carries a valid Harpocrates metadata envelope.',
      offline: true,
      events: [],
      chainProof: null,
      network: 'Test SDF Future Network ; October 2022',
      now: new Date('2026-11-19T12:05:00.000Z'),
    })

    expect(preview.includedFields.mode).toBe('offline')
    expect(preview.includedFields.chainStatus).toBe('not_checked')
    expect(preview.freshness.state).toBe('unverified')
    expect(preview.unresolvedChecks).toEqual([
      'On-chain Soroban registry status was not checked (offline mode).',
      'Backend NeonDB event feed was not queried (offline mode).',
      'Proof ID could not be resolved.',
      'Metadata hash could not be resolved.',
    ])
  })

  it('reports revoked chain status and error code as unresolved checks', () => {
    const preview = buildVerificationExportPreview({
      videoHash: SAMPLE_HASH,
      status: 'error',
      summary: 'Revoked: the chain record for this artifact has been revoked.',
      errorCode: 'REVOKED_EVIDENCE',
      offline: false,
      events: [makeEvent()],
      chainProof: makeChainProof({ status: 2 }),
      network: 'Test SDF Future Network ; October 2022',
      now: new Date('2026-11-19T12:05:00.000Z'),
    })

    expect(preview.includedFields.chainStatus).toBe('revoked')
    expect(preview.unresolvedChecks).toContain('On-chain proof record is revoked.')
    expect(preview.unresolvedChecks).toContain('Verification ended with error code: REVOKED_EVIDENCE.')
  })

  it('fails closed when verification is idle, in progress, or empty', () => {
    expect(() =>
      buildVerificationExportPreview({
        videoHash: SAMPLE_HASH,
        status: 'idle',
        summary: 'No verification run yet.',
        offline: false,
        events: [],
        chainProof: null,
        network: 'Test SDF Future Network ; October 2022',
      }),
    ).toThrow(/idle or in progress/i)

    expect(() =>
      buildVerificationExportPreview({
        videoHash: SAMPLE_HASH,
        status: 'verifying',
        summary: 'Inspecting evidence…',
        offline: false,
        events: [],
        chainProof: null,
        network: 'Test SDF Future Network ; October 2022',
      }),
    ).toThrow(/idle or in progress/i)

    expect(() =>
      buildVerificationExportPreview({
        videoHash: '',
        status: 'success',
        summary: '',
        offline: false,
        events: [],
        chainProof: null,
        network: 'Test SDF Future Network ; October 2022',
      }),
    ).toThrow(/without a reviewed verification result/i)
  })
})
