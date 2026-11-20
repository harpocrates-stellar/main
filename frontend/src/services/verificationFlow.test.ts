import { describe, expect, it, vi } from 'vitest'
import type { ChainProofRecord } from '../stellarTypes'
import {
  buildVerificationDimensions,
  runVerificationFlow,
  verifyUploadedVideo,
} from './verificationFlow'

vi.mock('./verificationService', () => ({
  extractMetadata: vi.fn(),
  fetchProofEventsByVideo: vi.fn(),
  getOnChainProof: vi.fn(),
}))

import {
  extractMetadata,
  fetchProofEventsByVideo,
  getOnChainProof,
} from './verificationService'

const VALID_HASH = 'a'.repeat(64)

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: VALID_HASH,
    metadataHash: 'b'.repeat(64),
    tier: 2,
    status: 1,
    createdAt: '2026-01-01T00:00:00Z',
    expiresAt: 2_000_000_000,
    source: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    issuer: 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQW2',
    ...overrides,
  }
}

describe('buildVerificationDimensions', () => {
  it('marks overall verified when all four trust dimensions pass', () => {
    const result = buildVerificationDimensions({
      hasHarpocratesMetadata: true,
      onChain: makeChainProof(),
      issuerRecord: { metadataHash: 'c'.repeat(64), active: true },
      nowUnixSeconds: 1_900_000_000,
    })

    expect(result.overall).toBe('verified')
    expect(result.hasFailure).toBe(false)
    expect(result.failedDimensions).toEqual([])
    expect(result.dimensions.contentIntegrity.state).toBe('verified')
    expect(result.dimensions.chainRegistration.state).toBe('verified')
    expect(result.dimensions.issuerTrust.state).toBe('verified')
    expect(result.dimensions.freshness.state).toBe('verified')
  })

  it('treats silent tier issuer trust as not_applicable without failing overall verdict', () => {
    const result = buildVerificationDimensions({
      hasHarpocratesMetadata: true,
      onChain: makeChainProof({ tier: 0, issuer: null, source: null, expiresAt: 0 }),
    })

    expect(result.overall).toBe('verified')
    expect(result.dimensions.issuerTrust.state).toBe('not_applicable')
    expect(result.dimensions.issuerTrust.code).toBe('SILENT_TIER_NO_ISSUER')
    expect(result.dimensions.freshness.state).toBe('verified')
  })

  it('does not let valid content, chain, and issuer mask an expired freshness failure', () => {
    const result = buildVerificationDimensions({
      hasHarpocratesMetadata: true,
      onChain: makeChainProof({ expiresAt: 1_800_000_000 }),
      issuerRecord: { metadataHash: 'c'.repeat(64), active: true },
      nowUnixSeconds: 1_900_000_000,
    })

    expect(result.dimensions.contentIntegrity.state).toBe('verified')
    expect(result.dimensions.chainRegistration.state).toBe('verified')
    expect(result.dimensions.issuerTrust.state).toBe('verified')
    expect(result.dimensions.freshness.state).toBe('failed')
    expect(result.dimensions.freshness.code).toBe('RECORD_EXPIRED')
    expect(result.overall).toBe('failed')
    expect(result.hasFailure).toBe(true)
    expect(result.failedDimensions).toEqual(['freshness'])
  })

  it('does not let valid content, chain, and freshness mask a revoked issuer failure', () => {
    const result = buildVerificationDimensions({
      hasHarpocratesMetadata: true,
      onChain: makeChainProof(),
      issuerRecord: { metadataHash: 'c'.repeat(64), active: false },
      nowUnixSeconds: 1_900_000_000,
    })

    expect(result.dimensions.contentIntegrity.state).toBe('verified')
    expect(result.dimensions.chainRegistration.state).toBe('verified')
    expect(result.dimensions.freshness.state).toBe('verified')
    expect(result.dimensions.issuerTrust.state).toBe('failed')
    expect(result.dimensions.issuerTrust.code).toBe('ISSUER_REVOKED')
    expect(result.overall).toBe('failed')
    expect(result.failedDimensions).toEqual(['issuerTrust'])
  })

  it('does not let valid chain, issuer, and freshness mask a metadata envelope mismatch', () => {
    const result = buildVerificationDimensions({
      hasHarpocratesMetadata: true,
      metadataEnvelopeMismatch: true,
      onChain: makeChainProof(),
      issuerRecord: { metadataHash: 'c'.repeat(64), active: true },
      nowUnixSeconds: 1_900_000_000,
    })

    expect(result.dimensions.contentIntegrity.state).toBe('failed')
    expect(result.dimensions.contentIntegrity.code).toBe('METADATA_ENVELOPE_MISMATCH')
    expect(result.dimensions.chainRegistration.state).toBe('verified')
    expect(result.dimensions.issuerTrust.state).toBe('verified')
    expect(result.dimensions.freshness.state).toBe('verified')
    expect(result.overall).toBe('failed')
    expect(result.failedDimensions).toEqual(['contentIntegrity'])
  })

  it('does not let valid content and freshness mask a revoked chain record', () => {
    const result = buildVerificationDimensions({
      hasHarpocratesMetadata: true,
      onChain: makeChainProof({ status: 2, expiresAt: 0 }),
      issuerRecord: { metadataHash: 'c'.repeat(64), active: true },
    })

    expect(result.dimensions.chainRegistration.state).toBe('failed')
    expect(result.dimensions.chainRegistration.code).toBe('CHAIN_REVOKED')
    expect(result.dimensions.contentIntegrity.state).toBe('verified')
    expect(result.overall).toBe('failed')
    expect(result.failedDimensions).toEqual(['chainRegistration'])
  })

  it('marks network-dependent dimensions unverified in offline mode and never verified overall', () => {
    const result = buildVerificationDimensions({
      hasHarpocratesMetadata: true,
      onChain: null,
      offline: true,
    })

    expect(result.dimensions.contentIntegrity.state).toBe('verified')
    expect(result.dimensions.chainRegistration.state).toBe('unverified')
    expect(result.dimensions.issuerTrust.state).toBe('unverified')
    expect(result.dimensions.freshness.state).toBe('unverified')
    expect(result.overall).toBe('incomplete')
    expect(result.hasFailure).toBe(false)
  })
})

describe('runVerificationFlow & verifyUploadedVideo', () => {
  it('returns structured trust dimensions alongside existing result fields', async () => {
    vi.mocked(fetchProofEventsByVideo).mockResolvedValueOnce([
      {
        id: 1,
        event_type: 'proof_registered',
        file_name: 'sample.mp4',
        video_hash: VALID_HASH,
        proof_id: 'p'.repeat(64),
        tier: 'source',
        created_at: '2026-01-01T00:00:00Z',
      },
    ])
    vi.mocked(getOnChainProof).mockResolvedValueOnce(
      makeChainProof({ tier: 1, expiresAt: 0 }),
    )

    const result = await runVerificationFlow(VALID_HASH)

    expect(result.videoHash).toBe(VALID_HASH)
    expect(result.hasHarpocratesMetadata).toBe(true)
    expect(result.trust.overall).toBe('verified')
    expect(result.trust.dimensions.issuerTrust.code).toBe('SOURCE_ATTRIBUTED')
  })

  it('recomputes trust dimensions using extracted metadata in verifyUploadedVideo', async () => {
    vi.mocked(extractMetadata).mockResolvedValueOnce({ hasHarpocratesMetadata: false })
    vi.mocked(fetchProofEventsByVideo).mockResolvedValueOnce([])
    vi.mocked(getOnChainProof).mockResolvedValueOnce(
      makeChainProof({ tier: 0, expiresAt: 0 }),
    )

    const file = new File(['synthetic'], 'synthetic.mp4', { type: 'video/mp4' })
    const result = await verifyUploadedVideo(file, VALID_HASH)

    expect(result.hasHarpocratesMetadata).toBe(false)
    expect(result.trust.dimensions.contentIntegrity.state).toBe('unverified')
    expect(result.trust.dimensions.chainRegistration.state).toBe('verified')
    expect(result.trust.overall).toBe('incomplete')
  })
})
