/**
 * Focused tests for verificationFlow — stable trust reason code mapping,
 * unknown issuer vs invalid signature separation, and flow orchestration.
 * Uses synthetic fixtures and mocked services only.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ChainProofRecord } from '../stellarTypes'
import { STELLAR_STRKEY_LENGTH } from '../provenance/issuerTrust'
import {
  TRUST_REASON_COPY,
  explainVerificationTrust,
  getTrustReasonCopy,
  resolveTrustReasonCode,
  runVerificationFlow,
  verifyUploadedVideo,
  type TrustReasonCode,
} from './verificationFlow'

vi.mock('./verificationService', () => ({
  extractMetadata: vi.fn(),
  fetchProofEventsByVideo: vi.fn(),
  getOnChainProof: vi.fn(),
}))

const VALID_HASH = 'a'.repeat(64)
const ACCOUNT_ISSUER = `G${'B'.repeat(STELLAR_STRKEY_LENGTH - 1)}`

const SEAL_PROOF: ChainProofRecord = {
  videoHash: VALID_HASH,
  metadataHash: 'b'.repeat(64),
  tier: 3,
  status: 1,
  createdAt: '1700000000',
  expiresAt: 0,
  source: null,
  issuer: ACCOUNT_ISSUER,
}

const SILENT_PROOF: ChainProofRecord = {
  ...SEAL_PROOF,
  tier: 1,
  issuer: null,
}

const ALL_REASON_CODES: TrustReasonCode[] = [
  'TRUSTED_ISSUER',
  'UNKNOWN_ISSUER',
  'REVOKED_ISSUER',
  'EXPIRED_ENDORSEMENT',
  'INVALID_SIGNATURE',
  'MALFORMED_ISSUER',
  'ISSUER_LOOKUP_UNAVAILABLE',
  'NO_ISSUER_REQUIRED',
  'ISSUER_CHECK_PENDING',
  'OFFLINE_NOT_CHECKED',
]

afterEach(() => {
  vi.clearAllMocks()
})

describe('TRUST_REASON_COPY and getTrustReasonCopy', () => {
  it('provides distinct, accessible, privacy-safe copy for every stable reason code', () => {
    const headings = new Set<string>()
    for (const code of ALL_REASON_CODES) {
      const copy = getTrustReasonCopy(code)
      expect(copy).toBe(TRUST_REASON_COPY[code])
      expect(copy.code).toBe(code)
      expect(copy.heading.length).toBeGreaterThan(0)
      expect(copy.explanation.length).toBeGreaterThan(copy.heading.length)
      expect(copy.signatureDistinction.length).toBeGreaterThan(0)
      expect(copy.explanation).not.toMatch(/rpc|stack|http|exception/i)
      headings.add(copy.heading)
    }
    expect(headings.size).toBe(ALL_REASON_CODES.length)
  })

  it('explains UNKNOWN_ISSUER separately from an invalid signature', () => {
    const unknown = getTrustReasonCopy('UNKNOWN_ISSUER')
    const invalidSig = getTrustReasonCopy('INVALID_SIGNATURE')

    expect(unknown.severity).toBe('caution')
    expect(unknown.isAlert).toBe(false)
    expect(unknown.signatureDistinction).toMatch(/not an invalid signature/i)
    expect(unknown.signatureDistinction).toMatch(/underlying proof result/i)

    expect(invalidSig.severity).toBe('critical')
    expect(invalidSig.isAlert).toBe(true)
    expect(invalidSig.explanation).toMatch(/signature or proof binding failed/i)
    expect(invalidSig.signatureDistinction).toMatch(/separate from.*issuer/i)
  })

  it('explains ISSUER_LOOKUP_UNAVAILABLE as neither unknown issuer nor invalid signature', () => {
    const unavailable = getTrustReasonCopy('ISSUER_LOOKUP_UNAVAILABLE')

    expect(unavailable.severity).toBe('caution')
    expect(unavailable.isAlert).toBe(false)
    expect(unavailable.explanation).toMatch(/no institutional trust decision was made/i)
    expect(unavailable.signatureDistinction).toMatch(/neither an unknown issuer nor an invalid signature/i)
  })
})

describe('resolveTrustReasonCode', () => {
  it('maps unknown issuer trust to UNKNOWN_ISSUER when proof verification succeeded', () => {
    expect(
      resolveTrustReasonCode({
        status: 'success',
        errorCode: null,
        issuerTrustState: 'unknown',
        chainProof: SEAL_PROOF,
      }),
    ).toBe('UNKNOWN_ISSUER')
  })

  it('maps INVALID_EVIDENCE and METADATA_ENVELOPE_MISMATCH to INVALID_SIGNATURE (fail-closed)', () => {
    expect(
      resolveTrustReasonCode({
        status: 'error',
        errorCode: 'INVALID_EVIDENCE',
        issuerTrustState: 'unknown',
        chainProof: SEAL_PROOF,
      }),
    ).toBe('INVALID_SIGNATURE')

    expect(
      resolveTrustReasonCode({
        status: 'error',
        errorCode: 'METADATA_ENVELOPE_MISMATCH',
        issuerTrustState: 'trusted',
        chainProof: SEAL_PROOF,
      }),
    ).toBe('INVALID_SIGNATURE')
  })

  it('preserves fail-closed INVALID_SIGNATURE even in offline mode', () => {
    expect(
      resolveTrustReasonCode({
        offline: true,
        status: 'error',
        errorCode: 'INVALID_EVIDENCE',
      }),
    ).toBe('INVALID_SIGNATURE')
  })

  it('maps offline verification without signature failure to OFFLINE_NOT_CHECKED', () => {
    expect(
      resolveTrustReasonCode({
        offline: true,
        status: 'success',
        errorCode: null,
      }),
    ).toBe('OFFLINE_NOT_CHECKED')
  })

  it.each([
    ['trusted', 'TRUSTED_ISSUER'],
    ['unknown', 'UNKNOWN_ISSUER'],
    ['revoked', 'REVOKED_ISSUER'],
    ['expired', 'EXPIRED_ENDORSEMENT'],
    ['malformed', 'MALFORMED_ISSUER'],
    ['oversized', 'MALFORMED_ISSUER'],
    ['unavailable', 'ISSUER_LOOKUP_UNAVAILABLE'],
    ['checking', 'ISSUER_CHECK_PENDING'],
    ['unsupported', 'NO_ISSUER_REQUIRED'],
  ] as const)('maps issuerTrustState %s to %s', (state, expected) => {
    expect(resolveTrustReasonCode({ issuerTrustState: state, chainProof: SEAL_PROOF })).toBe(expected)
  })

  it('falls back to chainProof address classification when issuerTrustState is omitted', () => {
    expect(resolveTrustReasonCode({ chainProof: SILENT_PROOF })).toBe('NO_ISSUER_REQUIRED')
    expect(resolveTrustReasonCode({ chainProof: { ...SEAL_PROOF, issuer: 'not-a-strkey' } })).toBe('MALFORMED_ISSUER')
    expect(resolveTrustReasonCode({ chainProof: SEAL_PROOF })).toBe('ISSUER_CHECK_PENDING')
    expect(resolveTrustReasonCode({})).toBeNull()
  })

  it('explainVerificationTrust returns null when no reason applies', () => {
    expect(explainVerificationTrust({ status: 'idle', chainProof: null, errorCode: null })).toBeNull()
  })
})

describe('runVerificationFlow and verifyUploadedVideo', () => {
  it('preserves existing result shape and attaches trust explanation for unknown issuer', async () => {
    const svc = await import('./verificationService')
    vi.mocked(svc.fetchProofEventsByVideo).mockResolvedValueOnce([
      {
        id: 1,
        event_type: 'registered',
        file_name: null,
        video_hash: VALID_HASH,
        proof_id: 'c'.repeat(64),
        tier: 'seal',
        created_at: '2026-01-01T00:00:00Z',
      },
    ])
    vi.mocked(svc.getOnChainProof).mockResolvedValueOnce(SEAL_PROOF)

    const result = await runVerificationFlow(VALID_HASH, { issuerTrustState: 'unknown' })

    expect(result.videoHash).toBe(VALID_HASH)
    expect(result.hasHarpocratesMetadata).toBe(true)
    expect(result.events).toHaveLength(1)
    expect(result.onChain).toEqual(SEAL_PROOF)
    expect(result.trustReasonCode).toBe('UNKNOWN_ISSUER')
    expect(result.trustExplanation?.heading).toMatch(/unknown issuer/i)
  })

  it('attaches NO_ISSUER_REQUIRED for Tier 1 proofs without an issuer', async () => {
    const svc = await import('./verificationService')
    vi.mocked(svc.fetchProofEventsByVideo).mockResolvedValueOnce([])
    vi.mocked(svc.getOnChainProof).mockResolvedValueOnce(SILENT_PROOF)

    const result = await runVerificationFlow(VALID_HASH)

    expect(result.onChain).toEqual(SILENT_PROOF)
    expect(result.trustReasonCode).toBe('NO_ISSUER_REQUIRED')
  })

  it('verifyUploadedVideo combines extraction with trust explanation', async () => {
    const svc = await import('./verificationService')
    vi.mocked(svc.extractMetadata).mockResolvedValueOnce({ hasHarpocratesMetadata: true })
    vi.mocked(svc.fetchProofEventsByVideo).mockResolvedValueOnce([])
    vi.mocked(svc.getOnChainProof).mockResolvedValueOnce(SEAL_PROOF)

    const file = new File([new Uint8Array([1, 2, 3])], 'synthetic.mp4', { type: 'video/mp4' })
    const result = await verifyUploadedVideo(file, VALID_HASH, { issuerTrustState: 'unknown' })

    expect(result.hasHarpocratesMetadata).toBe(true)
    expect(result.trustReasonCode).toBe('UNKNOWN_ISSUER')
    expect(result.trustExplanation?.signatureDistinction).toMatch(/not an invalid signature/i)
  })
})
