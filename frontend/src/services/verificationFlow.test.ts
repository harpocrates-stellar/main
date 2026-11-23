import { describe, expect, it } from 'vitest'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import {
  DEFAULT_OBSERVATION_STALE_MS,
  evaluateVerificationObservations,
  formatLedgerBounds,
} from './verificationFlow'

const NOW_MS = Date.parse('2026-06-01T12:00:00Z')
const VIDEO_HASH = 'a'.repeat(64)

function makeEvent(overrides: Partial<ProofEvent> = {}): ProofEvent {
  return {
    id: 1,
    event_type: 'registered',
    file_name: null,
    video_hash: VIDEO_HASH,
    proof_id: 'b'.repeat(64),
    tier: 'silent',
    created_at: '2026-06-01T11:00:00Z',
    time_attestation: {
      version: 1,
      protocol: 'harpocrates-time',
      evidenceDigest: VIDEO_HASH,
      stellarAnchors: [
        {
          ledgerSequence: 1024,
          ledgerTimestamp: Math.floor(NOW_MS / 1000) - 3600,
          transactionHash: 'c'.repeat(64),
          networkPassphrase: 'Test SDF Network ; September 2015',
        },
      ],
      rfc3161Anchors: [],
    },
    ...overrides,
  }
}

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: VIDEO_HASH,
    metadataHash: 'd'.repeat(64),
    tier: 1,
    status: 1,
    createdAt: '2026-06-01T11:00:00Z',
    expiresAt: 0,
    source: null,
    issuer: null,
    ...overrides,
  }
}

describe('evaluateVerificationObservations', () => {
  it('marks fresh and matching backend + Soroban observations as aligned with ledger bounds', () => {
    const result = evaluateVerificationObservations({
      events: [
        makeEvent(),
        makeEvent({
          id: 2,
          time_attestation: {
            version: 1,
            protocol: 'harpocrates-time',
            evidenceDigest: VIDEO_HASH,
            stellarAnchors: [
              {
                ledgerSequence: 1050,
                ledgerTimestamp: Math.floor(NOW_MS / 1000) - 1200,
                transactionHash: 'e'.repeat(64),
                networkPassphrase: 'Test SDF Network ; September 2015',
              },
            ],
            rfc3161Anchors: [],
          },
        }),
      ],
      chainProof: makeChainProof(),
      nowMs: NOW_MS,
    })

    expect(result.agreement).toBe('aligned')
    expect(result.freshness).toBe('fresh')
    expect(result.ledgerBounds.minLedger).toBe(1024)
    expect(result.ledgerBounds.maxLedger).toBe(1050)
    expect(result.ledgerBounds.expiresAt).toBe(0)
    expect(formatLedgerBounds(result.ledgerBounds)).toBe('Ledgers #1024–#1050 · No expiry bound')
  })

  it('classifies expired chain ledger bounds as stale evidence rather than contradictory', () => {
    const expiredUnix = Math.floor(NOW_MS / 1000) - 60
    const result = evaluateVerificationObservations({
      events: [makeEvent()],
      chainProof: makeChainProof({ status: 3, expiresAt: expiredUnix }),
      errorCode: 'EXPIRED_EVIDENCE',
      nowMs: NOW_MS,
    })

    expect(result.agreement).toBe('stale')
    expect(result.freshness).toBe('stale')
    expect(result.disagreementReasons).toHaveLength(0)
    expect(result.staleReasons.length).toBeGreaterThan(0)
    expect(result.sources.soroban.freshness).toBe('stale')
  })

  it('classifies backend observations older than the freshness window as stale evidence', () => {
    const oldTimestamp = new Date(NOW_MS - DEFAULT_OBSERVATION_STALE_MS - 60_000).toISOString()
    const result = evaluateVerificationObservations({
      events: [makeEvent({ created_at: oldTimestamp })],
      chainProof: makeChainProof(),
      nowMs: NOW_MS,
    })

    expect(result.agreement).toBe('stale')
    expect(result.freshness).toBe('stale')
    expect(result.sources.backend.freshness).toBe('stale')
    expect(result.sources.soroban.freshness).toBe('fresh')
  })

  it('distinguishes contradictory tier observations from stale evidence', () => {
    const result = evaluateVerificationObservations({
      events: [makeEvent({ tier: 'seal' })],
      chainProof: makeChainProof({ tier: 1 }),
      nowMs: NOW_MS,
    })

    expect(result.agreement).toBe('contradictory')
    expect(result.disagreementReasons).toContain(
      'Backend tier observation disagrees with the Soroban registry tier.',
    )
  })

  it('flags revoked Soroban status vs active backend events as contradictory', () => {
    const result = evaluateVerificationObservations({
      events: [makeEvent({ event_type: 'registered' })],
      chainProof: makeChainProof({ status: 2 }),
      errorCode: 'REVOKED_EVIDENCE',
      nowMs: NOW_MS,
    })

    expect(result.agreement).toBe('contradictory')
    expect(result.disagreementReasons[0]).toMatch(/revoked status/i)
  })

  it('flags metadata envelope mismatch as contradictory even without backend events', () => {
    const result = evaluateVerificationObservations({
      events: [],
      chainProof: makeChainProof(),
      errorCode: 'METADATA_ENVELOPE_MISMATCH',
      nowMs: NOW_MS,
    })

    expect(result.agreement).toBe('contradictory')
    expect(result.disagreementReasons[0]).toMatch(/contradicts the on-chain envelope/i)
  })

  it('reports incomplete observations in offline mode without fabricating ledger bounds', () => {
    const result = evaluateVerificationObservations({
      events: [],
      chainProof: null,
      offline: true,
      nowMs: NOW_MS,
    })

    expect(result.agreement).toBe('incomplete')
    expect(result.freshness).toBe('unknown')
    expect(formatLedgerBounds(result.ledgerBounds)).toBe('Ledger bounds unavailable')
  })
})
