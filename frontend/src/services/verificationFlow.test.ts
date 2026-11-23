import { describe, expect, it } from 'vitest'
import {
  resolveVerifiedStatementIdentity,
  shouldResetDependentTabState,
} from './verificationFlow'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'

const DIGEST_A = '1'.repeat(64)
const DIGEST_B = '2'.repeat(64)
const PROOF_A = `0x${'a'.repeat(64)}`
const PROOF_UNRELATED = `0x${'e'.repeat(64)}`

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: DIGEST_A,
    metadataHash: 'm'.repeat(64),
    tier: 1,
    source: 'GSRC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEF',
    issuer: 'GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEF',
    createdAt: '1750000000',
    expiresAt: 0,
    status: 1,
    ...overrides,
  }
}

describe('resolveVerifiedStatementIdentity', () => {
  it('resolves active verified statement digest and matching event proofId', () => {
    const events: ProofEvent[] = [
      {
        id: 1,
        video_hash: DIGEST_B,
        proof_id: PROOF_UNRELATED,
        tier: 'seal',
        tx_hash: 'tx1',
        created_at: '2026-01-01T00:00:00Z',
      },
      {
        id: 2,
        video_hash: DIGEST_A,
        proof_id: PROOF_A,
        tier: 'source',
        tx_hash: 'tx2',
        created_at: '2026-01-01T01:00:00Z',
      },
    ]

    const result = resolveVerifiedStatementIdentity({
      verifyHash: DIGEST_A,
      events,
      chainProof: makeChainProof(),
    })

    expect(result.statementDigest).toBe(DIGEST_A)
    expect(result.statementKey).toBe(DIGEST_A)
    expect(result.proofId).toBe(PROOF_A)
    expect(result.matchingEvents).toHaveLength(1)
    expect(result.matchingEvents[0].id).toBe(2)
    expect(result.chainSource).toBe('GSRC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEF')
    expect(result.metadataHash).toBe('m'.repeat(64))
  })

  it('never borrows proof ID from an event with a different statement digest', () => {
    const events: ProofEvent[] = [
      {
        id: 1,
        video_hash: DIGEST_B,
        proof_id: PROOF_UNRELATED,
        tier: 'seal',
        tx_hash: 'tx1',
        created_at: '2026-01-01T00:00:00Z',
      },
    ]

    const result = resolveVerifiedStatementIdentity({
      verifyHash: DIGEST_A,
      events,
      chainProof: null,
    })

    expect(result.statementDigest).toBe(DIGEST_A)
    expect(result.proofId).toBeNull()
    expect(result.matchingEvents).toHaveLength(0)
  })

  it('ignores typed proof ID input if videoHashInput conflicts with verified statement digest', () => {
    const result = resolveVerifiedStatementIdentity({
      verifyHash: DIGEST_A,
      videoHashInput: DIGEST_B,
      proofIdInput: 'stale-typed-proof-id',
      events: [],
      chainProof: null,
    })

    expect(result.statementDigest).toBe(DIGEST_A)
    expect(result.proofId).toBeNull()
  })

  it('normalizes 0x prefixes and lowercase hex digests', () => {
    const result = resolveVerifiedStatementIdentity({
      verifyHash: `0x${DIGEST_A.toUpperCase()}`,
      proofIdInput: `0X${'F'.repeat(64)}`,
      events: [],
      chainProof: null,
    })

    expect(result.statementDigest).toBe(DIGEST_A)
    expect(result.proofId).toBe(`0x${'f'.repeat(64)}`)
  })

  it('handles empty statement inputs safely without throwing', () => {
    const result = resolveVerifiedStatementIdentity({
      verifyHash: '',
      events: [],
      chainProof: null,
    })

    expect(result.statementDigest).toBe('')
    expect(result.statementKey).toBe('__empty_statement__')
    expect(result.proofId).toBeNull()
    expect(result.metadataHash).toBeNull()
    expect(result.chainSource).toBeNull()
    expect(result.matchingEvents).toHaveLength(0)
  })
})

describe('shouldResetDependentTabState', () => {
  it('returns true when statementKey changes', () => {
    expect(shouldResetDependentTabState(DIGEST_A, DIGEST_B)).toBe(true)
    expect(shouldResetDependentTabState('__empty_statement__', DIGEST_A)).toBe(true)
  })

  it('returns false when statementKey is identical', () => {
    expect(shouldResetDependentTabState(DIGEST_A, DIGEST_A)).toBe(false)
    expect(shouldResetDependentTabState('__empty_statement__', '__empty_statement__')).toBe(false)
  })
})
