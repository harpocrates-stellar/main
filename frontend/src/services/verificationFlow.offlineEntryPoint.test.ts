/**
 * Focused tests for the offline-verification entry point (issue #1137).
 *
 * Covers:
 * - validate_export_date_range: offline mode surfaces unavailable live checks
 * - explainVerificationTrust: skipped online revocation checks are NEVER labelled passed
 * - resolveVerifiedStatementIdentity: correct identity resolution
 * - createVerificationRevisionGuard: revision sequencing
 */

import { describe, it, expect } from 'vitest'
import {
  createVerificationRevisionGuard,
  explainVerificationTrust,
  resolveVerifiedStatementIdentity,
  buildVerificationExportPreview,
  type VerificationExportPreviewInput,
} from './verificationFlow'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'

// ── helpers ──────────────────────────────────────────────────────────────

function makeChainProof(overrides: Partial<ChainProofRecord> = {}): ChainProofRecord {
  return {
    videoHash: 'a'.repeat(64),
    metadataHash: 'b'.repeat(64),
    proofId: 'pid-1',
    tier: 1,
    status: 1,
    createdAt: new Date().toISOString(),
    expiresAt: null,
    source: null,
    issuer: null,
    ...overrides,
  }
}

function makeEvent(overrides: Partial<ProofEvent> = {}): ProofEvent {
  return {
    id: 1,
    event_type: 'registered',
    video_hash: 'a'.repeat(64),
    proof_id: 'pid-1',
    tier: 'source',
    tx_hash: null,
    created_at: new Date().toISOString(),
    file_name: null,
    time_attestation: undefined,
    ...overrides,
  }
}

function makePreviewInput(
  overrides: Partial<VerificationExportPreviewInput> = {},
): VerificationExportPreviewInput {
  return {
    videoHash: 'a'.repeat(64),
    status: 'success',
    summary: 'Verified.',
    offline: false,
    events: [],
    chainProof: null,
    network: 'Test SDF Network ; September 2015',
    ...overrides,
  }
}

// ── explainVerificationTrust ─────────────────────────────────────────────

describe('explainVerificationTrust – offline mode', () => {
  it('returns unverified overall when offline, never verified', () => {
    const result = explainVerificationTrust({
      status: 'success',
      offline: true,
      errorCode: null,
      chainProof: null,
      events: [],
    })
    expect(result.overall).toBe('unverified')
  })

  it('explicitly states online revocation was not checked', () => {
    const result = explainVerificationTrust({
      status: 'success',
      offline: true,
      errorCode: null,
      chainProof: makeChainProof({ status: 1 }),
      events: [makeEvent()],
    })
    // Skipped online check must NEVER be labelled as passed.
    expect(result.overall).not.toBe('verified')
    expect(result.detail.toLowerCase()).toMatch(/not checked|online|offline/)
  })

  it('still returns unverified even with a loaded chain proof when offline', () => {
    const result = explainVerificationTrust({
      status: 'success',
      offline: true,
      errorCode: null,
      chainProof: makeChainProof({ status: 1 }),
      events: [makeEvent()],
    })
    expect(result.overall).toBe('unverified')
  })

  it('returns failed for revoked in online mode', () => {
    const result = explainVerificationTrust({
      status: 'success',
      offline: false,
      errorCode: 'REVOKED_EVIDENCE',
      chainProof: makeChainProof({ status: 2 }),
      events: [],
    })
    expect(result.overall).toBe('failed')
  })

  it('returns verified when online, chain proof present, events corroborate', () => {
    const result = explainVerificationTrust({
      status: 'success',
      offline: false,
      errorCode: null,
      chainProof: makeChainProof(),
      events: [makeEvent()],
    })
    expect(result.overall).toBe('verified')
  })

  it('never marks expired as verified', () => {
    const result = explainVerificationTrust({
      status: 'success',
      offline: false,
      errorCode: 'EXPIRED_EVIDENCE',
      chainProof: makeChainProof({ status: 3 }),
      events: [],
    })
    expect(result.overall).toBe('failed')
  })
})

// ── buildVerificationExportPreview – offline unresolvedChecks ────────────

describe('buildVerificationExportPreview – offline mode shows unavailable live checks', () => {
  it('populates unresolvedChecks for both Soroban and NeonDB when offline', () => {
    const preview = buildVerificationExportPreview(
      makePreviewInput({ offline: true, status: 'success' }),
    )
    const checks = preview.unresolvedChecks.join(' ')
    expect(checks).toMatch(/soroban/i)
    expect(checks).toMatch(/neondb/i)
  })

  it('sets mode to "offline" in includedFields', () => {
    const preview = buildVerificationExportPreview(
      makePreviewInput({ offline: true, status: 'success' }),
    )
    expect(preview.includedFields.mode).toBe('offline')
  })

  it('sets chainStatus to "not_checked" when offline', () => {
    const preview = buildVerificationExportPreview(
      makePreviewInput({ offline: true, status: 'success', chainProof: makeChainProof() }),
    )
    // Online revocation status must not be reported as confirmed when it was never checked.
    expect(preview.includedFields.chainStatus).toBe('not_checked')
  })

  it('sets freshness state to "unverified" when offline', () => {
    const preview = buildVerificationExportPreview(
      makePreviewInput({
        offline: true,
        status: 'success',
        capturedAt: new Date().toISOString(),
      }),
    )
    expect(preview.freshness.state).toBe('unverified')
  })

  it('online mode with confirmed chain proof is "confirmed" and "fresh"', () => {
    const preview = buildVerificationExportPreview(
      makePreviewInput({
        offline: false,
        status: 'success',
        chainProof: makeChainProof({ status: 1 }),
        capturedAt: new Date().toISOString(),
      }),
    )
    expect(preview.includedFields.chainStatus).toBe('confirmed')
    expect(preview.freshness.state).toBe('fresh')
  })
})

// ── resolveVerifiedStatementIdentity ─────────────────────────────────────

describe('resolveVerifiedStatementIdentity', () => {
  it('prefers verifyHash as statement digest', () => {
    const result = resolveVerifiedStatementIdentity({
      verifyHash: 'a'.repeat(64),
      videoHashInput: 'b'.repeat(64),
      proofIdInput: '',
      events: [],
      chainProof: null,
    })
    expect(result.statementDigest).toBe('a'.repeat(64))
  })

  it('falls back to videoHashInput when verifyHash is empty', () => {
    const result = resolveVerifiedStatementIdentity({
      verifyHash: '',
      videoHashInput: 'c'.repeat(64),
      proofIdInput: '',
      events: [],
      chainProof: null,
    })
    expect(result.statementDigest).toBe('c'.repeat(64))
  })

  it('filters matchingEvents to those with the resolved digest', () => {
    const target = 'a'.repeat(64)
    const other = 'b'.repeat(64)
    const result = resolveVerifiedStatementIdentity({
      verifyHash: target,
      videoHashInput: '',
      proofIdInput: '',
      events: [makeEvent({ video_hash: target }), makeEvent({ video_hash: other, id: 2 })],
      chainProof: null,
    })
    expect(result.matchingEvents).toHaveLength(1)
    expect(result.matchingEvents[0].video_hash).toBe(target)
  })

  it('resolves metadataHash from chainProof', () => {
    const result = resolveVerifiedStatementIdentity({
      verifyHash: 'a'.repeat(64),
      videoHashInput: '',
      proofIdInput: '',
      events: [],
      chainProof: makeChainProof({ metadataHash: 'x'.repeat(64) }),
    })
    expect(result.metadataHash).toBe('x'.repeat(64))
  })
})

// ── createVerificationRevisionGuard ──────────────────────────────────────

describe('createVerificationRevisionGuard', () => {
  it('starts at revision 1 after first next()', () => {
    const guard = createVerificationRevisionGuard()
    expect(guard.next()).toBe(1)
  })

  it('isCurrent returns true for the latest revision', () => {
    const guard = createVerificationRevisionGuard()
    const rev = guard.next()
    expect(guard.isCurrent(rev)).toBe(true)
  })

  it('isCurrent returns false for a superseded revision', () => {
    const guard = createVerificationRevisionGuard()
    const old = guard.next()
    guard.next()
    expect(guard.isCurrent(old)).toBe(false)
  })

  it('invalidate() advances the sequence without returning a revision', () => {
    const guard = createVerificationRevisionGuard()
    const rev = guard.next()
    guard.invalidate()
    expect(guard.isCurrent(rev)).toBe(false)
  })
})
