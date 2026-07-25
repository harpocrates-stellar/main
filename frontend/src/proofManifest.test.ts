import { describe, it, expect } from 'vitest'
import { createProofManifest, serializeManifest, type ProofManifest } from './proofManifest'

const VALID_INPUT = {
  proofId: 'a'.repeat(64),
  tier: 'silent' as const,
  network: 'Test SDF Network ; September 2015',
  contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  transactionRef: 'b'.repeat(64),
  videoHash: 'c'.repeat(64),
  metadataHash: 'd'.repeat(64),
  sourceHash: 'e'.repeat(64),
  timestamp: '2025-07-24T12:00:00.000Z',
}

// ── createProofManifest – positive cases ──────────────────────────────────

describe('createProofManifest', () => {
  it('returns a manifest with protocol and version fields', () => {
    const manifest = createProofManifest(VALID_INPUT)

    expect(manifest.protocol).toBe('harpocrates')
    expect(manifest.version).toBe(1)
  })

  it('copies all supplied fields into the manifest', () => {
    const manifest = createProofManifest(VALID_INPUT)

    expect(manifest.proofId).toBe(VALID_INPUT.proofId)
    expect(manifest.tier).toBe(VALID_INPUT.tier)
    expect(manifest.network).toBe(VALID_INPUT.network)
    expect(manifest.contractId).toBe(VALID_INPUT.contractId)
    expect(manifest.transactionRef).toBe(VALID_INPUT.transactionRef)
    expect(manifest.videoHash).toBe(VALID_INPUT.videoHash)
    expect(manifest.metadataHash).toBe(VALID_INPUT.metadataHash)
    expect(manifest.sourceHash).toBe(VALID_INPUT.sourceHash)
    expect(manifest.timestamp).toBe(VALID_INPUT.timestamp)
  })

  it('does not expose any secret or private witness fields', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const keys = Object.keys(manifest)

    const forbiddenPatterns = [
      /seed/i,
      /credential/i,
      /nullifier/i,
      /witness/i,
      /private/i,
      /secret/i,
      /proof(?!Id)/i,
    ]

    for (const key of keys) {
      for (const pattern of forbiddenPatterns) {
        expect(key).not.toMatch(pattern)
      }
    }
  })

  it.each(['silent', 'source', 'seal'] as const)('accepts tier "%s"', (tier) => {
    const manifest = createProofManifest({ ...VALID_INPUT, tier })
    expect(manifest.tier).toBe(tier)
  })
})

// ── createProofManifest – negative cases ──────────────────────────────────

describe('createProofManifest – negative cases', () => {
  it('produces a valid manifest even when input hashes are short hex strings', () => {
    const manifest = createProofManifest({
      ...VALID_INPUT,
      videoHash: 'abcd',
      metadataHash: '1234',
    })

    expect(manifest.videoHash).toBe('abcd')
    expect(manifest.metadataHash).toBe('1234')
  })
})

// ── serializeManifest – deterministic output ──────────────────────────────

describe('serializeManifest', () => {
  it('returns a JSON string', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)

    expect(typeof json).toBe('string')
    expect(() => JSON.parse(json)).not.toThrow()
  })

  it('sorts keys alphabetically for deterministic output', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as ProofManifest
    const keys = Object.keys(parsed)

    expect(keys).toEqual([...keys].sort())
  })

  it('produces identical output across multiple invocations', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const first = serializeManifest(manifest)
    const second = serializeManifest(manifest)

    expect(first).toBe(second)
  })

  it('produces different output when inputs differ', () => {
    const manifestA = createProofManifest(VALID_INPUT)
    const manifestB = createProofManifest({ ...VALID_INPUT, proofId: 'f'.repeat(64) })

    expect(serializeManifest(manifestA)).not.toBe(serializeManifest(manifestB))
  })

  it('includes all expected top-level keys in sorted order', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as Record<string, unknown>

    const expectedKeys = [
      'contractId',
      'metadataHash',
      'network',
      'proofId',
      'protocol',
      'sourceHash',
      'tier',
      'timestamp',
      'transactionRef',
      'version',
      'videoHash',
    ]

    expect(Object.keys(parsed)).toEqual(expectedKeys)
  })
})

// ── round-trip: create then serialize ─────────────────────────────────────

describe('manifest round-trip', () => {
  it('can be parsed back into an object with all fields intact', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as ProofManifest

    expect(parsed).toEqual(manifest)
  })
})
