import { describe, it, expect } from 'vitest'
import type { ProofPackage } from './types'
import {
  MAX_PREVIEW_INPUT_BYTES,
  REDACTED_PLACEHOLDER,
  REDACTION_PREVIEW_VERSION,
  buildRedactionPreview,
  redactionErrorMessage,
  toPrivacySafePreviewSignal,
} from './redactionPreview'

function sampleProof(overrides: Partial<ProofPackage> = {}): ProofPackage {
  return {
    fileName: 'clip.mp4',
    sourceHash: 'a'.repeat(64),
    videoHash: 'b'.repeat(64),
    metadataHash: 'c'.repeat(64),
    proofId: 'd'.repeat(64),
    timestamp: '2026-09-21T12:00:00.000Z',
    tier: 'silent',
    silentWitness: {
      credentialRoot: 'ee'.repeat(32),
      nullifier: 'ff'.repeat(32),
      proof: 'ab'.repeat(256),
      publicInputs: 'cd'.repeat(176),
      proofBytes: 512,
      publicInputBytes: 352,
    },
    ...overrides,
  }
}

describe('buildRedactionPreview', () => {
  it('discloses public fingerprint fields and redacts witness/secrets', () => {
    const result = buildRedactionPreview({
      proof: sampleProof(),
      secrets: {
        credentialSeed: 'super-secret-credential',
        nullifierSeed: 'super-secret-nullifier',
        privateKey: 'SSECRETKEYEXAMPLE',
        mediaObjectUrl: 'blob:https://example.invalid/abc',
      },
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(result.version).toBe(REDACTION_PREVIEW_VERSION)
    expect(result.disclosedCount).toBeGreaterThan(0)
    expect(result.redactedCount).toBeGreaterThan(0)

    const byKey = Object.fromEntries(result.fields.map((f) => [f.key, f]))
    expect(byKey.fileName.value).toBe('clip.mp4')
    expect(byKey.tier.value).toBe('silent')
    expect(byKey.sourceHash.value).toContain('...')
    expect(byKey.sourceHash.value).not.toBe('a'.repeat(64))

    for (const key of [
      'silentWitness.credentialRoot',
      'silentWitness.nullifier',
      'silentWitness.proof',
      'silentWitness.publicInputs',
      'secrets.credentialSeed',
      'secrets.nullifierSeed',
      'secrets.privateKey',
      'secrets.mediaObjectUrl',
    ]) {
      expect(byKey[key].disclosed).toBe(false)
      expect(byKey[key].value).toBe(REDACTED_PLACEHOLDER)
    }

    // Secret plaintext must never appear in the preview payload.
    const serialized = JSON.stringify(result)
    expect(serialized).not.toContain('super-secret-credential')
    expect(serialized).not.toContain('super-secret-nullifier')
    expect(serialized).not.toContain('SSECRETKEYEXAMPLE')
    expect(serialized).not.toContain('blob:https://example.invalid/abc')
    expect(serialized).not.toContain('ab'.repeat(16))
  })

  it('returns MISSING_EVIDENCE when proof is absent', () => {
    const result = buildRedactionPreview({ proof: null })
    expect(result).toEqual({
      ok: false,
      code: 'MISSING_EVIDENCE',
      message: redactionErrorMessage('MISSING_EVIDENCE'),
    })
  })

  it('returns MALFORMED_EVIDENCE for non-object proof', () => {
    const result = buildRedactionPreview({ proof: 'not-a-package' as unknown as ProofPackage })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('MALFORMED_EVIDENCE')
  })

  it('returns UNSUPPORTED_TIER for unknown tiers', () => {
    const result = buildRedactionPreview({
      proof: sampleProof({ tier: 'unknown' as ProofPackage['tier'] }),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('UNSUPPORTED_TIER')
  })

  it('returns OVERSIZED_PAYLOAD when the input exceeds the byte budget', () => {
    const huge = 'x'.repeat(MAX_PREVIEW_INPUT_BYTES + 1024)
    const result = buildRedactionPreview({
      proof: sampleProof({ fileName: huge }),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('OVERSIZED_PAYLOAD')
    expect(JSON.stringify(result)).not.toContain(huge.slice(0, 64))
  })

  it('sanitizes path-like file names down to a basename', () => {
    const result = buildRedactionPreview({
      proof: sampleProof({ fileName: '../../etc/passwd\u0000.mp4' }),
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const file = result.fields.find((f) => f.key === 'fileName')
    expect(file?.value).toBe('passwd.mp4')
  })

  it('works for source and seal tiers without silent witness', () => {
    for (const tier of ['source', 'seal'] as const) {
      const result = buildRedactionPreview({ proof: sampleProof({ tier, silentWitness: undefined }) })
      expect(result.ok).toBe(true)
      if (!result.ok) return
      expect(result.fields.find((f) => f.key === 'tier')?.value).toBe(tier)
    }
  })
})

describe('toPrivacySafePreviewSignal', () => {
  it('emits codes and counts only — never field values', () => {
    const preview = buildRedactionPreview({ proof: sampleProof() })
    const signal = toPrivacySafePreviewSignal(preview)
    expect(signal.ok).toBe(true)
    expect(signal.version).toBe(REDACTION_PREVIEW_VERSION)
    expect(Object.keys(signal).sort()).toEqual(
      ['disclosedCount', 'ok', 'redactedCount', 'version'].sort(),
    )
    expect(JSON.stringify(signal)).not.toContain('clip.mp4')
    expect(JSON.stringify(signal)).not.toContain(REDACTED_PLACEHOLDER)
  })

  it('emits stable failure codes without messages that could carry values', () => {
    const signal = toPrivacySafePreviewSignal(buildRedactionPreview({ proof: null }))
    expect(signal).toEqual({
      ok: false,
      code: 'MISSING_EVIDENCE',
      version: REDACTION_PREVIEW_VERSION,
    })
  })
})
