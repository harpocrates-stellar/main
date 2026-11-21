import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  buildProofPreparationPreview,
  PROOF_PREPARATION_POLICY_ID,
  PROOF_PREPARATION_POLICY_VERSION,
  PROOF_PREPARATION_PREVIEW_VERSION,
  proofPreparationErrorMessage,
} from './proofPreparationPreview'
import { REDACTED_PLACEHOLDER } from './redactionPreview'
import type { ProofPackage } from './types'

const VIDEO_HASH = `${'11'.repeat(16)}${'22'.repeat(16)}`

function makeProof(overrides: Partial<ProofPackage> = {}): ProofPackage {
  return {
    fileName: 'harpocrates-clip.mp4',
    sourceHash: 'a'.repeat(64),
    videoHash: VIDEO_HASH,
    metadataHash: 'c'.repeat(64),
    proofId: 'd'.repeat(64),
    timestamp: '2026-01-01T00:00:00.000Z',
    tier: 'silent',
    ...overrides,
  }
}

describe('buildProofPreparationPreview', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('shows the canonical public inputs and policy version before proving', () => {
    const result = buildProofPreparationPreview({
      proof: makeProof(),
      tier: 'silent',
      verifierScope: '0',
      epoch: 20_000,
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(result.version).toBe(PROOF_PREPARATION_PREVIEW_VERSION)
    expect(result.policyId).toBe(PROOF_PREPARATION_POLICY_ID)
    expect(result.policyVersion).toBe(PROOF_PREPARATION_POLICY_VERSION)
    expect(result.tier).toBe('silent')
    expect(result.publicInputs.map((field) => field.key)).toEqual([
      'video_hash_hi',
      'video_hash_lo',
      'verifier_scope',
      'epoch',
    ])
    expect(result.publicInputs[0].value).toBe(BigInt(`0x${'11'.repeat(16)}`).toString(10))
    expect(result.publicInputs[1].value).toBe(BigInt(`0x${'22'.repeat(16)}`).toString(10))
    expect(result.publicInputs[2].value).toBe('0')
    expect(result.publicInputs[3].value).toBe('20000')
    expect(result.publicInputs.every((field) => field.disclosed)).toBe(true)
    expect(result.readOnly).toBe(true)
    expect(result.transactionSubmission).toBe('none')
  })

  it('normalizes hexadecimal scope and stays deterministic across calls', () => {
    const input = {
      proof: makeProof(),
      tier: 'silent' as const,
      verifierScope: '0x07',
      epoch: 12,
    }

    const first = buildProofPreparationPreview(input)
    const second = buildProofPreparationPreview(input)

    expect(second).toEqual(first)
    expect(first.ok).toBe(true)
    if (!first.ok) return
    expect(first.publicInputs.find((field) => field.key === 'verifier_scope')?.value).toBe('7')
  })

  it('defaults the epoch to the current UTC day', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-11-19T23:30:00.000Z'))

    const result = buildProofPreparationPreview({ proof: makeProof(), tier: 'silent' })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.publicInputs.find((field) => field.key === 'epoch')?.value).toBe(
      String(Math.floor(Date.parse('2026-11-19T23:30:00.000Z') / 86_400_000)),
    )
  })

  it('conceals private witness values even when the package already carries them', () => {
    const proof = makeProof({
      silentWitness: {
        credentialRoot: 'ab'.repeat(32),
        nullifier: 'cd'.repeat(32),
        proof: 'ef'.repeat(64),
        publicInputs: '99'.repeat(32),
        proofBytes: 128,
        publicInputBytes: 128,
      },
    })

    const result = buildProofPreparationPreview({ proof, tier: 'silent', epoch: 1 })
    expect(result.ok).toBe(true)
    if (!result.ok) return

    const serialized = JSON.stringify(result)
    expect(serialized).not.toContain('ab'.repeat(32))
    expect(serialized).not.toContain('cd'.repeat(32))
    expect(serialized).not.toContain('ef'.repeat(64))
    expect(serialized).not.toContain('99'.repeat(32))

    expect(result.concealedInputs.map((field) => field.key)).toEqual([
      'credential_secret',
      'nullifier_secret',
    ])
    for (const field of result.concealedInputs) {
      expect(field.value).toBe(REDACTED_PLACEHOLDER)
      expect(field.disclosed).toBe(false)
    }
  })

  it('fails closed on non-canonical public inputs without echoing them', () => {
    const badHash = 'zz'.repeat(32)
    const cases = [
      {
        input: { proof: makeProof({ videoHash: badHash }), tier: 'silent' as const },
        needle: badHash,
      },
      {
        input: { proof: makeProof(), tier: 'silent' as const, verifierScope: 'harpocrates' },
        needle: 'harpocrates',
      },
      {
        input: { proof: makeProof(), tier: 'silent' as const, epoch: -1 },
        needle: '-1',
      },
    ]

    for (const { input, needle } of cases) {
      const result = buildProofPreparationPreview(input)
      expect(result.ok).toBe(false)
      if (result.ok) continue
      expect(result.code).toBe('INVALID_PUBLIC_INPUTS')
      expect(result.message).toBe(proofPreparationErrorMessage('INVALID_PUBLIC_INPUTS'))
      expect(result.message).not.toContain(needle)
    }
  })

  it('rejects tiers that do not prove and evidence that does not exist yet', () => {
    expect(
      buildProofPreparationPreview({ proof: makeProof({ tier: 'source' }), tier: 'source' }),
    ).toMatchObject({ ok: false, code: 'UNSUPPORTED_TIER' })

    expect(
      buildProofPreparationPreview({ proof: null, tier: 'silent' }),
    ).toMatchObject({ ok: false, code: 'MISSING_EVIDENCE' })
  })

  it('performs no network work and submits no transaction', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    const result = buildProofPreparationPreview({ proof: makeProof(), tier: 'silent', epoch: 5 })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.readOnly).toBe(true)
    expect(result.transactionSubmission).toBe('none')
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
