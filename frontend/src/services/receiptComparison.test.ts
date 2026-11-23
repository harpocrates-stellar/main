import { describe, expect, it } from 'vitest'
import type { VerificationReceiptPayload } from '../verificationReceipt'
import {
  compareVerificationReceipts,
  createReceiptComparisonShareUrl,
  formatTimeDelta,
  parseReceiptComparisonShareUrl,
  parseReceiptInput,
} from './receiptComparison'

const HEX_A = 'a'.repeat(64)
const HEX_B = 'b'.repeat(64)
const HEX_C = 'c'.repeat(64)
const HEX_D = 'd'.repeat(64)
const HEX_E = 'e'.repeat(64)
const HEX_F = 'f'.repeat(64)

function makeReceipt(
  overrides: Partial<VerificationReceiptPayload> = {},
): VerificationReceiptPayload {
  return {
    protocol: 'harpocrates-verification-receipt',
    version: 1,
    result: 'verified',
    verifiedAt: '2026-05-01T10:00:00.000Z',
    proofId: HEX_A,
    videoHash: HEX_B,
    metadataHash: HEX_C,
    tier: 'source',
    networkPassphrase: 'Test SDF Network ; September 2015',
    contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4',
    ledgerSequence: 100500,
    transactionHash: HEX_D,
    circuitVersion: '0.25.0',
    verifierVersion: '1.2.0',
    signer: {
      keyId: 'verifier-key-2026-q1',
      algorithm: 'ECDSA_P256_SHA256',
    },
    ...overrides,
  }
}

describe('parseReceiptInput', () => {
  it('parses a valid JSON receipt and normalizes timestamps and hex digests', () => {
    const raw = JSON.stringify({
      ...makeReceipt({
        verifiedAt: '2026-05-01T10:00:00Z',
        videoHash: HEX_B.toUpperCase(),
      }),
      signature: 'fake-signature-stripped-on-parse',
    })

    const res = parseReceiptInput(raw)
    expect(res.ok).toBe(true)
    if (res.ok) {
      expect(res.receipt.verifiedAt).toBe('2026-05-01T10:00:00.000Z')
      expect(res.receipt.videoHash).toBe(HEX_B)
      expect('signature' in res.receipt).toBe(false)
    }
  })

  it('rejects empty, malformed, and oversized inputs fail-closed', () => {
    expect(parseReceiptInput('')).toMatchObject({ ok: false, code: 'EMPTY_INPUT' })
    expect(parseReceiptInput('{not-json')).toMatchObject({ ok: false, code: 'MALFORMED_RECEIPT' })
    expect(parseReceiptInput('x'.repeat(9000))).toMatchObject({ ok: false, code: 'OVERSIZED_INPUT' })
  })

  it('rejects unsupported protocol/version and invalid digests or timestamps', () => {
    const badProto = parseReceiptInput(JSON.stringify({ ...makeReceipt(), version: 99 }))
    expect(badProto).toMatchObject({ ok: false, code: 'UNSUPPORTED_PROTOCOL' })

    const badDigest = parseReceiptInput(JSON.stringify({ ...makeReceipt(), videoHash: 'short' }))
    expect(badDigest).toMatchObject({ ok: false, code: 'INVALID_DIGEST' })

    const badTime = parseReceiptInput(JSON.stringify({ ...makeReceipt(), verifiedAt: 'not-a-date' }))
    expect(badTime).toMatchObject({ ok: false, code: 'INVALID_TIMESTAMP' })
  })

  it('rejects receipts containing private evidence metadata or secret keys', () => {
    const withFileName = parseReceiptInput(
      JSON.stringify({ ...makeReceipt(), fileName: 'secret-source-interview.mp4' }),
    )
    expect(withFileName).toMatchObject({ ok: false, code: 'PRIVATE_METADATA_FORBIDDEN' })

    const withWitness = parseReceiptInput(
      JSON.stringify({ ...makeReceipt(), witness: '0xdeadbeef' }),
    )
    expect(withWitness).toMatchObject({ ok: false, code: 'PRIVATE_METADATA_FORBIDDEN' })

    const withNullifier = parseReceiptInput(
      JSON.stringify({ ...makeReceipt(), nested: { nullifier: HEX_E } }),
    )
    expect(withNullifier).toMatchObject({ ok: false, code: 'PRIVATE_METADATA_FORBIDDEN' })
  })
})

describe('compareVerificationReceipts', () => {
  it('reports zero changes for identical receipts', () => {
    const a = makeReceipt()
    const b = makeReceipt()
    const cmp = compareVerificationReceipts(a, b)

    expect(cmp.sameArtifact).toBe(true)
    expect(cmp.trustChanged).toBe(false)
    expect(cmp.chainChanged).toBe(false)
    expect(cmp.artifactChanged).toBe(false)
    expect(cmp.changedCount).toBe(0)
    expect(cmp.timeDeltaMs).toBe(0)
    expect(cmp.timeDeltaLabel).toBe('0s (same timestamp)')
    expect(cmp.chronology).toBe('same')
  })

  it('highlights changed trust and chain observations with exact timestamps', () => {
    const a = makeReceipt({
      result: 'verified',
      verifiedAt: '2026-05-01T10:00:00.000Z',
      tier: 'source',
      ledgerSequence: 100500,
      transactionHash: HEX_D,
    })
    const b = makeReceipt({
      result: 'unverified',
      verifiedAt: '2026-05-01T12:15:30.000Z',
      tier: 'seal',
      ledgerSequence: 100750,
      transactionHash: HEX_E,
      signer: {
        keyId: 'verifier-key-2026-q2',
        algorithm: 'ECDSA_P256_SHA256',
      },
    })

    const cmp = compareVerificationReceipts(a, b)
    expect(cmp.sameArtifact).toBe(true)
    expect(cmp.trustChanged).toBe(true)
    expect(cmp.chainChanged).toBe(true)
    expect(cmp.leftTimestamp).toBe('2026-05-01T10:00:00.000Z')
    expect(cmp.rightTimestamp).toBe('2026-05-01T12:15:30.000Z')
    expect(cmp.timeDeltaLabel).toBe('+2h 15m 30s')
    expect(cmp.chronology).toBe('later')

    const resultObs = cmp.observations.find((o) => o.key === 'result')
    expect(resultObs?.changed).toBe(true)
    expect(resultObs?.severity).toBe('critical')
    expect(resultObs?.detail).toContain('2026-05-01T10:00:00.000Z')
    expect(resultObs?.detail).toContain('2026-05-01T12:15:30.000Z')

    const ledgerObs = cmp.observations.find((o) => o.key === 'ledgerSequence')
    expect(ledgerObs?.changed).toBe(true)
    expect(ledgerObs?.detail).toBe('Ledger delta: +250')
  })

  it('flags when receipts reference different artifacts', () => {
    const a = makeReceipt({ videoHash: HEX_B })
    const b = makeReceipt({ videoHash: HEX_F })
    const cmp = compareVerificationReceipts(a, b)
    expect(cmp.sameArtifact).toBe(false)
    expect(cmp.artifactChanged).toBe(true)
  })
})

describe('privacy-safe comparison share URLs', () => {
  it('round-trips two receipts without exposing private evidence metadata', () => {
    const left = makeReceipt({ verifiedAt: '2026-05-01T10:00:00.000Z' })
    const right = makeReceipt({
      result: 'unverified',
      verifiedAt: '2026-05-01T11:30:00.000Z',
      ledgerSequence: 100600,
    })

    const created = createReceiptComparisonShareUrl(left, right, {
      baseUrl: 'https://verify.harpocrates.example',
    })
    expect(created.ok).toBe(true)
    if (!created.ok) return

    expect(created.url.startsWith('https://verify.harpocrates.example#verify?compare=')).toBe(true)
    expect(created.url).not.toMatch(/fileName|witness|nullifier|secret|media|stego|signature/i)

    const parsed = parseReceiptComparisonShareUrl(created.url)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return

    expect(parsed.left).toEqual(left)
    expect(parsed.right).toEqual(right)
  })

  it('rejects tampered comparison URLs containing private metadata keys', () => {
    const tampered = {
      protocol: 'harpocrates-receipt-comparison',
      version: 1,
      left: { fileName: 'sensitive.mp4' },
      right: {},
    }
    const encoded = btoa(JSON.stringify(tampered))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replace(/=+$/, '')

    const parsed = parseReceiptComparisonShareUrl(
      `https://verify.harpocrates.example#verify?compare=${encoded}`,
    )
    expect(parsed).toMatchObject({ ok: false, code: 'PRIVATE_METADATA_FORBIDDEN' })
  })

  it('formats negative and multi-day time deltas accurately', () => {
    expect(formatTimeDelta(-3_661_000)).toBe('-1h 1m 1s')
    expect(formatTimeDelta(90_061_000)).toBe('+1d 1h 1m 1s')
  })
})
