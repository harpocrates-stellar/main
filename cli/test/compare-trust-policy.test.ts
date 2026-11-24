import { beforeAll, describe, expect, it } from 'vitest'
import { createProofManifest } from '../src/manifest.js'
import { signVerificationReceipt, type VerificationReceiptInput } from '../src/signed-receipt.js'
import {
  compareTrustPolicies,
  formatTrustPolicyComparison,
  parseTrustPolicy,
  runCompareTrustPolicy,
  PolicyParseError,
  type TrustPolicy,
  type TrustPolicyComparisonReport,
} from '../src/compare-trust-policy.js'
import type { OfflineBundle } from '../src/verify-bundle.js'

// ── Shared synthetic fixtures ─────────────────────────────────────────────

const NETWORK = 'Test SDF Network ; September 2015'
const KEY_ID_A = 'verifier-key-a'
const KEY_ID_B = 'verifier-key-b'

const VALID_MANIFEST = createProofManifest({
  proofId: 'a'.repeat(64),
  tier: 'silent',
  network: NETWORK,
  contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  transactionRef: 'e'.repeat(64),
  videoHash: 'c'.repeat(64),
  metadataHash: 'd'.repeat(64),
  sourceHash: 'b'.repeat(64),
  timestamp: '2026-11-19T00:00:00.000Z',
})

const RECEIPT_INPUT: VerificationReceiptInput = {
  result: 'verified',
  verifiedAt: '2026-11-19T12:00:00.000Z',
  proofId: 'a'.repeat(64),
  videoHash: 'c'.repeat(64),
  metadataHash: 'd'.repeat(64),
  tier: 'silent',
  networkPassphrase: NETWORK,
  contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M',
  ledgerSequence: 12345,
  transactionHash: 'f'.repeat(64),
  circuitVersion: 'silent-witness-v1',
  verifierVersion: 'registry-v1',
}

let keyPairA: CryptoKeyPair
let keyPairB: CryptoKeyPair
let pubJwkA: JsonWebKey
let pubJwkB: JsonWebKey

beforeAll(async () => {
  const algo = { name: 'ECDSA', namedCurve: 'P-256' } as const
  ;[keyPairA, keyPairB] = await Promise.all([
    crypto.subtle.generateKey(algo, true, ['sign', 'verify']),
    crypto.subtle.generateKey(algo, true, ['sign', 'verify']),
  ])
  ;[pubJwkA, pubJwkB] = await Promise.all([
    crypto.subtle.exportKey('jwk', keyPairA.publicKey),
    crypto.subtle.exportKey('jwk', keyPairB.publicKey),
  ])
})

async function makeBundle(overrides: Partial<OfflineBundle> = {}): Promise<OfflineBundle> {
  const receipt = await signVerificationReceipt(RECEIPT_INPUT, KEY_ID_A, keyPairA.privateKey)
  return {
    version: '1.0.0',
    trustSnapshot: { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK },
    manifests: [VALID_MANIFEST],
    receipts: [receipt],
    ...overrides,
  }
}

// ── compareTrustPolicies ──────────────────────────────────────────────────

describe('compareTrustPolicies', () => {
  it('reports no change when both policies trust the same key and both pass', async () => {
    const bundle = await makeBundle()
    const policy: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }

    const report = await compareTrustPolicies(policy, policy, bundle)

    expect(report.changed).toBe(false)
    expect(report.summary.receiptsChanged).toBe(0)
    expect(report.summary.receiptsTotal).toBe(1)
    expect(report.receipts[0].changed).toBe(false)
    // unchanged decision carries the passing outcome
    if (!report.receipts[0].changed) {
      expect(report.receipts[0].decision.valid).toBe(true)
    }
  })

  it('detects a change when policy B trusts a different key and the receipt becomes invalid', async () => {
    const bundle = await makeBundle()
    const policyA: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }
    // policy B uses key B — the receipt was signed with key A, so it fails under policy B
    const policyB: TrustPolicy = { keys: { [KEY_ID_B]: pubJwkB }, networkPassphrase: NETWORK }

    const report = await compareTrustPolicies(policyA, policyB, bundle)

    expect(report.changed).toBe(true)
    expect(report.summary.receiptsChanged).toBe(1)
    const diff = report.receipts[0]
    expect(diff.changed).toBe(true)
    if (diff.changed) {
      expect(diff.before.valid).toBe(true)
      expect(diff.after.valid).toBe(false)
    }
  })

  it('detects a change when policy A uses a wrong key and policy B fixes it', async () => {
    const bundle = await makeBundle()
    const policyA: TrustPolicy = { keys: { [KEY_ID_B]: pubJwkB }, networkPassphrase: NETWORK }
    const policyB: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }

    const report = await compareTrustPolicies(policyA, policyB, bundle)

    expect(report.changed).toBe(true)
    const diff = report.receipts[0]
    if (diff.changed) {
      expect(diff.before.valid).toBe(false)
      expect(diff.after.valid).toBe(true)
    }
  })

  it('reports no change when both policies reject (consistent failure)', async () => {
    const bundle = await makeBundle()
    // neither policy carries any key → both reject
    const policyEmpty: TrustPolicy = { keys: {}, networkPassphrase: NETWORK }

    const report = await compareTrustPolicies(policyEmpty, policyEmpty, bundle)

    expect(report.changed).toBe(false)
    expect(report.receipts[0].changed).toBe(false)
    if (!report.receipts[0].changed) {
      expect(report.receipts[0].decision.valid).toBe(false)
    }
  })

  it('detects a change when policy B uses a different network passphrase', async () => {
    const bundle = await makeBundle()
    const policyA: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }
    const policyB: TrustPolicy = {
      keys: { [KEY_ID_A]: pubJwkA },
      networkPassphrase: 'Public Global Stellar Network ; September 2015',
    }

    const report = await compareTrustPolicies(policyA, policyB, bundle)

    expect(report.changed).toBe(true)
    const diff = report.receipts[0]
    if (diff.changed) {
      expect(diff.before.valid).toBe(true)
      expect(diff.after.valid).toBe(false)
    }
  })

  it('handles a bundle with no receipts — reports no change and empty arrays', async () => {
    const bundle = await makeBundle({ receipts: [] })
    const policy: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }

    const report = await compareTrustPolicies(policy, policy, bundle)

    expect(report.changed).toBe(false)
    expect(report.receipts).toHaveLength(0)
    expect(report.summary.receiptsTotal).toBe(0)
  })

  it('evaluates each receipt independently across multiple receipts', async () => {
    // receipt[0] signed by key A, receipt[1] signed by key B
    const receiptA = await signVerificationReceipt(RECEIPT_INPUT, KEY_ID_A, keyPairA.privateKey)
    const receiptB = await signVerificationReceipt(RECEIPT_INPUT, KEY_ID_B, keyPairB.privateKey)
    const bundle: OfflineBundle = {
      version: '1.0.0',
      trustSnapshot: { keys: { [KEY_ID_A]: pubJwkA, [KEY_ID_B]: pubJwkB }, networkPassphrase: NETWORK },
      manifests: [],
      receipts: [receiptA, receiptB],
    }
    // policy A trusts both keys; policy B trusts only key A
    const policyBoth: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA, [KEY_ID_B]: pubJwkB }, networkPassphrase: NETWORK }
    const policyAOnly: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }

    const report = await compareTrustPolicies(policyBoth, policyAOnly, bundle)

    expect(report.changed).toBe(true)
    expect(report.summary.receiptsTotal).toBe(2)
    // receipt[0] (signed by A) → unchanged, both pass
    expect(report.receipts[0].changed).toBe(false)
    // receipt[1] (signed by B) → changed: passes under policyBoth, fails under policyAOnly
    expect(report.receipts[1].changed).toBe(true)
    if (report.receipts[1].changed) {
      expect(report.receipts[1].before.valid).toBe(true)
      expect(report.receipts[1].after.valid).toBe(false)
    }
  })

  it('manifests are always reported as unchanged (policy does not affect parsing)', async () => {
    const bundle = await makeBundle()
    const policyA: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }
    const policyB: TrustPolicy = { keys: { [KEY_ID_B]: pubJwkB }, networkPassphrase: NETWORK }

    const report = await compareTrustPolicies(policyA, policyB, bundle)

    for (const m of report.manifests) {
      expect(m.changed).toBe(false)
    }
  })
})

// ── parseTrustPolicy ──────────────────────────────────────────────────────

describe('parseTrustPolicy', () => {
  it('round-trips a valid policy object', () => {
    const policy = { keys: { [KEY_ID_A]: { kty: 'EC' } }, networkPassphrase: NETWORK }
    const parsed = parseTrustPolicy(JSON.stringify(policy))
    expect(Object.keys(parsed.keys)).toEqual([KEY_ID_A])
    expect(parsed.networkPassphrase).toBe(NETWORK)
  })

  it.each([
    ['not json', 'not json at all'],
    ['not an object', JSON.stringify([1, 2])],
    ['missing keys', JSON.stringify({ networkPassphrase: NETWORK })],
    ['keys not an object', JSON.stringify({ keys: 'bad' })],
  ])('rejects %s with PolicyParseError', (_label, input) => {
    expect(() => parseTrustPolicy(input)).toThrow(PolicyParseError)
  })
})

// ── formatTrustPolicyComparison ───────────────────────────────────────────

describe('formatTrustPolicyComparison', () => {
  it('shows "No trust decisions changed" when nothing differs', async () => {
    const bundle = await makeBundle()
    const policy: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }
    const report = await compareTrustPolicies(policy, policy, bundle)
    const text = formatTrustPolicyComparison(report)
    expect(text).toContain('No trust decisions changed')
    expect(text).toContain('unchanged')
  })

  it('shows CHANGED and both decisions when a receipt differs', async () => {
    const bundle = await makeBundle()
    const policyA: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }
    const policyB: TrustPolicy = { keys: { [KEY_ID_B]: pubJwkB }, networkPassphrase: NETWORK }
    const report = await compareTrustPolicies(policyA, policyB, bundle)
    const text = formatTrustPolicyComparison(report)
    expect(text).toContain('Trust decisions changed')
    expect(text).toContain('CHANGED')
    expect(text).toContain('policy A:')
    expect(text).toContain('policy B:')
  })
})

// ── runCompareTrustPolicy ─────────────────────────────────────────────────

describe('runCompareTrustPolicy', () => {
  async function run(
    flags: Record<string, string>,
    files: Record<string, string>,
  ): Promise<{ code: number; stdout: string; stderr: string }> {
    let stdout = ''
    let stderr = ''
    const code = await runCompareTrustPolicy(flags, {
      readText: async (p) => {
        if (!(p in files)) throw new Error(`file not found: ${p}`)
        return files[p]
      },
      writeStdout: (t) => { stdout += t },
      writeStderr: (t) => { stderr += t },
    })
    return { code, stdout, stderr }
  }

  it('exits 0 and prints text when both policies agree', async () => {
    const bundle = await makeBundle()
    const policy: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }
    const policyJson = JSON.stringify(policy)
    const bundleJson = JSON.stringify(bundle)

    const { code, stdout } = await run(
      { 'policy-a': 'a.json', 'policy-b': 'b.json', bundle: 'bundle.json' },
      { 'a.json': policyJson, 'b.json': policyJson, 'bundle.json': bundleJson },
    )

    expect(code).toBe(0)
    expect(stdout).toContain('No trust decisions changed')
  })

  it('exits 1 and shows diff when policies differ', async () => {
    const bundle = await makeBundle()
    const policyA: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }
    const policyB: TrustPolicy = { keys: { [KEY_ID_B]: pubJwkB }, networkPassphrase: NETWORK }

    const { code, stdout } = await run(
      { 'policy-a': 'a.json', 'policy-b': 'b.json', bundle: 'bundle.json' },
      {
        'a.json': JSON.stringify(policyA),
        'b.json': JSON.stringify(policyB),
        'bundle.json': JSON.stringify(bundle),
      },
    )

    expect(code).toBe(1)
    expect(stdout).toContain('CHANGED')
  })

  it('exits 0 with JSON output when policies agree', async () => {
    const bundle = await makeBundle()
    const policy: TrustPolicy = { keys: { [KEY_ID_A]: pubJwkA }, networkPassphrase: NETWORK }
    const policyJson = JSON.stringify(policy)
    const bundleJson = JSON.stringify(bundle)

    const { code, stdout } = await run(
      { 'policy-a': 'a.json', 'policy-b': 'b.json', bundle: 'bundle.json', output: 'json' },
      { 'a.json': policyJson, 'b.json': policyJson, 'bundle.json': bundleJson },
    )

    expect(code).toBe(0)
    const parsed = JSON.parse(stdout) as TrustPolicyComparisonReport
    expect(parsed.changed).toBe(false)
    expect(parsed.summary.receiptsTotal).toBe(1)
  })

  it.each([
    [{ 'policy-b': 'b.json', bundle: 'bundle.json' }, '--policy-a is required'],
    [{ 'policy-a': 'a.json', bundle: 'bundle.json' }, '--policy-b is required'],
    [{ 'policy-a': 'a.json', 'policy-b': 'b.json' }, '--bundle is required'],
    [{ 'policy-a': 'a.json', 'policy-b': 'b.json', bundle: 'bundle.json', output: 'xml' }, 'invalid --output'],
  ] as const)('exits 2 for missing/invalid flag: %s', async (flags, expectedStderr) => {
    const { code, stderr } = await run(flags as Record<string, string>, {})
    expect(code).toBe(2)
    expect(stderr).toContain(expectedStderr)
  })

  it('exits 8 when policy-a file is not valid JSON', async () => {
    const bundle = await makeBundle()
    const { code, stderr } = await run(
      { 'policy-a': 'a.json', 'policy-b': 'b.json', bundle: 'bundle.json' },
      { 'a.json': 'not json', 'b.json': '{"keys":{}}', 'bundle.json': JSON.stringify(bundle) },
    )
    expect(code).toBe(8)
    expect(stderr).toContain('policy-a')
  })

  it('exits 8 when the bundle file is malformed', async () => {
    const policy = JSON.stringify({ keys: { [KEY_ID_A]: pubJwkA } })
    const { code, stderr } = await run(
      { 'policy-a': 'a.json', 'policy-b': 'b.json', bundle: 'bundle.json' },
      { 'a.json': policy, 'b.json': policy, 'bundle.json': 'not json' },
    )
    expect(code).toBe(8)
    expect(stderr).toContain('bundle')
  })
})
