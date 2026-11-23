import { beforeAll, describe, expect, it } from 'vitest'
import { createProofManifest } from '../src/manifest.js'
import { signVerificationReceipt, type VerificationReceiptInput } from '../src/signed-receipt.js'
import {
  BundleFormatError,
  parseOfflineBundle,
  verifyOfflineBundle,
  formatOfflineBundleReport,
  type OfflineBundle,
} from '../src/verify-bundle.js'

const NETWORK = 'Test SDF Network ; September 2015'
const KEY_ID = 'verifier-2026-11'

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

let publicKey: JsonWebKey
let privateKey: CryptoKey

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  privateKey = pair.privateKey
  publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey)
})

async function makeBundle(overrides: Partial<OfflineBundle> = {}): Promise<OfflineBundle> {
  const receipt = await signVerificationReceipt(RECEIPT_INPUT, KEY_ID, privateKey)
  return {
    version: '1.0.0',
    trustSnapshot: {
      keys: { [KEY_ID]: publicKey },
      networkPassphrase: NETWORK,
      capturedAt: '2026-11-19T00:00:00.000Z',
    },
    manifests: [VALID_MANIFEST],
    receipts: [receipt],
    ...overrides,
  }
}

describe('verifyOfflineBundle', () => {
  it('verifies manifests and receipts offline and reports online checks as unavailable', async () => {
    const report = await verifyOfflineBundle(await makeBundle())
    expect(report.offline).toBe(true)
    expect(report.summary).toMatchObject({
      manifestsValid: 1,
      manifestsTotal: 1,
      receiptsValid: 1,
      receiptsTotal: 1,
      allValid: true,
    })
    expect(report.trustSnapshot.keyCount).toBe(1)
    // Every online-only check is explicitly unavailable, never pass/fail.
    expect(report.onlineChecks.length).toBeGreaterThan(0)
    for (const check of report.onlineChecks) {
      expect(check.status).toBe('unavailable')
    }
    expect(report.onlineChecks.map((c) => c.name)).toContain('on-chain-proof-status')
  })

  it('flags an invalid manifest without failing the whole run early', async () => {
    const bundle = await makeBundle({ manifests: [{ protocol: 'not-harpocrates' }] })
    const report = await verifyOfflineBundle(bundle)
    expect(report.summary.manifestsValid).toBe(0)
    expect(report.manifests[0]).toMatchObject({ index: 0, valid: false })
    expect(report.summary.allValid).toBe(false)
  })

  it('rejects a receipt signed by a key missing from the trust snapshot', async () => {
    const other = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const otherPublic = await crypto.subtle.exportKey('jwk', other.publicKey)
    const bundle = await makeBundle({
      trustSnapshot: { keys: { 'different-key': otherPublic }, networkPassphrase: NETWORK },
    })
    const report = await verifyOfflineBundle(bundle)
    expect(report.summary.receiptsValid).toBe(0)
    expect(report.receipts[0]).toMatchObject({ index: 0, valid: false })
    expect(report.summary.allValid).toBe(false)
  })

  it('rejects a receipt whose network differs from the trust snapshot', async () => {
    const bundle = await makeBundle()
    bundle.trustSnapshot.networkPassphrase = 'Public Global Stellar Network ; September 2015'
    const report = await verifyOfflineBundle(bundle)
    expect(report.summary.receiptsValid).toBe(0)
    expect(report.receipts[0]).toMatchObject({ valid: false })
  })
})

describe('parseOfflineBundle', () => {
  it('round-trips a serialized bundle', async () => {
    const bundle = await makeBundle()
    const parsed = parseOfflineBundle(JSON.stringify(bundle))
    expect(parsed.manifests).toHaveLength(1)
    expect(parsed.receipts).toHaveLength(1)
    expect(Object.keys(parsed.trustSnapshot.keys)).toEqual([KEY_ID])
  })

  it('defaults missing manifests and receipts to empty arrays', () => {
    const parsed = parseOfflineBundle(JSON.stringify({ trustSnapshot: { keys: { k: {} } } }))
    expect(parsed.manifests).toEqual([])
    expect(parsed.receipts).toEqual([])
  })

  it.each([
    ['not json', 'not json at all'],
    ['missing trust snapshot', JSON.stringify({ manifests: [], receipts: [] })],
    ['snapshot without keys', JSON.stringify({ trustSnapshot: {} })],
    ['manifests not an array', JSON.stringify({ trustSnapshot: { keys: {} }, manifests: {} })],
  ])('rejects %s', (_label, input) => {
    expect(() => parseOfflineBundle(input)).toThrow(BundleFormatError)
  })
})

describe('formatOfflineBundleReport', () => {
  it('summarizes a passing bundle and lists unavailable online checks', async () => {
    const report = await verifyOfflineBundle(await makeBundle())
    const text = formatOfflineBundleReport(report)
    expect(text).toContain('Offline bundle verified')
    expect(text).toContain('on-chain-proof-status: unavailable')
  })
})
