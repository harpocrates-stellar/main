import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
import {
  decodeReceiptFromQr,
  encodeReceiptForQr,
  signVerificationReceipt,
  serializeVerificationReceipt,
  verifyVerificationReceipt,
  type SignedVerificationReceipt,
  type VerificationReceiptInput,
} from '../src/signed-receipt.js'

type InteropFixture = {
  fixtureVersion: number
  keys: Record<string, JsonWebKey>
  keyValidity: Record<string, { notBefore?: string; notAfter?: string }>
  verificationNow: string
  validVectors: Array<{
    name: string
    unsignedInput: VerificationReceiptInput
    canonicalPayload: string
    signedReceipt: SignedVerificationReceipt
    serializedReceipt: string
    qrPayload: string
  }>
  mutatedStatements: Array<{
    name: string
    receipt: SignedVerificationReceipt
    expectedReasonPattern: string
  }>
}

const interopFixture: InteropFixture = JSON.parse(
  readFileSync(resolve(process.cwd(), '../devx/fixtures/receipt-interop/vectors.json'), 'utf8'),
)

const input: VerificationReceiptInput = {
  result: 'verified',
  verifiedAt: '2026-07-26T12:00:00.000Z',
  proofId: 'a'.repeat(64),
  videoHash: 'b'.repeat(64),
  metadataHash: 'c'.repeat(64),
  tier: 'silent',
  networkPassphrase: 'Test SDF Network ; September 2015',
  contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M',
  ledgerSequence: 12345,
  transactionHash: 'd'.repeat(64),
  circuitVersion: 'silent-witness-v1',
  verifierVersion: 'registry-v1',
}

let privateKey: CryptoKey
let publicKey: JsonWebKey

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  privateKey = pair.privateKey
  publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey)
})

describe('signed verification receipts', () => {
  it('creates stable file and QR encodings that verify offline', async () => {
    const receipt = await signVerificationReceipt(input, 'verifier-2026-07', privateKey)
    expect(serializeVerificationReceipt(receipt)).toBe(serializeVerificationReceipt(receipt))
    expect(decodeReceiptFromQr(encodeReceiptForQr(receipt))).toEqual(receipt)
    await expect(verifyVerificationReceipt(receipt, {
      keys: { 'verifier-2026-07': publicKey },
      expectedNetworkPassphrase: input.networkPassphrase,
      expectedProofId: input.proofId,
    })).resolves.toMatchObject({ valid: true })
  })

  it('rejects tampered, substituted-proof, wrong-network, and unknown-key receipts', async () => {
    const receipt = await signVerificationReceipt(input, 'verifier-2026-07', privateKey)
    await expect(verifyVerificationReceipt({ ...receipt, result: 'unverified' }, { keys: { 'verifier-2026-07': publicKey } })).resolves.toMatchObject({ valid: false })
    await expect(verifyVerificationReceipt(receipt, { keys: { 'verifier-2026-07': publicKey }, expectedProofId: 'e'.repeat(64) })).resolves.toMatchObject({ valid: false, reason: expect.stringMatching(/proof/) })
    await expect(verifyVerificationReceipt(receipt, { keys: { 'verifier-2026-07': publicKey }, expectedNetworkPassphrase: 'Public Global Stellar Network ; September 2015' })).resolves.toMatchObject({ valid: false, reason: expect.stringMatching(/network/) })
    await expect(verifyVerificationReceipt(receipt, { keys: {} })).resolves.toMatchObject({ valid: false, reason: expect.stringMatching(/unknown/) })
  })

  it('rejects stale signing keys', async () => {
    const receipt = await signVerificationReceipt(input, 'verifier-2026-07', privateKey)
    await expect(verifyVerificationReceipt(receipt, {
      keys: { 'verifier-2026-07': publicKey },
      keyValidity: { 'verifier-2026-07': { notAfter: '2026-07-25T00:00:00.000Z' } },
      now: new Date('2026-07-26T12:00:00.000Z'),
    })).resolves.toMatchObject({ valid: false, reason: expect.stringMatching(/stale/) })
  })
})

describe('backend and CLI receipt interoperability fixtures', () => {
  for (const vector of interopFixture.validVectors) {
    it(`parses, encodes, and verifies shared vector: ${vector.name}`, async () => {
      expect(serializeVerificationReceipt(vector.signedReceipt)).toBe(vector.serializedReceipt)
      expect(encodeReceiptForQr(vector.signedReceipt)).toBe(vector.qrPayload)
      expect(decodeReceiptFromQr(vector.qrPayload)).toEqual(vector.signedReceipt)

      await expect(verifyVerificationReceipt(vector.signedReceipt, {
        keys: interopFixture.keys,
        expectedNetworkPassphrase: vector.unsignedInput.networkPassphrase,
        expectedProofId: vector.unsignedInput.proofId,
        keyValidity: interopFixture.keyValidity,
        now: new Date(interopFixture.verificationNow),
      })).resolves.toEqual({ valid: true, receipt: vector.signedReceipt })
    })
  }

  for (const mutated of interopFixture.mutatedStatements) {
    it(`explicitly rejects mutated statement: ${mutated.name}`, async () => {
      const result = await verifyVerificationReceipt(mutated.receipt, {
        keys: interopFixture.keys,
        keyValidity: interopFixture.keyValidity,
        now: new Date(interopFixture.verificationNow),
      })
      expect(result.valid).toBe(false)
      if (!result.valid) {
        expect(result.reason).toMatch(new RegExp(mutated.expectedReasonPattern, 'i'))
      }
    })
  }
})
