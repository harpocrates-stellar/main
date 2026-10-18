import { describe, expect, it } from 'vitest'
import {
  createSignedVerificationReceipt,
  createVerificationReceiptQrPayload,
} from './verificationReceiptService'
import {
  decodeReceiptFromQr,
  verifyVerificationReceipt,
  type VerificationReceiptInput,
} from '../verificationReceipt'

const input: VerificationReceiptInput = {
  result: 'verified',
  verifiedAt: '2026-07-26T12:00:00.000Z',
  proofId: 'a'.repeat(64),
  videoHash: 'b'.repeat(64),
  metadataHash: 'c'.repeat(64),
  tier: 'silent',
  networkPassphrase: 'Test SDF Network ; September 2015',
  contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M',
  ledgerSequence: null,
  transactionHash: 'd'.repeat(64),
  circuitVersion: 'silent-witness-v1',
  verifierVersion: 'registry-v1',
}

describe('verification receipt service', () => {
  it('creates a signed QR payload that decodes and verifies', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )

    const receipt = await createSignedVerificationReceipt(input, {
      keyId: 'test-verifier',
      signingKey: pair.privateKey,
    })

    const payload = createVerificationReceiptQrPayload(receipt)

    expect(payload).toBeTruthy()
    expect(payload.length).toBeLessThanOrEqual(4096)

    const decoded = decodeReceiptFromQr(payload)

    expect(decoded).toEqual(receipt)

    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)

    const verification = await verifyVerificationReceipt(decoded, {
      keys: {
        'test-verifier': publicJwk,
      },
    })

    expect(verification).toEqual({
      valid: true,
      receipt: decoded,
    })
  }) 
}) 