import {
  encodeReceiptForQr,
  signVerificationReceipt,
  type SignedVerificationReceipt,
  type VerificationReceiptInput,
} from '../verificationReceipt'

export type ReceiptSigner = {
  keyId: string
  signingKey: CryptoKey
}

export async function createSignedVerificationReceipt(
  input: VerificationReceiptInput,
  signer: ReceiptSigner,
): Promise<SignedVerificationReceipt> {
  return signVerificationReceipt(input, signer.keyId, signer.signingKey)
}

export function createVerificationReceiptQrPayload(
  receipt: SignedVerificationReceipt,
): string {
  return encodeReceiptForQr(receipt)
}