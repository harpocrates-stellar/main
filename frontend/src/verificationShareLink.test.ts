import { describe, it, expect } from 'vitest'
import {
  SHARE_LINK_PROTOCOL,
  SHARE_LINK_VERSION,
  MAX_SHARE_PAYLOAD_BYTES,
  createVerificationSharePayload,
  createVerificationShareLink,
  encodeVerificationSharePayload,
  decodeVerificationSharePayload,
  parseVerificationShareLink,
  serializeVerificationSharePayload,
  type VerificationShareLinkInput,
} from './verificationShareLink'

const VALID_INPUT: VerificationShareLinkInput = {
  videoHash: 'a'.repeat(64),
  proofId: 'b'.repeat(64),
  metadataHash: 'c'.repeat(64),
  network: 'Test SDF Network ; September 2015',
  contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M',
  transactionRef: 'd'.repeat(64),
  tier: 'silent',
}

describe('createVerificationSharePayload', () => {
  it('builds a v1 public-only payload', () => {
    const result = createVerificationSharePayload(VALID_INPUT)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.payload.protocol).toBe(SHARE_LINK_PROTOCOL)
    expect(result.payload.version).toBe(SHARE_LINK_VERSION)
    expect(result.payload.videoHash).toBe(VALID_INPUT.videoHash)
    expect(result.payload.proofId).toBe(VALID_INPUT.proofId)
    expect(result.payload.metadataHash).toBe(VALID_INPUT.metadataHash)
    expect(result.payload.network).toBe(VALID_INPUT.network)
    expect(result.payload.contractId).toBe(VALID_INPUT.contractId)
    expect(result.payload.transactionRef).toBe(VALID_INPUT.transactionRef)
    expect(result.payload.tier).toBe('silent')
  })

  it('normalizes digests to lowercase hex', () => {
    const result = createVerificationSharePayload({
      ...VALID_INPUT,
      videoHash: 'A'.repeat(64),
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.payload.videoHash).toBe('a'.repeat(64))
  })

  it('omits optional fields when absent', () => {
    const result = createVerificationSharePayload({
      videoHash: VALID_INPUT.videoHash,
      proofId: VALID_INPUT.proofId,
      metadataHash: VALID_INPUT.metadataHash,
      network: VALID_INPUT.network,
      contractId: VALID_INPUT.contractId,
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.payload.transactionRef).toBeUndefined()
    expect(result.payload.tier).toBeUndefined()
  })

  it('rejects non-hex digests', () => {
    const result = createVerificationSharePayload({
      ...VALID_INPUT,
      videoHash: 'not-a-hash',
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('INVALID_DIGEST')
  })

  it('rejects missing network/contract', () => {
    const result = createVerificationSharePayload({
      ...VALID_INPUT,
      network: '   ',
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('MISSING_FIELD')
  })

  it('rejects invalid tier', () => {
    const result = createVerificationSharePayload({
      ...VALID_INPUT,
      tier: 'admin' as never,
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('INVALID_FIELD')
  })

  it('never includes secret-looking keys', () => {
    const result = createVerificationSharePayload(VALID_INPUT)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const keys = Object.keys(result.payload).join(',')
    expect(keys).not.toMatch(/seed|secret|witness|nullifier|credential|private/i)
  })
})

describe('createVerificationShareLink', () => {
  it('returns a #verify?p= URL under the given base', () => {
    const result = createVerificationShareLink(VALID_INPUT, {
      baseUrl: 'https://app.example/harpocrates/',
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.url.startsWith('https://app.example/harpocrates#verify?p=')).toBe(true)
    expect(result.encoded.length).toBeGreaterThan(20)
  })

  it('round-trips through parseVerificationShareLink', () => {
    const created = createVerificationShareLink(VALID_INPUT, {
      baseUrl: 'https://verify.harpocrates.example',
    })
    expect(created.ok).toBe(true)
    if (!created.ok) return
    const parsed = parseVerificationShareLink(created.url)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(parsed.payload).toEqual(created.payload)
  })

  it('rejects malformed base URL', () => {
    const result = createVerificationShareLink(VALID_INPUT, { baseUrl: 'not a url' })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('MALFORMED_URL')
  })
})

describe('encode/decode + parse edge cases', () => {
  it('serializes deterministically', () => {
    const created = createVerificationSharePayload(VALID_INPUT)
    expect(created.ok).toBe(true)
    if (!created.ok) return
    const a = serializeVerificationSharePayload(created.payload)
    const b = serializeVerificationSharePayload(created.payload)
    expect(a).toBe(b)
    const keys = Object.keys(JSON.parse(a))
    expect(keys).toEqual([...keys].sort())
  })

  it('decode rejects secret-looking keys', () => {
    const evil = {
      protocol: SHARE_LINK_PROTOCOL,
      version: SHARE_LINK_VERSION,
      videoHash: 'a'.repeat(64),
      proofId: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
      network: 'n',
      contractId: 'c',
      nullifierSeed: 'leak',
    }
    const encoded = encodeVerificationSharePayload(evil as never)
    const decoded = decodeVerificationSharePayload(encoded)
    expect(decoded.ok).toBe(false)
    if (decoded.ok) return
    expect(decoded.code).toBe('INVALID_FIELD')
  })

  it('decode rejects unsupported protocol/version', () => {
    const encoded = btoa(
      JSON.stringify({
        protocol: 'other',
        version: 1,
        videoHash: 'a'.repeat(64),
        proofId: 'b'.repeat(64),
        metadataHash: 'c'.repeat(64),
        network: 'n',
        contractId: 'c',
      }),
    )
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replace(/=+$/, '')
    const decoded = decodeVerificationSharePayload(encoded)
    expect(decoded.ok).toBe(false)
    if (decoded.ok) return
    expect(decoded.code).toBe('UNSUPPORTED_PROTOCOL')
  })

  it('parse rejects missing payload', () => {
    const parsed = parseVerificationShareLink('https://app.example/#verify')
    expect(parsed.ok).toBe(false)
    if (parsed.ok) return
    expect(parsed.code).toBe('MISSING_PAYLOAD')
  })

  it('parse rejects oversized URL', () => {
    const huge = `https://app.example/#verify?p=${'a'.repeat(MAX_SHARE_PAYLOAD_BYTES + 500)}`
    const parsed = parseVerificationShareLink(huge)
    expect(parsed.ok).toBe(false)
    if (parsed.ok) return
    expect(['OVERSIZED_URL', 'OVERSIZED_PAYLOAD']).toContain(parsed.code)
  })

  it('parse accepts bare hash fragments', () => {
    const created = createVerificationShareLink(VALID_INPUT, {
      baseUrl: 'https://app.example',
    })
    expect(created.ok).toBe(true)
    if (!created.ok) return
    const hash = created.url.slice(created.url.indexOf('#'))
    const parsed = parseVerificationShareLink(hash)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(parsed.payload.proofId).toBe(VALID_INPUT.proofId)
  })

  it('messages stay privacy-safe (no media / secrets)', () => {
    const result = createVerificationSharePayload({
      ...VALID_INPUT,
      videoHash: 'bad',
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.message).not.toMatch(/seed|witness|nullifier|private key|mp4/i)
  })
})
