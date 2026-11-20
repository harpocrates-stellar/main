import { describe, it, expect } from 'vitest'
import { classifyVerification, computeResult, networkName } from '../src/normalize.js'
import { createProofManifest } from '../src/manifest.js'

describe('computeResult', () => {
  it('returns not_found when tx is missing', () => {
    expect(computeResult(null, 'missing')).toBe('not_found')
  })

  it('returns failed when tx failed', () => {
    expect(computeResult(null, 'failed')).toBe('failed')
  })

  it('returns pending when tx is pending', () => {
    expect(computeResult(null, 'pending')).toBe('pending')
  })

  it('returns not_found when tx confirmed but no chain record', () => {
    expect(computeResult(null, 'confirmed')).toBe('not_found')
  })

  it('returns valid for status 1', () => {
    expect(computeResult({ status: 1 }, 'confirmed')).toBe('valid')
  })

  it('returns revoked for status 2', () => {
    expect(computeResult({ status: 2 }, 'confirmed')).toBe('revoked')
  })

  it('returns expired for status 3', () => {
    expect(computeResult({ status: 3 }, 'confirmed')).toBe('expired')
  })

  it('fails closed for unknown status', () => {
    expect(computeResult({ status: 99 }, 'confirmed')).toBe('error')
  })
})

describe('classifyVerification', () => {
  const manifest = createProofManifest({
    proofId: 'a'.repeat(64), tier: 'silent', network: 'testnet', contractId: 'contract',
    transactionRef: 'b'.repeat(64), videoHash: 'c'.repeat(64),
    metadataHash: 'd'.repeat(64), sourceHash: 'e'.repeat(64),
    timestamp: '2026-07-24T12:00:00.000Z',
  })
  const transaction = { status: 'confirmed' as const, txHash: manifest.transactionRef, contractMatch: true }
  const record = {
    videoHash: manifest.videoHash, metadataHash: manifest.metadataHash,
    tier: 1, status: 1, createdAt: '1', source: null, issuer: null,
  }

  it('accepts matching confirmed evidence', () => {
    expect(classifyVerification(manifest, transaction, record)).toBe('valid')
  })

  it('rejects contract or registry mismatches', () => {
    expect(classifyVerification(manifest, { ...transaction, contractMatch: false }, record)).toBe('contract_mismatch')
    expect(classifyVerification(manifest, transaction, { ...record, metadataHash: 'f'.repeat(64) })).toBe('error')
    expect(classifyVerification(manifest, transaction, { ...record, tier: 2 })).toBe('error')
  })

  it('reports expiry from the registry deadline', () => {
    expect(classifyVerification(manifest, transaction, { ...record, expiresAt: '100' }, 101)).toBe('expired')
    expect(classifyVerification(manifest, transaction, { ...record, expiresAt: '102' }, 101)).toBe('valid')
  })
})

describe('networkName', () => {
  it('returns human-readable name for known passphrases', () => {
    expect(networkName('Test SDF Network ; September 2015')).toBe('Testnet')
    expect(networkName('Public Global Stellar Network ; September 2015')).toBe('Mainnet')
  })

  it('returns raw passphrase for unknown ones', () => {
    expect(networkName('Custom Network')).toBe('Custom Network')
  })
})
