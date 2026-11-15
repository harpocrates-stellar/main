import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { StrKey } from '@stellar/stellar-sdk'
import { createProofManifest, type ProofManifest } from '../src/manifest.js'
import { DEFAULT_NETWORK_PASSPHRASE } from '../src/network.js'
import { createReceipt, type VerificationReceipt } from '../src/receipt.js'
import {
  encodeReceiptForQr,
  signVerificationReceipt,
  type SignedVerificationReceipt,
} from '../src/signed-receipt.js'
import {
  BUNDLE_REPORT_PROTOCOL,
  computeManifestDigest,
  createOfflineVerificationBundle,
  serializeVerificationBundle,
  verifyOfflineBundle,
  type BundleVerificationReport,
  type OfflineVerificationBundle,
} from '../src/verify-bundle.js'
import { main } from '../src/cli.js'

const CONTRACT_ID = StrKey.encodeContract(Uint8Array.from({ length: 32 }, (_, i) => i + 1))
const OTHER_CONTRACT_ID = StrKey.encodeContract(Uint8Array.from({ length: 32 }, (_, i) => i + 2))
const PARENT_PROOF_ID = '11'.repeat(32)

class ExitSignal extends Error {
  readonly code: number
  constructor(code: number) {
    super(`exit(${code})`)
    this.code = code
  }
}

async function generateTestSigningKeys(): Promise<{
  privateKey: CryptoKey
  publicJwk: JsonWebKey
  privateJwk: JsonWebKey
}> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  return { privateKey: pair.privateKey, publicJwk, privateJwk }
}

function makeManifest(overrides: Partial<ProofManifest> = {}): ProofManifest {
  const base = createProofManifest({
    proofId: 'aa'.repeat(32),
    tier: 'source',
    network: DEFAULT_NETWORK_PASSPHRASE,
    contractId: CONTRACT_ID,
    transactionRef: 'bb'.repeat(32),
    videoHash: 'cc'.repeat(32),
    metadataHash: 'dd'.repeat(32),
    sourceHash: 'ee'.repeat(32),
    timestamp: '2026-06-01T00:00:00.000Z',
    verifierScope: '7',
    epoch: 2,
  })
  return { ...base, ...overrides }
}

function makeConfirmedReceipt(manifest: ProofManifest): VerificationReceipt {
  const base = createReceipt(
    manifest,
    {
      status: 'confirmed',
      txHash: manifest.transactionRef,
      contractMatch: true,
      ledger: 4200,
      createdAt: 1748736060,
    },
    {
      videoHash: manifest.videoHash,
      metadataHash: manifest.metadataHash,
      tier: { silent: 1, source: 2, seal: 3 }[manifest.tier],
      status: 1,
      createdAt: manifest.timestamp,
      source: manifest.sourceHash,
      issuer: null,
    },
    'valid',
  )
  return { ...base, verifiedAt: '2026-06-01T00:02:00.000Z' }
}

async function makeSignedReceipt(
  manifest: ProofManifest,
  keyId: string,
  privateKey: CryptoKey,
  overrides: Partial<Parameters<typeof signVerificationReceipt>[0]> = {},
): Promise<SignedVerificationReceipt> {
  return await signVerificationReceipt(
    {
      result: 'verified',
      verifiedAt: '2026-06-01T00:02:00.000Z',
      proofId: manifest.proofId,
      videoHash: manifest.videoHash,
      metadataHash: manifest.metadataHash,
      tier: manifest.tier,
      networkPassphrase: manifest.network,
      contractId: manifest.contractId,
      ledgerSequence: 4200,
      transactionHash: manifest.transactionRef,
      circuitVersion: '1.0.0',
      verifierVersion: '1.0.0',
      ...overrides,
    },
    keyId,
    privateKey,
  )
}

describe('verify-bundle offline verification module and CLI', () => {
  let tempDir: string
  let stdoutChunks: string[]
  let stderrChunks: string[]

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'harpocrates-bundle-test-'))
    stdoutChunks = []
    stderrChunks = []

    vi.spyOn(globalThis, 'fetch').mockImplementation((async () => {
      throw new Error('network fetch must never be called during offline bundle verification')
    }) as typeof fetch)

    vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => {
      stdoutChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    }) as typeof process.stdout.write)

    vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
      stderrChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    }) as typeof process.stderr.write)

    vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new ExitSignal(code ?? 0)
    }) as typeof process.exit)
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    await rm(tempDir, { recursive: true, force: true })
  })

  async function invokeCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
    stdoutChunks = []
    stderrChunks = []
    let code = 0
    try {
      await main(args)
    } catch (err) {
      if (err instanceof ExitSignal) {
        code = err.code
      } else {
        throw err
      }
    }
    return {
      code,
      stdout: stdoutChunks.join(''),
      stderr: stderrChunks.join(''),
    }
  }

  it('validates manifest, receipts, trust snapshot, and lineage snapshot locally while reporting online-only checks as unavailable', async () => {
    const { privateKey, publicJwk } = await generateTestSigningKeys()
    const manifest = makeManifest()
    const signedReceipt = await makeSignedReceipt(manifest, 'verifier-key-1', privateKey)
    const receipt = makeConfirmedReceipt(manifest)

    const bundle = createOfflineVerificationBundle({
      manifest,
      signedReceipt,
      receipt,
      trustSnapshot: {
        capturedAt: '2026-06-01T00:05:00.000Z',
        network: 'testnet',
        contractId: CONTRACT_ID,
        trustedKeys: { 'verifier-key-1': publicJwk },
        keyValidity: {
          'verifier-key-1': {
            notBefore: '2026-01-01T00:00:00.000Z',
            notAfter: '2027-01-01T00:00:00.000Z',
          },
        },
        expectedTier: 'source',
        verifierScope: '7',
        lineageSnapshot: {
          records: {
            [manifest.videoHash]: {
              outputDigest: manifest.videoHash,
              parentProofIds: [PARENT_PROOF_ID],
              parentCommitments: ['22'.repeat(32)],
              manifestDigest: computeManifestDigest(manifest),
              actor: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
              operationType: 'trim',
              depth: 1,
            },
          },
          proofStatuses: {
            [PARENT_PROOF_ID]: 'valid',
          },
        },
      },
    })

    const bundlePath = join(tempDir, 'bundle.json')
    await writeFile(bundlePath, serializeVerificationBundle(bundle), 'utf-8')

    const jsonRun = await invokeCli([
      'verify-bundle',
      '--bundle',
      bundlePath,
      '--contract-id',
      CONTRACT_ID,
      '--network',
      'testnet',
      '--proof-id',
      manifest.proofId,
      '--at',
      '2026-06-02T00:00:00.000Z',
      '--output',
      'json',
    ])

    expect(jsonRun.code).toBe(0)
    expect(globalThis.fetch).not.toHaveBeenCalled()

    const report = JSON.parse(jsonRun.stdout) as BundleVerificationReport
    expect(report.protocol).toBe(BUNDLE_REPORT_PROTOCOL)
    expect(report.mode).toBe('offline')
    expect(report.bundleValid).toBe(true)
    expect(report.overallStatus).toBe('offline_verified')
    expect(report.onlineChecksStatus).toBe('unavailable')
    expect(report.manifestDigest).toBe(computeManifestDigest(manifest))
    expect(report.onlineChecks).toEqual({
      liveRpcTransactionLookup: 'unavailable',
      liveContractStateSimulation: 'unavailable',
      liveRevocationAndDisputeCheck: 'unavailable',
    })

    const offlineChecks = report.checks.filter((c) => c.scope === 'offline')
    const onlineChecks = report.checks.filter((c) => c.scope === 'online_only')
    expect(offlineChecks.map((c) => c.id)).toEqual([
      'bundle_integrity',
      'manifest_validation',
      'trust_snapshot_validation',
      'signed_receipt_signature',
      'receipt_validation',
      'statement_consistency',
      'lineage_snapshot',
    ])
    expect(offlineChecks.every((c) => c.status === 'passed')).toBe(true)
    expect(onlineChecks).toHaveLength(3)
    expect(onlineChecks.every((c) => c.status === 'unavailable')).toBe(true)

    const textRun = await invokeCli([
      'verify-bundle',
      '-b',
      bundlePath,
      '--at',
      '2026-06-02T00:00:00.000Z',
    ])
    expect(textRun.code).toBe(0)
    expect(textRun.stdout).toContain('Online-Only Checks:  UNAVAILABLE')
    expect(textRun.stdout).toContain('[UNAVAILABLE] live_rpc_transaction_lookup')
    expect(textRun.stdout).toContain('[UNAVAILABLE] live_contract_state_simulation')
    expect(textRun.stdout).toContain('[UNAVAILABLE] live_revocation_and_dispute_check')
  })

  it('supports QR-encoded compact signed receipts inside an offline bundle', async () => {
    const { privateKey, publicJwk } = await generateTestSigningKeys()
    const manifest = makeManifest()
    const signedReceipt = await makeSignedReceipt(manifest, 'qr-key', privateKey)

    const bundle = createOfflineVerificationBundle({
      manifest,
      signedReceipt: encodeReceiptForQr(signedReceipt),
      trustSnapshot: {
        capturedAt: '2026-06-01T00:05:00.000Z',
        network: DEFAULT_NETWORK_PASSPHRASE,
        contractId: CONTRACT_ID,
        trustedKeys: { 'qr-key': publicJwk },
      },
    })

    const report = await verifyOfflineBundle(bundle, {
      now: new Date('2026-06-01T01:00:00.000Z'),
    })
    expect(report.bundleValid).toBe(true)
    expect(report.exitCode).toBe(0)
    expect(report.onlineChecksStatus).toBe('unavailable')
  })

  it('fails closed on tampered signatures, cross-artifact statement/tier mismatches, expired keys, or pending receipts', async () => {
    const { privateKey, publicJwk } = await generateTestSigningKeys()
    const manifest = makeManifest()
    const signedReceipt = await makeSignedReceipt(manifest, 'k1', privateKey)

    // 1. Tampered signature
    const tamperedBundle: OfflineVerificationBundle = createOfflineVerificationBundle({
      manifest,
      signedReceipt: {
        ...signedReceipt,
        signature: signedReceipt.signature.slice(0, -4) + 'AAAA',
      },
      trustSnapshot: {
        capturedAt: '2026-06-01T00:05:00.000Z',
        network: DEFAULT_NETWORK_PASSPHRASE,
        contractId: CONTRACT_ID,
        trustedKeys: { k1: publicJwk },
      },
    })
    const tamperedReport = await verifyOfflineBundle(tamperedBundle)
    expect(tamperedReport.bundleValid).toBe(false)
    expect(tamperedReport.exitCode).toBe(8)

    // 2. Identity tier mismatch between signedReceipt and manifest (valid signature over wrong tier)
    const wrongTierSigned = await makeSignedReceipt(manifest, 'k1', privateKey, {
      tier: 'seal',
    })
    const tierMismatchReport = await verifyOfflineBundle(
      createOfflineVerificationBundle({
        manifest,
        signedReceipt: wrongTierSigned,
        trustSnapshot: {
          capturedAt: '2026-06-01T00:05:00.000Z',
          network: DEFAULT_NETWORK_PASSPHRASE,
          contractId: CONTRACT_ID,
          trustedKeys: { k1: publicJwk },
        },
      }),
    )
    expect(tierMismatchReport.bundleValid).toBe(false)
    expect(tierMismatchReport.exitCode).toBe(8)
    expect(tierMismatchReport.failureReasons).toContain(
      'signedReceipt.tier does not match manifest.tier',
    )

    // 3. Stale signer key at evaluation time (--at after notAfter)
    const expiredKeyReport = await verifyOfflineBundle(
      createOfflineVerificationBundle({
        manifest,
        signedReceipt,
        trustSnapshot: {
          capturedAt: '2026-06-01T00:05:00.000Z',
          network: DEFAULT_NETWORK_PASSPHRASE,
          contractId: CONTRACT_ID,
          trustedKeys: { k1: publicJwk },
          keyValidity: {
            k1: { notAfter: '2026-06-01T12:00:00.000Z' },
          },
        },
      }),
      { now: new Date('2026-06-02T00:00:00.000Z') },
    )
    expect(expiredKeyReport.bundleValid).toBe(false)
    expect(expiredKeyReport.exitCode).toBe(8)

    // 4. Pending unsigned receipt without confirmed chain state fails closed
    const pendingReceipt = createReceipt(
      manifest,
      { status: 'pending', txHash: manifest.transactionRef },
      null,
      'pending',
    )
    const pendingReport = await verifyOfflineBundle(
      createOfflineVerificationBundle({
        manifest,
        receipt: pendingReceipt,
        trustSnapshot: {
          capturedAt: '2026-06-01T00:05:00.000Z',
          network: DEFAULT_NETWORK_PASSPHRASE,
          contractId: CONTRACT_ID,
        },
      }),
    )
    expect(pendingReport.bundleValid).toBe(false)
    expect(pendingReport.exitCode).toBe(8)
  })

  it('rejects private JWKs, prohibited witness/secret fields, and revoked lineage snapshots fail-closed', async () => {
    const { privateKey, publicJwk, privateJwk } = await generateTestSigningKeys()
    const manifest = makeManifest()
    const signedReceipt = await makeSignedReceipt(manifest, 'k1', privateKey)

    // Private JWK in trustSnapshot.trustedKeys
    const privJwkReport = await verifyOfflineBundle(
      createOfflineVerificationBundle({
        manifest,
        signedReceipt,
        trustSnapshot: {
          capturedAt: '2026-06-01T00:05:00.000Z',
          network: DEFAULT_NETWORK_PASSPHRASE,
          contractId: CONTRACT_ID,
          trustedKeys: { k1: privateJwk },
        },
      }),
    )
    expect(privJwkReport.bundleValid).toBe(false)
    expect(privJwkReport.exitCode).toBe(8)
    expect(privJwkReport.failureReasons[0]).toContain('private key material')

    // Prohibited witness field smuggled into bundle
    const witnessBundle = {
      ...createOfflineVerificationBundle({
        manifest,
        signedReceipt,
        trustSnapshot: {
          capturedAt: '2026-06-01T00:05:00.000Z',
          network: DEFAULT_NETWORK_PASSPHRASE,
          contractId: CONTRACT_ID,
          trustedKeys: { k1: publicJwk },
        },
      }),
      privateWitness: 'deadbeef',
    }
    const witnessReport = await verifyOfflineBundle(witnessBundle)
    expect(witnessReport.bundleValid).toBe(false)
    expect(witnessReport.exitCode).toBe(8)
    expect(witnessReport.failureReasons[0]).toContain('prohibited private or witness field')

    // Revoked ancestor in lineageSnapshot
    const revokedLineageReport = await verifyOfflineBundle(
      createOfflineVerificationBundle({
        manifest,
        signedReceipt,
        trustSnapshot: {
          capturedAt: '2026-06-01T00:05:00.000Z',
          network: DEFAULT_NETWORK_PASSPHRASE,
          contractId: CONTRACT_ID,
          trustedKeys: { k1: publicJwk },
          lineageSnapshot: {
            records: {
              [manifest.videoHash]: {
                outputDigest: manifest.videoHash,
                parentProofIds: [PARENT_PROOF_ID],
                parentCommitments: ['22'.repeat(32)],
                manifestDigest: computeManifestDigest(manifest),
                actor: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
                operationType: 'crop',
                depth: 1,
              },
            },
            proofStatuses: {
              [PARENT_PROOF_ID]: 'revoked',
            },
          },
        },
      }),
    )
    expect(revokedLineageReport.bundleValid).toBe(false)
    expect(revokedLineageReport.exitCode).toBe(8)
    expect(revokedLineageReport.failureReasons[0]).toContain('revoked')
  })

  it('returns distinct exit codes for network mismatch (4), contract mismatch (5), and usage errors (2)', async () => {
    const { privateKey, publicJwk } = await generateTestSigningKeys()
    const manifest = makeManifest()
    const signedReceipt = await makeSignedReceipt(manifest, 'k1', privateKey)
    const bundle = createOfflineVerificationBundle({
      manifest,
      signedReceipt,
      trustSnapshot: {
        capturedAt: '2026-06-01T00:05:00.000Z',
        network: DEFAULT_NETWORK_PASSPHRASE,
        contractId: CONTRACT_ID,
        trustedKeys: { k1: publicJwk },
      },
    })

    const bundlePath = join(tempDir, 'bundle.json')
    await writeFile(bundlePath, serializeVerificationBundle(bundle), 'utf-8')

    const netMismatch = await invokeCli([
      'verify-bundle',
      '--bundle',
      bundlePath,
      '--network',
      'mainnet',
      '--output',
      'json',
    ])
    expect(netMismatch.code).toBe(4)
    expect((JSON.parse(netMismatch.stdout) as BundleVerificationReport).overallStatus).toBe(
      'network_mismatch',
    )

    const contractMismatch = await invokeCli([
      'verify-bundle',
      '--bundle',
      bundlePath,
      '--contract-id',
      OTHER_CONTRACT_ID,
      '--output',
      'json',
    ])
    expect(contractMismatch.code).toBe(5)
    expect((JSON.parse(contractMismatch.stdout) as BundleVerificationReport).overallStatus).toBe(
      'contract_mismatch',
    )

    const missingBundle = await invokeCli(['verify-bundle'])
    expect(missingBundle.code).toBe(2)
  })
})
