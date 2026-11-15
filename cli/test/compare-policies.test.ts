import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  compareTrustPolicies,
  parseTrustPolicy,
  formatPolicyComparisonReport,
  POLICY_COMPARISON_PROTOCOL,
  type TrustPolicy,
} from '../src/compare-policies.js'
import { createProofManifest } from '../src/manifest.js'
import type { VerificationReceipt } from '../src/receipt.js'
import { signVerificationReceipt } from '../src/signed-receipt.js'
import { main } from '../src/cli.js'

const CONTRACT_A = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4'
const TESTNET = 'Test SDF Network ; September 2015'

class ExitSignal extends Error {
  readonly code: number
  constructor(code: number) {
    super(`exit(${code})`)
    this.code = code
  }
}

function makeBundleItem(params: {
  proofId: string
  tier: 'silent' | 'source' | 'seal'
  result?: VerificationReceipt['result']
  txStatus?: VerificationReceipt['transaction']['status']
  verifiedAt?: string
}) {
  const manifest = createProofManifest({
    proofId: params.proofId,
    tier: params.tier,
    network: TESTNET,
    contractId: CONTRACT_A,
    transactionRef: '11'.repeat(32),
    videoHash: '22'.repeat(32),
    metadataHash: '33'.repeat(32),
    sourceHash: '44'.repeat(32),
    timestamp: '2026-08-01T10:00:00.000Z',
    verifierScope: '0',
    epoch: 1,
  })
  const receipt: VerificationReceipt = {
    version: 1,
    verifiedAt: params.verifiedAt ?? '2026-08-01T10:05:00.000Z',
    manifest,
    transaction: {
      status: params.txStatus ?? 'confirmed',
      txHash: '11'.repeat(32),
      ledger: 200,
      contractMatch: true,
    },
    chainRecord:
      params.result === 'pending'
        ? null
        : {
            videoHash: manifest.videoHash,
            metadataHash: manifest.metadataHash,
            tier: { silent: 1, source: 2, seal: 3 }[manifest.tier],
            status: 1,
            createdAt: '1754042400',
          },
    result: params.result ?? 'valid',
  }
  return { manifest, receipt }
}

describe('compareTrustPolicies unit suite', () => {
  it('evaluates two policies against identical saved bundle evidence without mutating policy objects or network', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    try {
      const bundle = {
        protocol: 'harpocrates-verification-bundle',
        version: 1,
        items: [
          makeBundleItem({ proofId: 'aa'.repeat(32), tier: 'silent' }),
          makeBundleItem({ proofId: 'bb'.repeat(32), tier: 'seal' }),
        ],
      }

      const policyA: TrustPolicy = {
        protocol: 'harpocrates-trust-policy',
        version: 1,
        name: 'baseline-open-tiers',
        allowedNetworks: ['testnet'],
        allowedContractIds: [CONTRACT_A],
        minimumTier: 'silent',
      }
      const policyB: TrustPolicy = {
        protocol: 'harpocrates-trust-policy',
        version: 1,
        name: 'candidate-seal-only',
        allowedNetworks: [TESTNET],
        allowedContractIds: [CONTRACT_A],
        minimumTier: 'seal',
      }
      const rawA = JSON.stringify(policyA)
      const rawB = JSON.stringify(policyB)

      const report = await compareTrustPolicies(JSON.stringify(bundle), rawA, rawB)

      expect(report.protocol).toBe(POLICY_COMPARISON_PROTOCOL)
      expect(report.identicalDecisions).toBe(false)
      expect(report.decisionChangedCount).toBe(1)
      expect(report.totalItems).toBe(2)
      expect(report.changedDecisions).toHaveLength(1)
      expect(report.changedDecisions[0]).toMatchObject({
        proofId: 'aa'.repeat(32),
        tier: 'silent',
        transition: 'newly_rejected',
      })
      expect(report.changedDecisions[0].policyB.failedRules).toEqual(['below_minimum_tier'])
      expect(JSON.stringify(policyA)).toBe(rawA)
      expect(JSON.stringify(policyB)).toBe(rawB)
      expect(formatPolicyComparisonReport(report)).toContain('1 CHANGED DECISION(S)')
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      fetchSpy.mockRestore()
    }
  })

  it('evaluates signed receipt key rotation and maxReceiptAgeSeconds deterministically', async () => {
    const key1 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])
    const key2 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])
    const pub1 = await crypto.subtle.exportKey('jwk', key1.publicKey)
    const pub2 = await crypto.subtle.exportKey('jwk', key2.publicKey)

    const signedReceipt = await signVerificationReceipt(
      {
        result: 'verified',
        verifiedAt: '2026-08-01T10:00:00.000Z',
        proofId: 'cc'.repeat(32),
        videoHash: '22'.repeat(32),
        metadataHash: '33'.repeat(32),
        tier: 'source',
        networkPassphrase: TESTNET,
        contractId: CONTRACT_A,
        ledgerSequence: 55,
        transactionHash: '11'.repeat(32),
        circuitVersion: '1.0.0',
        verifierVersion: '1.0.0',
      },
      'k1',
      key1.privateKey,
    )

    const bundle = { signedReceipt }
    const policyWithK1: TrustPolicy = {
      version: 1,
      requireOnChainConfirmation: false,
      requireSignedReceipt: true,
      trustedKeys: { k1: pub1 },
      maxReceiptAgeSeconds: 3600,
    }
    const policyWithK2: TrustPolicy = {
      version: 1,
      requireOnChainConfirmation: false,
      requireSignedReceipt: true,
      trustedKeys: { k2: pub2 },
      maxReceiptAgeSeconds: 3600,
    }

    const report = await compareTrustPolicies(
      JSON.stringify(bundle),
      JSON.stringify(policyWithK1),
      JSON.stringify(policyWithK2),
      { now: new Date('2026-08-01T10:30:00.000Z') },
    )
    expect(report.decisionChangedCount).toBe(1)
    expect(report.items[0].policyA.outcome).toBe('trusted')
    expect(report.items[0].policyB.outcome).toBe('rejected')
    expect(report.items[0].policyB.failedRules).toContain('signed_receipt_untrusted')
  })

  it('never trusts pending offline evidence and rejects private key material or inconsistent bundles', async () => {
    const pendingItem = makeBundleItem({
      proofId: 'dd'.repeat(32),
      tier: 'silent',
      result: 'pending',
      txStatus: 'pending',
    })
    const openPolicy: TrustPolicy = { version: 1 }
    const pendingReport = await compareTrustPolicies(
      JSON.stringify(pendingItem),
      JSON.stringify(openPolicy),
      JSON.stringify(openPolicy),
    )
    expect(pendingReport.items[0].policyA.trusted).toBe(false)
    expect(pendingReport.items[0].policyA.outcome).toBe('incomplete')

    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])
    const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
    expect(() =>
      parseTrustPolicy(JSON.stringify({ version: 1, trustedKeys: { k1: privJwk } })),
    ).toThrow(/private key material/)

    const mismatched = makeBundleItem({ proofId: 'ee'.repeat(32), tier: 'silent' })
    const badBundle = {
      manifest: mismatched.manifest,
      receipt: {
        ...mismatched.receipt,
        manifest: { ...mismatched.manifest, videoHash: 'ff'.repeat(32) },
      },
    }
    await expect(
      compareTrustPolicies(
        JSON.stringify(badBundle),
        JSON.stringify(openPolicy),
        JSON.stringify(openPolicy),
      ),
    ).rejects.toThrow(/disagree/)
  })
})

describe('CLI command: compare-policies', () => {
  let tempDir: string
  let bundlePath: string
  let policyAPath: string
  let policyBPath: string
  let policyBIdenticalPath: string
  let stdoutChunks: string[]
  let stderrChunks: string[]

  beforeEach(() => {
    stdoutChunks = []
    stderrChunks = []
    tempDir = resolve(tmpdir(), `harpocrates-pol-${Date.now()}-${Math.random().toString(36).slice(2)}`)
    mkdirSync(tempDir, { recursive: true })

    bundlePath = join(tempDir, 'bundle.json')
    policyAPath = join(tempDir, 'policy-a.json')
    policyBPath = join(tempDir, 'policy-b.json')
    policyBIdenticalPath = join(tempDir, 'policy-b-same.json')

    writeFileSync(
      bundlePath,
      JSON.stringify(makeBundleItem({ proofId: 'aa'.repeat(32), tier: 'silent' }), null, 2),
      'utf-8',
    )
    writeFileSync(
      policyAPath,
      JSON.stringify({ version: 1, name: 'lenient', minimumTier: 'silent' }, null, 2),
      'utf-8',
    )
    writeFileSync(
      policyBPath,
      JSON.stringify({ version: 1, name: 'strict', minimumTier: 'seal' }, null, 2),
      'utf-8',
    )
    writeFileSync(
      policyBIdenticalPath,
      JSON.stringify({ version: 1, name: 'lenient-copy', allowedNetworks: ['testnet'] }, null, 2),
      'utf-8',
    )

    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stdoutChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    })
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderrChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    })
    vi.spyOn(process.exit, 'bind')
    vi.spyOn(process, 'exit').mockImplementation(((code?: string | number | null) => {
      throw new ExitSignal(Number(code ?? 0))
    }) as never)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    if (tempDir && existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true })
    }
  })

  async function runMain(args: string[]) {
    stdoutChunks = []
    stderrChunks = []
    try {
      await main(args)
    } catch (err) {
      if (err instanceof ExitSignal) {
        return { code: err.code, stdout: stdoutChunks.join(''), stderr: stderrChunks.join('') }
      }
      throw err
    }
    throw new Error('Expected main() to exit')
  }

  it('preserves policy files byte-for-byte on disk, exiting 0 when unchanged and 1 when decisions change', async () => {
    const beforeA = readFileSync(policyAPath)
    const beforeB = readFileSync(policyBPath)
    const beforeBundle = readFileSync(bundlePath)

    const sameRes = await runMain([
      'compare-policies',
      '--bundle',
      bundlePath,
      '--policy-a',
      policyAPath,
      '--policy-b',
      policyBIdenticalPath,
      '--output',
      'json',
    ])
    expect(sameRes.code).toBe(0)
    expect(JSON.parse(sameRes.stdout).identicalDecisions).toBe(true)

    const diffRes = await runMain([
      'compare-policies',
      '-b',
      bundlePath,
      '-a',
      policyAPath,
      '-p',
      policyBPath,
      '--at',
      '2026-08-01T10:10:00.000Z',
      '-o',
      'json',
    ])
    expect(diffRes.code).toBe(1)
    const parsed = JSON.parse(diffRes.stdout)
    expect(parsed.decisionChangedCount).toBe(1)
    expect(parsed.changedDecisions[0].transition).toBe('newly_rejected')

    expect(readFileSync(policyAPath).equals(beforeA)).toBe(true)
    expect(readFileSync(policyBPath).equals(beforeB)).toBe(true)
    expect(readFileSync(bundlePath).equals(beforeBundle)).toBe(true)
  })

  it('exits 2 on missing flags or invalid --at and exits 8 on corrupt policy with clean stdout', async () => {
    const missing = await runMain(['compare-policies', '--bundle', bundlePath, '--policy-a', policyAPath])
    expect(missing.code).toBe(2)
    expect(missing.stdout).toBe('')

    const badAt = await runMain([
      'compare-policies',
      '--bundle',
      bundlePath,
      '--policy-a',
      policyAPath,
      '--policy-b',
      policyBPath,
      '--at',
      'not-a-timestamp',
    ])
    expect(badAt.code).toBe(2)
    expect(badAt.stdout).toBe('')

    const corruptPath = join(tempDir, 'corrupt-policy.json')
    writeFileSync(corruptPath, '{bad', 'utf-8')
    const corrupt = await runMain([
      'compare-policies',
      '--bundle',
      bundlePath,
      '--policy-a',
      policyAPath,
      '--policy-b',
      corruptPath,
      '--output',
      'json',
    ])
    expect(corrupt.code).toBe(8)
    expect(corrupt.stdout).toBe('')
  })
})
