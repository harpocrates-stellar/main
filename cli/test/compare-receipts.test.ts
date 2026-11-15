import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import {
  compareReceipts,
  serializeReceiptComparison,
  formatReceiptComparison,
  RECEIPT_COMPARISON_PROTOCOL,
} from '../src/compare-receipts.js'
import { createProofManifest } from '../src/manifest.js'
import type { VerificationReceipt } from '../src/receipt.js'
import {
  signVerificationReceipt,
  encodeReceiptForQr,
  serializeVerificationReceipt,
} from '../src/signed-receipt.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = resolve(__filename, '..')
const cliRoot = resolve(__dirname, '..')
const distCli = resolve(cliRoot, 'dist', 'cli.js')

const CONTRACT_A = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4'
const CONTRACT_B = 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526'
const TESTNET = 'Test SDF Network ; September 2015'
const MAINNET = 'Public Global Stellar Network ; September 2015'

function makeVerificationReceipt(
  overrides: {
    verifiedAt?: string
    proofId?: string
    videoHash?: string
    tier?: 'silent' | 'source' | 'seal'
    network?: string
    contractId?: string
    result?: VerificationReceipt['result']
    txStatus?: VerificationReceipt['transaction']['status']
    chainStatus?: number
  } = {},
): VerificationReceipt {
  const manifest = createProofManifest({
    proofId: overrides.proofId ?? 'ab'.repeat(32),
    tier: overrides.tier ?? 'source',
    network: overrides.network ?? TESTNET,
    contractId: overrides.contractId ?? CONTRACT_A,
    transactionRef: '12'.repeat(32),
    videoHash: overrides.videoHash ?? 'cd'.repeat(32),
    metadataHash: 'ef'.repeat(32),
    sourceHash: '34'.repeat(32),
    timestamp: '2026-08-01T10:00:00.000Z',
    verifierScope: '1',
    epoch: 3,
  })
  return {
    version: 1,
    verifiedAt: overrides.verifiedAt ?? '2026-08-01T10:05:00.000Z',
    manifest,
    transaction: {
      status: overrides.txStatus ?? 'confirmed',
      txHash: '12'.repeat(32),
      ledger: 500,
      contractMatch: true,
    },
    chainRecord: {
      videoHash: manifest.videoHash,
      metadataHash: manifest.metadataHash,
      tier: { silent: 1, source: 2, seal: 3 }[manifest.tier],
      status: overrides.chainStatus ?? 1,
      createdAt: '1754042400',
    },
    result: overrides.result ?? 'valid',
  }
}

describe('compareReceipts unit suite', () => {
  it('treats canonical statement and trust as equivalent across wall-clock verifiedAt and hex case without network calls', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    try {
      const left = makeVerificationReceipt({
        verifiedAt: '2026-08-01T10:05:00.000Z',
        proofId: 'ab'.repeat(32),
      })
      const right = makeVerificationReceipt({
        verifiedAt: '2026-08-01T11:30:00.000Z',
        proofId: 'AB'.repeat(32),
      })

      const report = await compareReceipts(JSON.stringify(left), JSON.stringify(right))
      expect(report.protocol).toBe(RECEIPT_COMPARISON_PROTOCOL)
      expect(report.equivalent).toBe(true)
      expect(report.statementEqual).toBe(true)
      expect(report.trustEqual).toBe(true)
      expect(report.statementDifferences).toEqual([])
      expect(report.trustDifferences).toEqual([])
      expect(report.observationMetadata.verifiedAtChanged).toBe(true)
      expect(serializeReceiptComparison(report)).toBe(serializeReceiptComparison(report))
      expect(formatReceiptComparison(report)).toContain('Receipt Comparison: EQUIVALENT')
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      fetchSpy.mockRestore()
    }
  })

  it('cleanly separates canonical statement differences from trust-context differences', async () => {
    const baseline = makeVerificationReceipt()
    const changedStatementOnly = makeVerificationReceipt({
      videoHash: '99'.repeat(32),
      tier: 'seal',
    })
    const stmtReport = await compareReceipts(
      JSON.stringify(baseline),
      JSON.stringify(changedStatementOnly),
    )
    expect(stmtReport.equivalent).toBe(false)
    expect(stmtReport.statementEqual).toBe(false)
    expect(stmtReport.trustEqual).toBe(true)
    expect(stmtReport.statementDifferences.map((d) => d.field)).toEqual(['tier', 'videoHash'])
    expect(stmtReport.trustDifferences).toEqual([])

    const changedTrustOnly = makeVerificationReceipt({
      result: 'revoked',
      chainStatus: 2,
      network: MAINNET,
      contractId: CONTRACT_B,
    })
    const trustReport = await compareReceipts(
      JSON.stringify(baseline),
      JSON.stringify(changedTrustOnly),
    )
    expect(trustReport.equivalent).toBe(false)
    expect(trustReport.statementEqual).toBe(true)
    expect(trustReport.trustEqual).toBe(false)
    expect(trustReport.statementDifferences).toEqual([])
    expect(trustReport.trustDifferences.map((d) => d.field)).toEqual([
      'chainStatus',
      'contractId',
      'network',
      'outcomeCategory',
      'rawResult',
    ])
  })

  it('compares signed JSON and QR receipts offline and verifies signatures when keys are supplied', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )
    const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)

    const signedA = await signVerificationReceipt(
      {
        result: 'verified',
        verifiedAt: '2026-08-01T12:00:00.000Z',
        proofId: '11'.repeat(32),
        videoHash: '22'.repeat(32),
        metadataHash: '33'.repeat(32),
        tier: 'silent',
        networkPassphrase: TESTNET,
        contractId: CONTRACT_A,
        ledgerSequence: 77,
        transactionHash: '44'.repeat(32),
        circuitVersion: '2.0.0',
        verifierVersion: '1.0.0',
      },
      'issuer-key-1',
      keyPair.privateKey,
    )
    const qrEncoded = encodeReceiptForQr(signedA)

    const eqReport = await compareReceipts(
      serializeVerificationReceipt(signedA),
      qrEncoded,
      { keys: { 'issuer-key-1': publicJwk } },
    )
    expect(eqReport.equivalent).toBe(true)
    expect(eqReport.trustDifferences).toEqual([])

    const tampered = { ...signedA, signature: 'AAAA' }
    const tamperedReport = await compareReceipts(
      serializeVerificationReceipt(signedA),
      JSON.stringify(tampered),
      { keys: { 'issuer-key-1': publicJwk } },
    )
    expect(tamperedReport.equivalent).toBe(false)
    expect(tamperedReport.trustEqual).toBe(false)
    expect(tamperedReport.trustDifferences.map((d) => d.field)).toContain('signatureStatus')
  })

  it('rejects malformed, private-field-tainted, and oversized inputs fail-closed', async () => {
    const valid = JSON.stringify(makeVerificationReceipt())
    await expect(compareReceipts('{bad-json', valid)).rejects.toThrow(/not valid JSON/)

    const tainted = { ...makeVerificationReceipt(), witnessData: 'secret-witness' }
    await expect(compareReceipts(JSON.stringify(tainted), valid)).rejects.toThrow(
      /forbidden private or secret fields/,
    )

    const oversized = ' '.repeat(1024 * 1024 + 5)
    await expect(compareReceipts(oversized, valid)).rejects.toThrow(/1 MiB input limit/)
  })
})

describe('CLI command: compare-receipts', () => {
  let tempDir: string
  let leftPath: string
  let rightEquivalentPath: string
  let rightRevokedPath: string

  beforeAll(() => {
    tempDir = resolve(tmpdir(), `harpocrates-cmp-${Date.now()}-${Math.random().toString(36).slice(2)}`)
    mkdirSync(tempDir, { recursive: true })

    leftPath = join(tempDir, 'left.json')
    rightEquivalentPath = join(tempDir, 'right-eq.json')
    rightRevokedPath = join(tempDir, 'right-revoked.json')

    writeFileSync(
      leftPath,
      JSON.stringify(makeVerificationReceipt({ verifiedAt: '2026-08-01T10:00:00.000Z' })),
      'utf-8',
    )
    writeFileSync(
      rightEquivalentPath,
      JSON.stringify(makeVerificationReceipt({ verifiedAt: '2026-08-01T10:15:00.000Z' })),
      'utf-8',
    )
    writeFileSync(
      rightRevokedPath,
      JSON.stringify(makeVerificationReceipt({ result: 'revoked', chainStatus: 2 })),
      'utf-8',
    )
  })

  afterAll(() => {
    if (tempDir && existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true })
    }
  })

  function runCli(args: string[], input?: string) {
    return spawnSync(process.execPath, [distCli, ...args], {
      cwd: cliRoot,
      encoding: 'utf-8',
      input,
    })
  }

  it('exits 0 on equivalent receipts and 1 when canonical statement or trust differs', () => {
    const eqRes = runCli(['compare-receipts', '--left', leftPath, '--right', rightEquivalentPath, '-o', 'json'])
    expect(eqRes.status).toBe(0)
    expect(eqRes.stderr).toBe('')
    const eqJson = JSON.parse(eqRes.stdout.trim())
    expect(eqJson.equivalent).toBe(true)

    const diffRes = runCli(['compare-receipts', '-a', leftPath, '-b', rightRevokedPath, '-o', 'json'])
    expect(diffRes.status).toBe(1)
    expect(diffRes.stderr).toBe('')
    const diffJson = JSON.parse(diffRes.stdout.trim())
    expect(diffJson.equivalent).toBe(false)
    expect(diffJson.statementEqual).toBe(true)
    expect(diffJson.trustEqual).toBe(false)
  })

  it('exits 2 on missing flags or dual stdin and exits 8 on corrupt receipt with clean stdout', () => {
    const missing = runCli(['compare-receipts', '--left', leftPath])
    expect(missing.status).toBe(2)
    expect(missing.stdout).toBe('')

    const dualStdin = runCli(['compare-receipts', '--left', '-', '--right', '-'])
    expect(dualStdin.status).toBe(2)
    expect(dualStdin.stdout).toBe('')

    const corrupt = runCli(['compare-receipts', '--left', '-', '--right', leftPath, '-o', 'json'], '{bad')
    expect(corrupt.status).toBe(8)
    expect(corrupt.stdout).toBe('')
    expect(corrupt.stderr).toContain('invalid or unreadable receipt')
  })
})
