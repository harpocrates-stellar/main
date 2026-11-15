import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdirSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { tmpdir } from 'node:os'

const {
  verifyTransactionMock,
  lookupByVideoHashMock,
  lookupProofStatusMock,
  getLineageMock,
  getProofStatusMock,
} = vi.hoisted(() => ({
  verifyTransactionMock: vi.fn(),
  lookupByVideoHashMock: vi.fn(),
  lookupProofStatusMock: vi.fn(),
  getLineageMock: vi.fn(),
  getProofStatusMock: vi.fn(),
}))

vi.mock('../src/stellar-lookup.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/stellar-lookup.js')>()
  return {
    ...actual,
    verifyTransaction: verifyTransactionMock,
    lookupByVideoHash: lookupByVideoHashMock,
    lookupProofStatus: lookupProofStatusMock,
    getLineage: getLineageMock,
    getProofStatus: getProofStatusMock,
  }
})

import { LookupTimeoutError } from '../src/stellar-lookup.js'
import {
  CLI_EXIT_CODES,
  evaluateVerificationChecks,
  exitCodeForVerificationResult,
  aggregateBatchExitCode,
} from '../src/exit-codes.js'
import { createProofManifest, serializeManifest } from '../src/manifest.js'
import { main } from '../src/cli.js'

const VALID_CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4'
const SOURCE_ADDRESS = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF'
const TESTNET = 'Test SDF Network ; September 2015'
const TX_HASH = '12'.repeat(32)
const VIDEO_HASH = 'ab'.repeat(32)
const METADATA_HASH = 'cd'.repeat(32)
const SOURCE_HASH = 'ef'.repeat(32)
const PROOF_ID = '34'.repeat(32)

class ExitSignal extends Error {
  readonly code: number
  constructor(code: number) {
    super(`exit(${code})`)
    this.code = code
  }
}

describe('exit-codes unit suite', () => {
  it('defines distinct codes for invalid (8), incomplete (6), and unavailable (9)', () => {
    expect(CLI_EXIT_CODES.VALID).toBe(0)
    expect(CLI_EXIT_CODES.INCOMPLETE).toBe(6)
    expect(CLI_EXIT_CODES.INVALID).toBe(8)
    expect(CLI_EXIT_CODES.UNAVAILABLE).toBe(9)
    expect(new Set([CLI_EXIT_CODES.INVALID, CLI_EXIT_CODES.INCOMPLETE, CLI_EXIT_CODES.UNAVAILABLE]).size).toBe(3)

    expect(exitCodeForVerificationResult('valid')).toBe(0)
    expect(exitCodeForVerificationResult('pending')).toBe(6)
    expect(exitCodeForVerificationResult('incomplete')).toBe(6)
    expect(exitCodeForVerificationResult('error')).toBe(8)
    expect(exitCodeForVerificationResult('invalid')).toBe(8)
    expect(exitCodeForVerificationResult('unavailable')).toBe(9)
  })

  it('never reports skipped required checks as success in evaluateVerificationChecks', () => {
    expect(evaluateVerificationChecks([])).toEqual({
      outcome: 'incomplete',
      exitCode: CLI_EXIT_CODES.INCOMPLETE,
    })

    expect(
      evaluateVerificationChecks([
        { name: 'manifest_schema', required: true, status: 'passed' },
        { name: 'on_chain_registry', required: true, status: 'skipped' },
      ]),
    ).toEqual({
      outcome: 'incomplete',
      exitCode: CLI_EXIT_CODES.INCOMPLETE,
    })

    expect(
      evaluateVerificationChecks([
        { name: 'manifest_schema', required: true, status: 'passed' },
        { name: 'on_chain_registry', required: true, status: 'unavailable' },
        { name: 'lineage', required: true, status: 'skipped' },
      ]),
    ).toEqual({
      outcome: 'unavailable',
      exitCode: CLI_EXIT_CODES.UNAVAILABLE,
    })

    expect(
      evaluateVerificationChecks([
        { name: 'manifest_schema', required: true, status: 'failed' },
        { name: 'on_chain_registry', required: true, status: 'unavailable' },
      ]),
    ).toEqual({
      outcome: 'invalid',
      exitCode: CLI_EXIT_CODES.INVALID,
    })

    expect(
      evaluateVerificationChecks([
        { name: 'manifest_schema', required: true, status: 'passed' },
        { name: 'optional_c2pa', required: false, status: 'skipped' },
      ]),
    ).toEqual({
      outcome: 'valid',
      exitCode: CLI_EXIT_CODES.VALID,
    })
  })

  it('aggregates batch exit codes deterministically without masking incomplete, unavailable, or invalid items', () => {
    expect(aggregateBatchExitCode([])).toBe(CLI_EXIT_CODES.INCOMPLETE)
    expect(aggregateBatchExitCode([0, 0, 0])).toBe(CLI_EXIT_CODES.VALID)
    expect(aggregateBatchExitCode([0, 6])).toBe(CLI_EXIT_CODES.INCOMPLETE)
    expect(aggregateBatchExitCode([0, 9])).toBe(CLI_EXIT_CODES.UNAVAILABLE)
    expect(aggregateBatchExitCode([6, 9])).toBe(CLI_EXIT_CODES.UNAVAILABLE)
    expect(aggregateBatchExitCode([0, 6, 9, 8])).toBe(CLI_EXIT_CODES.INVALID)
  })
})

describe('CLI single and batch verification exit codes', () => {
  let tempDir: string
  let validManifestPath: string
  let validManifest2Path: string
  let corruptManifestPath: string
  let stdoutChunks: string[]
  let stderrChunks: string[]

  beforeEach(() => {
    vi.clearAllMocks()
    stdoutChunks = []
    stderrChunks = []
    tempDir = resolve(tmpdir(), `harpocrates-exit-${Date.now()}-${Math.random().toString(36).slice(2)}`)
    mkdirSync(tempDir, { recursive: true })

    const m1 = createProofManifest({
      proofId: PROOF_ID,
      tier: 'silent',
      network: TESTNET,
      contractId: VALID_CONTRACT_ID,
      transactionRef: TX_HASH,
      videoHash: VIDEO_HASH,
      metadataHash: METADATA_HASH,
      sourceHash: SOURCE_HASH,
      timestamp: '2026-08-01T00:00:00.000Z',
    })
    const m2 = createProofManifest({
      proofId: '56'.repeat(32),
      tier: 'source',
      network: TESTNET,
      contractId: VALID_CONTRACT_ID,
      transactionRef: TX_HASH,
      videoHash: VIDEO_HASH,
      metadataHash: METADATA_HASH,
      sourceHash: SOURCE_HASH,
      timestamp: '2026-08-01T00:00:00.000Z',
    })

    validManifestPath = join(tempDir, 'm1.json')
    validManifest2Path = join(tempDir, 'm2.json')
    corruptManifestPath = join(tempDir, 'corrupt.json')
    writeFileSync(validManifestPath, serializeManifest(m1), 'utf-8')
    writeFileSync(validManifest2Path, serializeManifest(m2), 'utf-8')
    writeFileSync(corruptManifestPath, '{not-valid-json', 'utf-8')

    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stdoutChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    })
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderrChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    })
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

  async function runMain(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
    stdoutChunks = []
    stderrChunks = []
    try {
      await main(args)
    } catch (err) {
      if (err instanceof ExitSignal) {
        return {
          code: err.code,
          stdout: stdoutChunks.join(''),
          stderr: stderrChunks.join(''),
        }
      }
      throw err
    }
    throw new Error('Expected main() to exit')
  }

  it('distinguishes valid (0), incomplete (6), invalid (8), and unavailable (9) in single verify', async () => {
    verifyTransactionMock.mockResolvedValueOnce({
      status: 'confirmed',
      txHash: TX_HASH,
      ledger: 42,
      contractMatch: true,
    })
    lookupByVideoHashMock.mockResolvedValueOnce({
      videoHash: VIDEO_HASH,
      metadataHash: METADATA_HASH,
      tier: 1,
      status: 1,
      createdAt: '1754006400',
    })
    const okRes = await runMain([
      'verify',
      '--manifest',
      validManifestPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--output',
      'json',
    ])
    expect(okRes.code).toBe(0)

    const offlineRes = await runMain([
      'verify',
      '--manifest',
      validManifestPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--offline',
      '--output',
      'json',
    ])
    expect(offlineRes.code).toBe(6)

    verifyTransactionMock.mockResolvedValueOnce({
      status: 'confirmed',
      txHash: TX_HASH,
      ledger: 42,
      contractMatch: true,
    })
    lookupByVideoHashMock.mockResolvedValueOnce({
      videoHash: 'ff'.repeat(32), // digest mismatch -> invalid (8)
      metadataHash: METADATA_HASH,
      tier: 1,
      status: 1,
      createdAt: '1754006400',
    })
    const invalidRes = await runMain([
      'verify',
      '--manifest',
      validManifestPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--output',
      'json',
    ])
    expect(invalidRes.code).toBe(8)

    verifyTransactionMock.mockRejectedValueOnce(new LookupTimeoutError('verifyTransaction', 5000))
    const timeoutRes = await runMain([
      'verify',
      '--manifest',
      validManifestPath,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--output',
      'json',
    ])
    expect(timeoutRes.code).toBe(9)
    expect(timeoutRes.stderr).toContain('unavailable')
  })

  it('returns 9 (unavailable) on RPC failure in status and verify-lineage, vs 8 (invalid) on cycle', async () => {
    lookupProofStatusMock.mockRejectedValueOnce(new Error('ECONNREFUSED'))
    const statusUnavail = await runMain([
      'status',
      '--contract-id',
      VALID_CONTRACT_ID,
      '--proof-id',
      PROOF_ID,
    ])
    expect(statusUnavail.code).toBe(9)

    getLineageMock.mockResolvedValueOnce(null)
    getProofStatusMock.mockRejectedValueOnce(new Error('RPC unreachable'))
    const lineageUnavail = await runMain([
      'verify-lineage',
      '--output-digest',
      VIDEO_HASH,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--source-address',
      SOURCE_ADDRESS,
    ])
    expect(lineageUnavail.code).toBe(9)

    getLineageMock.mockImplementation(async (digest: string) => ({
      parentProofIds: [digest],
      parentCommitments: ['c1'],
      manifestDigest: 'm1',
      actor: SOURCE_ADDRESS,
      operationType: 'crop',
      outputDigest: digest,
      depth: 1,
    }))
    const lineageCycle = await runMain([
      'verify-lineage',
      '--output-digest',
      VIDEO_HASH,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--source-address',
      SOURCE_ADDRESS,
    ])
    expect(lineageCycle.code).toBe(8)
  })

  it('applies identical distinct exit codes across batch verification (verify --batch)', async () => {
    const validBatchList = join(tempDir, 'batch-valid.json')
    writeFileSync(validBatchList, JSON.stringify([validManifestPath, validManifest2Path]), 'utf-8')

    // Offline batch skips required on-chain checks -> must exit 6 (incomplete), NEVER 0
    const offlineBatch = await runMain([
      'verify',
      '--batch',
      validBatchList,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--offline',
      '--output',
      'json',
    ])
    expect(offlineBatch.code).toBe(6)
    const offlineParsed = JSON.parse(offlineBatch.stdout)
    expect(offlineParsed.summary).toEqual({
      total: 2,
      valid: 0,
      incomplete: 2,
      invalid: 0,
      unavailable: 0,
      exitCode: 6,
    })

    // Online batch where all items pass required checks -> exits 0
    verifyTransactionMock.mockResolvedValue({
      status: 'confirmed',
      txHash: TX_HASH,
      ledger: 42,
      contractMatch: true,
    })
    lookupByVideoHashMock
      .mockResolvedValueOnce({
        videoHash: VIDEO_HASH,
        metadataHash: METADATA_HASH,
        tier: 1,
        status: 1,
        createdAt: '1754006400',
      })
      .mockResolvedValueOnce({
        videoHash: VIDEO_HASH,
        metadataHash: METADATA_HASH,
        tier: 2,
        status: 1,
        createdAt: '1754006400',
      })
    const onlineOkBatch = await runMain([
      'verify',
      '--batch',
      validBatchList,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--output',
      'json',
    ])
    expect(onlineOkBatch.code).toBe(0)

    // Batch where second item encounters RPC unavailability -> exits 9 (unavailable)
    lookupByVideoHashMock
      .mockResolvedValueOnce({
        videoHash: VIDEO_HASH,
        metadataHash: METADATA_HASH,
        tier: 1,
        status: 1,
        createdAt: '1754006400',
      })
      .mockRejectedValueOnce(new Error('RPC timeout'))
    const unavailBatch = await runMain([
      'verify',
      '--batch',
      validBatchList,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--output',
      'json',
    ])
    expect(unavailBatch.code).toBe(9)

    // Mixed batch containing a corrupt manifest -> exits 8 (invalid)
    const mixedBatchList = join(tempDir, 'batch-mixed.json')
    writeFileSync(mixedBatchList, JSON.stringify([validManifestPath, corruptManifestPath]), 'utf-8')
    lookupByVideoHashMock.mockResolvedValueOnce({
      videoHash: VIDEO_HASH,
      metadataHash: METADATA_HASH,
      tier: 1,
      status: 1,
      createdAt: '1754006400',
    })
    const invalidBatch = await runMain([
      'verify',
      '--batch',
      mixedBatchList,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--output',
      'json',
    ])
    expect(invalidBatch.code).toBe(8)
  })
})
