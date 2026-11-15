import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { StrKey } from '@stellar/stellar-sdk'

const { verifyTransactionMock, lookupByVideoHashMock } = vi.hoisted(() => ({
  verifyTransactionMock: vi.fn(),
  lookupByVideoHashMock: vi.fn(),
}))

vi.mock('../src/stellar-lookup.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/stellar-lookup.js')>()
  return {
    ...actual,
    verifyTransaction: verifyTransactionMock,
    lookupByVideoHash: lookupByVideoHashMock,
  }
})

import { createProofManifest, serializeManifest, type ProofManifest } from '../src/manifest.js'
import { DEFAULT_NETWORK_PASSPHRASE } from '../src/network.js'
import {
  BATCH_VERIFY_PROTOCOL,
  BatchBoundError,
  computeDeterministicItemId,
  resolveBatchManifestSelection,
  runBatchVerification,
} from '../src/batch-verify.js'
import { main } from '../src/cli.js'

const CONTRACT_ID = StrKey.encodeContract(Uint8Array.from({ length: 32 }, (_, i) => i + 1))
const OTHER_CONTRACT_ID = StrKey.encodeContract(Uint8Array.from({ length: 32 }, (_, i) => i + 2))

class ExitSignal extends Error {
  readonly code: number
  constructor(code: number) {
    super(`exit(${code})`)
    this.code = code
  }
}

function makeSampleManifest(seedByte: number, overrides: Partial<ProofManifest> = {}): ProofManifest {
  const hex = seedByte.toString(16).padStart(2, '0')
  const base = createProofManifest({
    proofId: hex.repeat(32),
    tier: 'source',
    network: DEFAULT_NETWORK_PASSPHRASE,
    contractId: CONTRACT_ID,
    transactionRef: (seedByte + 16).toString(16).padStart(2, '0').repeat(32),
    videoHash: (seedByte + 32).toString(16).padStart(2, '0').repeat(32),
    metadataHash: (seedByte + 48).toString(16).padStart(2, '0').repeat(32),
    sourceHash: (seedByte + 64).toString(16).padStart(2, '0').repeat(32),
    timestamp: '2026-06-01T00:00:00.000Z',
  })
  return { ...base, ...overrides }
}

describe('batch-verify module and CLI', () => {
  let tempDir: string
  let stdoutChunks: string[]
  let stderrChunks: string[]

  beforeEach(async () => {
    vi.clearAllMocks()
    tempDir = await mkdtemp(join(tmpdir(), 'harpocrates-batch-test-'))
    stdoutChunks = []
    stderrChunks = []

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

  it('computes identical deterministic item identities regardless of filename or key order and never leaks paths', async () => {
    const manifest = makeSampleManifest(1)
    const dirA = await mkdtemp(join(tempDir, 'alpha-'))
    const dirB = await mkdtemp(join(tempDir, 'bravo-'))

    const reorderedJson = JSON.stringify({
      timestamp: manifest.timestamp,
      videoHash: manifest.videoHash,
      version: manifest.version,
      verifierScope: manifest.verifierScope,
      epoch: manifest.epoch,
      protocol: manifest.protocol,
      proofId: manifest.proofId,
      tier: manifest.tier,
      network: manifest.network,
      contractId: manifest.contractId,
      transactionRef: manifest.transactionRef,
      metadataHash: manifest.metadataHash,
      sourceHash: manifest.sourceHash,
    })

    const fileA = join(dirA, 'camera_roll_private_name.json')
    const fileB = join(dirB, 'renamed_copy.json')
    await writeFile(fileA, serializeManifest(manifest), 'utf-8')
    await writeFile(fileB, reorderedJson, 'utf-8')

    const runA = await runBatchVerification({
      manifestPaths: [fileA],
      contractId: CONTRACT_ID,
      offline: true,
    })
    const runB = await runBatchVerification({
      manifestPaths: [fileB],
      contractId: CONTRACT_ID,
      offline: true,
    })

    expect(runA.results[0].itemId).toBe(computeDeterministicItemId(manifest, null, 0))
    expect(runA.results[0].itemId).toMatch(/^manifest:[0-9a-f]{64}$/)
    expect(runB.results[0].itemId).toBe(runA.results[0].itemId)

    const cliRun = await invokeCli([
      'verify-batch',
      '--input',
      dirA,
      '--contract-id',
      CONTRACT_ID,
      '--offline',
    ])

    expect(cliRun.code).toBe(6)
    expect(cliRun.stdout).not.toContain('camera_roll_private_name')
    expect(cliRun.stderr).not.toContain('camera_roll_private_name')
    expect(cliRun.stdout).not.toContain(dirA)
    expect(cliRun.stderr).not.toContain(dirA)
  })

  it('keeps JSONL result records strictly on stdout and JSONL progress + debug diagnostics on stderr', async () => {
    const m1 = makeSampleManifest(1)
    const m2 = makeSampleManifest(2)
    await writeFile(join(tempDir, '02-second.json'), serializeManifest(m2), 'utf-8')
    await writeFile(join(tempDir, '01-first.json'), serializeManifest(m1), 'utf-8')

    verifyTransactionMock.mockImplementation(async (txHash: string) => ({
      status: 'confirmed',
      txHash,
      ledger: 1001,
      ledgerTimestamp: '2026-06-01T00:05:00.000Z',
    }))
    lookupByVideoHashMock.mockImplementation(async (_cid: string, videoHash: string) => {
      const matched = videoHash === m1.videoHash ? m1 : m2
      return {
        videoHash: matched.videoHash,
        metadataHash: matched.metadataHash,
        tier: 2,
        status: 1,
        createdAt: matched.timestamp,
        source: matched.sourceHash,
        issuer: null,
      }
    })

    const res = await invokeCli([
      'verify-batch',
      '--input',
      tempDir,
      '--contract-id',
      CONTRACT_ID,
      '--debug',
    ])

    expect(res.code).toBe(0)

    const stdoutLines = res.stdout.trim().split('\n')
    expect(stdoutLines).toHaveLength(2)
    const parsedResults = stdoutLines.map((line) => JSON.parse(line) as Record<string, unknown>)
    expect(parsedResults[0]).toMatchObject({
      protocol: BATCH_VERIFY_PROTOCOL,
      version: 1,
      type: 'result',
      index: 0,
      proofId: m1.proofId,
      result: 'valid',
      exitCode: 0,
    })
    expect(parsedResults[1]).toMatchObject({
      protocol: BATCH_VERIFY_PROTOCOL,
      version: 1,
      type: 'result',
      index: 1,
      proofId: m2.proofId,
      result: 'valid',
      exitCode: 0,
    })

    const stderrLines = res.stderr.trim().split('\n')
    const parsedStderr = stderrLines.map((line) => JSON.parse(line) as Record<string, unknown>)
    const progressEvents = parsedStderr.filter((entry) => entry.type === 'progress')
    const debugEvents = parsedStderr.filter(
      (entry) => typeof entry.event === 'string' && entry.event.startsWith('verify-batch.'),
    )

    expect(progressEvents.map((e) => e.phase)).toEqual(['start', 'item', 'item', 'complete'])
    expect(progressEvents[0]).toMatchObject({ total: 2, maxItems: 64 })
    expect(progressEvents[3]).toMatchObject({
      completed: 2,
      total: 2,
      validCount: 2,
      failedCount: 0,
      pendingCount: 0,
      exitCode: 0,
    })
    expect(debugEvents.length).toBeGreaterThanOrEqual(2)
  })

  it('supports verify --batch with an explicit JSON array selection in caller order', async () => {
    const m1 = makeSampleManifest(3)
    const m2 = makeSampleManifest(4)
    const path1 = join(tempDir, 'a.json')
    const path2 = join(tempDir, 'b.json')
    const listPath = join(tempDir, 'selection.txt')

    await writeFile(path1, serializeManifest(m1), 'utf-8')
    await writeFile(path2, serializeManifest(m2), 'utf-8')
    await writeFile(listPath, JSON.stringify([path2, path1]), 'utf-8')

    const res = await invokeCli([
      'verify',
      '--batch',
      listPath,
      '--contract-id',
      CONTRACT_ID,
      '--offline',
    ])

    expect(res.code).toBe(6)
    const stdoutRecords = res.stdout
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { index: number; proofId: string; result: string })
    expect(stdoutRecords.map((r) => r.proofId)).toEqual([m2.proofId, m1.proofId])
    expect(verifyTransactionMock).not.toHaveBeenCalled()
    expect(lookupByVideoHashMock).not.toHaveBeenCalled()
  })

  it('rejects batch selections exceeding --max-items or empty selections fail-closed with clean stdout', async () => {
    const m1 = makeSampleManifest(5)
    const m2 = makeSampleManifest(6)
    const m3 = makeSampleManifest(7)
    await writeFile(join(tempDir, '1.json'), serializeManifest(m1), 'utf-8')
    await writeFile(join(tempDir, '2.json'), serializeManifest(m2), 'utf-8')
    await writeFile(join(tempDir, '3.json'), serializeManifest(m3), 'utf-8')

    await expect(resolveBatchManifestSelection(tempDir, 2)).rejects.toThrow(BatchBoundError)

    const overBound = await invokeCli([
      'verify-batch',
      '--input',
      tempDir,
      '--contract-id',
      CONTRACT_ID,
      '--max-items',
      '2',
      '--offline',
    ])

    expect(overBound.code).toBe(8)
    expect(overBound.stdout).toBe('')
    expect(overBound.stderr).toContain('exceeds maximum of 2 items')

    const emptyDir = await mkdtemp(join(tempDir, 'empty-'))
    stdoutChunks = []
    stderrChunks = []
    const emptyRes = await invokeCli([
      'verify-batch',
      '--input',
      emptyDir,
      '--contract-id',
      CONTRACT_ID,
      '--offline',
    ])

    expect(emptyRes.code).toBe(8)
    expect(emptyRes.stdout).toBe('')
    expect(emptyRes.stderr).toContain('contains no manifest JSON files')
  })

  it('records malformed, oversized, and contract-mismatched items deterministically and aggregates exit code', async () => {
    const validManifest = makeSampleManifest(8)
    const wrongContractManifest = makeSampleManifest(9, { contractId: OTHER_CONTRACT_ID })
    const malformedPath = join(tempDir, '01-corrupt.json')
    const mismatchPath = join(tempDir, '02-mismatch.json')
    const oversizedPath = join(tempDir, '03-oversized.json')
    const validPath = join(tempDir, '04-valid.json')

    await writeFile(malformedPath, '{"not":"a-manifest"}', 'utf-8')
    await writeFile(mismatchPath, serializeManifest(wrongContractManifest), 'utf-8')
    await writeFile(oversizedPath, 'x'.repeat(1024 * 1024 + 32), 'utf-8')
    await writeFile(validPath, serializeManifest(validManifest), 'utf-8')

    const res = await invokeCli([
      'verify-batch',
      '--input',
      tempDir,
      '--contract-id',
      CONTRACT_ID,
      '--offline',
    ])

    expect(res.code).toBe(8)
    const records = res.stdout
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { itemId: string; result: string; exitCode: number; reason?: string })

    expect(records).toHaveLength(4)
    expect(records[0].itemId).toMatch(/^raw:[0-9a-f]{64}$/)
    expect(records[0]).toMatchObject({ result: 'error', exitCode: 8, reason: 'invalid_or_unreadable_manifest' })
    expect(records[1]).toMatchObject({ result: 'contract_mismatch', exitCode: 5 })
    expect(records[2].itemId).toBe('unreadable:0002')
    expect(records[2]).toMatchObject({ result: 'error', exitCode: 8, reason: 'input_limit_exceeded' })
    expect(records[3]).toMatchObject({ result: 'pending', exitCode: 6 })
  })

  it('rejects invalid usage flags with exit code 2 and empty stdout', async () => {
    const badMax = await invokeCli([
      'verify-batch',
      '--input',
      tempDir,
      '--contract-id',
      CONTRACT_ID,
      '--max-items',
      '65',
    ])
    expect(badMax.code).toBe(2)
    expect(badMax.stdout).toBe('')

    stdoutChunks = []
    stderrChunks = []
    const conflict = await invokeCli([
      'verify',
      '--manifest',
      'a.json',
      '--batch',
      tempDir,
      '--contract-id',
      CONTRACT_ID,
    ])
    expect(conflict.code).toBe(2)
    expect(conflict.stdout).toBe('')
  })
})
