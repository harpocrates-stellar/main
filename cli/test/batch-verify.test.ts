vi.mock('../src/register.js', () => ({
  handleRegister: vi.fn(),
}))
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { StrKey } from '@stellar/stellar-sdk'
import { verifyManifest, main, MAX_BATCH_SIZE } from '../src/cli.js'
import { createProofManifest, serializeManifest } from '../src/manifest.js'
import * as stellarLookup from '../src/stellar-lookup.js'

const contractBytes = Uint8Array.from({ length: 32 }, (_, index) => index)
const contractId = StrKey.encodeContract(contractBytes)
const otherContractBytes = Uint8Array.from({ length: 32 }, () => 9)
const otherContractId = StrKey.encodeContract(otherContractBytes)

function makeSampleManifest(overrides: Partial<Parameters<typeof createProofManifest>[0]> = {}) {
  return createProofManifest({
    proofId: 'a'.repeat(64),
    tier: 'silent',
    network: 'Test SDF Network ; September 2015',
    contractId,
    transactionRef: 'b'.repeat(64),
    videoHash: 'c'.repeat(64),
    metadataHash: 'd'.repeat(64),
    sourceHash: 'e'.repeat(64),
    timestamp: '2026-07-24T12:00:00.000Z',
    ...overrides,
  })
}

describe('verifyManifest single-manifest flow', () => {
  it('returns pending receipt in offline mode', async () => {
    const manifest = makeSampleManifest()
    const receipt = await verifyManifest(manifest, {
      contractId,
      offline: true,
    })
    expect(receipt.result).toBe('pending')
    expect(receipt.manifest.proofId).toBe(manifest.proofId)
    expect(receipt.transaction.status).toBe('pending')
  })

  it('rejects contract mismatch with exitCode 5', async () => {
    const manifest = makeSampleManifest({ contractId: otherContractId })
    await expect(
      verifyManifest(manifest, {
        contractId,
        offline: true,
      }),
    ).rejects.toMatchObject({
      exitCode: 5,
      result: 'contract_mismatch',
    })
  })

  it('rejects network mismatch with exitCode 4', async () => {
    const manifest = makeSampleManifest({ network: 'Custom Network' })
    await expect(
      verifyManifest(manifest, {
        contractId,
        offline: true,
      }),
    ).rejects.toMatchObject({
      exitCode: 4,
      result: 'network_mismatch',
    })
  })

  it('rejects transaction hash mismatch with exitCode 8', async () => {
    const manifest = makeSampleManifest()
    await expect(
      verifyManifest(manifest, {
        contractId,
        txHash: 'f'.repeat(64),
        offline: true,
      }),
    ).rejects.toMatchObject({
      exitCode: 8,
    })
  })

  it('rejects invalid or unreadable string manifest with exitCode 8', async () => {
    await expect(
      verifyManifest('not-a-valid-json', {
        contractId,
        offline: true,
      }),
    ).rejects.toMatchObject({
      exitCode: 8,
    })
  })

  it('verifies against mocked on-chain lookup', async () => {
    const manifest = makeSampleManifest()
    const verifyTransactionSpy = vi.spyOn(stellarLookup, 'verifyTransaction').mockResolvedValueOnce({
      status: 'confirmed',
      txHash: manifest.transactionRef,
      contractMatch: true,
    })
    const lookupByVideoHashSpy = vi.spyOn(stellarLookup, 'lookupByVideoHash').mockResolvedValueOnce({
      videoHash: manifest.videoHash,
      metadataHash: manifest.metadataHash,
      tier: 1,
      status: 1,
      createdAt: '1234567890',
      source: null,
      issuer: null,
    })

    const receipt = await verifyManifest(serializeManifest(manifest), {
      contractId,
    })
    expect(receipt.result).toBe('valid')
    expect(verifyTransactionSpy).toHaveBeenCalled()
    expect(lookupByVideoHashSpy).toHaveBeenCalled()

    verifyTransactionSpy.mockRestore()
    lookupByVideoHashSpy.mockRestore()
  })
})

describe('batch verification (--manifests)', () => {
  let tempDir: string

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'batch-verify-test-'))
  })

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true })
    vi.restoreAllMocks()
  })

  it('processes all manifests and outputs JSON lines when --output jsonl is used', async () => {
    const m1 = makeSampleManifest({ proofId: '1'.repeat(64), videoHash: '1'.repeat(64), transactionRef: 'a'.repeat(64) })
    const m2 = makeSampleManifest({ proofId: '2'.repeat(64), videoHash: '2'.repeat(64), transactionRef: 'b'.repeat(64) })
    const m3 = makeSampleManifest({ proofId: '3'.repeat(64), videoHash: '3'.repeat(64), transactionRef: 'c'.repeat(64) })

    await writeFile(join(tempDir, '01-first.json'), serializeManifest(m1))
    await writeFile(join(tempDir, '02-second.json'), serializeManifest(m2))
    await writeFile(join(tempDir, '03-third.json'), serializeManifest(m3))

    vi.spyOn(stellarLookup, 'verifyTransaction').mockImplementation(async (txHash) => ({
      status: 'confirmed',
      txHash,
      contractMatch: true,
    }))

    vi.spyOn(stellarLookup, 'lookupByVideoHash').mockImplementation(async (_contract, videoHash) => ({
      videoHash,
      metadataHash: 'd'.repeat(64),
      tier: 1,
      status: 1,
      createdAt: '100',
      source: null,
      issuer: null,
    }))

    const stdoutLines: string[] = []
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      stdoutLines.push(String(chunk))
      return true
    })

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null) => {
      throw new Error(`EXIT_${code}`)
    })

    await expect(
      main([
        'verify',
        '--contract-id', contractId,
        '--manifests', tempDir,
        '--output', 'jsonl',
      ]),
    ).rejects.toThrow('EXIT_0')

    stdoutSpy.mockRestore()
    exitSpy.mockRestore()

    const rawOutput = stdoutLines.join('')
    const lines = rawOutput.trim().split('\n').map((l) => JSON.parse(l))
    expect(lines).toHaveLength(3)
    expect(lines[0].file).toBe('01-first.json')
    expect(lines[0].result).toBe('valid')
    expect(lines[1].file).toBe('02-second.json')
    expect(lines[1].result).toBe('valid')
    expect(lines[2].file).toBe('03-third.json')
    expect(lines[2].result).toBe('valid')
  })

  it('respects concurrency cap and maintains order across workers', async () => {
    let activeWorkers = 0
    let peakConcurrency = 0

    const manifestFiles: string[] = []
    for (let i = 0; i < 8; i++) {
      const fileName = `manifest-${String(i).padStart(2, '0')}.json`
      const m = makeSampleManifest({
        proofId: String(i).repeat(64),
        videoHash: String(i).repeat(64),
        transactionRef: String(i).repeat(64),
      })
      await writeFile(join(tempDir, fileName), serializeManifest(m))
      manifestFiles.push(fileName)
    }

    vi.spyOn(stellarLookup, 'verifyTransaction').mockImplementation(async (txHash) => {
      activeWorkers++
      if (activeWorkers > peakConcurrency) peakConcurrency = activeWorkers
      await new Promise((r) => setTimeout(r, 20))
      activeWorkers--
      return { status: 'confirmed', txHash, contractMatch: true }
    })

    vi.spyOn(stellarLookup, 'lookupByVideoHash').mockImplementation(async (_contract, videoHash) => ({
      videoHash,
      metadataHash: 'd'.repeat(64),
      tier: 1,
      status: 1,
      createdAt: '100',
      source: null,
      issuer: null,
    }))

    const stdoutLines: string[] = []
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      stdoutLines.push(String(chunk))
      return true
    })
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null) => {
      throw new Error(`EXIT_${code}`)
    })

    await expect(
      main([
        'verify',
        '--contract-id', contractId,
        '--manifests', tempDir,
        '--concurrency', '3',
        '--output', 'json',
      ]),
    ).rejects.toThrow('EXIT_0')

    expect(peakConcurrency).toBeLessThanOrEqual(3)

    const fullOutput = JSON.parse(stdoutLines.join(''))
    expect(fullOutput.total).toBe(8)
    expect(fullOutput.counts.valid).toBe(8)
    expect(fullOutput.allVerified).toBe(true)
    expect(fullOutput.items.map((it: { file: string }) => it.file)).toEqual(manifestFiles)

    exitSpy.mockRestore()
  })

  it('prints a summary and exits non-zero (exit 1) if any item is not verified', async () => {
    const mValid = makeSampleManifest({ proofId: '1'.repeat(64), videoHash: '1'.repeat(64), transactionRef: 'a'.repeat(64) })
    const mRevoked = makeSampleManifest({ proofId: '2'.repeat(64), videoHash: '2'.repeat(64), transactionRef: 'b'.repeat(64) })

    await writeFile(join(tempDir, '01-valid.json'), serializeManifest(mValid))
    await writeFile(join(tempDir, '02-revoked.json'), serializeManifest(mRevoked))

    vi.spyOn(stellarLookup, 'verifyTransaction').mockImplementation(async (txHash) => ({
      status: 'confirmed',
      txHash,
      contractMatch: true,
    }))

    vi.spyOn(stellarLookup, 'lookupByVideoHash').mockImplementation(async (_contract, videoHash) => {
      const isRevoked = videoHash === '2'.repeat(64)
      return {
        videoHash,
        metadataHash: 'd'.repeat(64),
        tier: 1,
        status: isRevoked ? 2 : 1, // status 2 = revoked
        createdAt: '100',
        source: null,
        issuer: null,
      }
    })

    const stdoutLines: string[] = []
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      stdoutLines.push(String(chunk))
      return true
    })

    let exitCode: number | undefined
    vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null) => {
      exitCode = typeof code === 'number' ? code : Number(code)
      throw new Error(`EXIT_${code}`)
    })

    await expect(
      main([
        'verify',
        '--contract-id', contractId,
        '--manifests', tempDir,
      ]),
    ).rejects.toThrow('EXIT_1')

    expect(exitCode).toBe(1)
    const summaryText = stdoutLines.join('')
    expect(summaryText).toContain('Harpocrates Batch Verification Summary')
    expect(summaryText).toContain('Total items:     2')
    expect(summaryText).toContain('Valid:           1')
    expect(summaryText).toContain('Revoked:         1')
  })

  it('enforces maximum 1 MiB per-manifest limit', async () => {
    const oversized = Buffer.alloc(1024 * 1024 + 10, 'a')
    await writeFile(join(tempDir, 'oversized.json'), oversized)

    const stdoutLines: string[] = []
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      stdoutLines.push(String(chunk))
      return true
    })

    vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null) => {
      throw new Error(`EXIT_${code}`)
    })

    await expect(
      main([
        'verify',
        '--contract-id', contractId,
        '--manifests', tempDir,
        '--output', 'jsonl',
      ]),
    ).rejects.toThrow('EXIT_1')

    const line = JSON.parse(stdoutLines.join('').trim())
    expect(line.file).toBe('oversized.json')
    expect(line.result).toBe('error')
    expect(line.error).toContain('1 MiB')
  })

  it('rejects invalid --concurrency values with exitCode 2', async () => {
    let exitMsg = ''
    vi.spyOn(process.stderr, 'write').mockImplementation((msg) => {
      exitMsg += String(msg)
      return true
    })
    vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null) => {
      throw new Error(`EXIT_${code}`)
    })

    await expect(
      main([
        'verify',
        '--contract-id', contractId,
        '--manifests', tempDir,
        '--concurrency', '0',
      ]),
    ).rejects.toThrow('EXIT_2')

    expect(exitMsg).toContain('--concurrency')

    await expect(
      main([
        'verify',
        '--contract-id', contractId,
        '--manifests', tempDir,
        '--concurrency', '17',
      ]),
    ).rejects.toThrow('EXIT_2')
  })
})
