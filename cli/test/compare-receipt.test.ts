import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  compareReceipts,
  formatComparisonResult,
  normalizeReceipt,
  parseReceiptInput,
  type ReceiptComparisonResult,
} from '../src/compare-receipt.js'
import { createReceipt, type VerificationReceipt } from '../src/receipt.js'
import { createProofManifest, type ProofManifest } from '../src/manifest.js'
import { encodeReceiptForQr, type SignedVerificationReceipt } from '../src/signed-receipt.js'
import { main } from '../src/cli.js'

function H64(hexPrefix: string): string {
  return hexPrefix.padEnd(64, '0')
}

function makeManifest(overrides: Partial<ProofManifest> = {}): ProofManifest {
  return createProofManifest({
    proofId: H64('1111'),
    videoHash: H64('2222'),
    metadataHash: H64('3333'),
    sourceHash: H64('4444'),
    contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
    transactionRef: H64('5555'),
    tier: 'silent',
    network: 'Test SDF Network ; September 2015',
    timestamp: '2026-11-20T12:00:00.000Z',
    verifierScope: '0',
    epoch: 1,
    scopeName: 'test-scope',
    ...overrides,
  })
}

function makeReceipt(
  result: VerificationReceipt['result'] = 'valid',
  manifestOverrides: Partial<ProofManifest> = {},
): VerificationReceipt {
  const manifest = makeManifest(manifestOverrides)
  return createReceipt(
    manifest,
    {
      status: 'confirmed',
      txHash: manifest.transactionRef,
      ledger: 1000,
      createdAt: '2026-11-20T12:00:00.000Z',
      contractMatch: true,
    },
    {
      videoHash: manifest.videoHash,
      metadataHash: manifest.metadataHash,
      tier: manifest.tier,
      status: 'valid',
      createdAt: '2026-11-20T12:00:00.000Z',
      expiresAt: '2027-11-20T12:00:00.000Z',
      source: manifest.sourceHash ?? '',
      issuer: 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
    },
    result,
  )
}

function makeSignedReceipt(overrides: Partial<SignedVerificationReceipt> = {}): SignedVerificationReceipt {
  return {
    protocol: 'harpocrates-verification-receipt',
    version: 1,
    result: 'verified',
    verifiedAt: '2026-11-20T12:00:00.000Z',
    proofId: H64('1111'),
    videoHash: H64('2222'),
    metadataHash: H64('3333'),
    tier: 'silent',
    networkPassphrase: 'Test SDF Network ; September 2015',
    contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
    ledgerSequence: 1000,
    transactionHash: H64('5555'),
    circuitVersion: '1.0.0',
    verifierVersion: '1.0.0',
    signer: {
      keyId: 'key-1',
      algorithm: 'ECDSA_P256_SHA256',
    },
    signature: 'fake-sig',
    ...overrides,
  }
}

describe('normalizeReceipt and parseReceiptInput', () => {
  it('parses valid JSON string', () => {
    const receipt = makeReceipt()
    const parsed = parseReceiptInput(JSON.stringify(receipt))
    expect(parsed).toEqual(receipt)
  })

  it('decodes QR payload string', () => {
    const signed = makeSignedReceipt()
    const qr = encodeReceiptForQr(signed)
    const parsed = parseReceiptInput(qr)
    expect(parsed).toEqual(signed)
  })

  it('rejects empty input', () => {
    expect(() => parseReceiptInput('')).toThrow('empty receipt content')
    expect(() => parseReceiptInput('   ')).toThrow('empty receipt content')
  })

  it('rejects invalid JSON', () => {
    expect(() => parseReceiptInput('{ invalid json')).toThrow('invalid receipt JSON')
  })

  it('rejects non-object values', () => {
    expect(() => normalizeReceipt('hello')).toThrow('receipt must be a valid JSON object')
    expect(() => normalizeReceipt(123)).toThrow('receipt must be a valid JSON object')
  })
})

describe('compareReceipts', () => {
  describe('matching receipts', () => {
    it('reports identical for two identical VerificationReceipt objects', () => {
      const a = makeReceipt('valid')
      const b = makeReceipt('valid')
      const diff = compareReceipts(a, b)

      expect(diff.match).toBe(true)
      expect(diff.statementMatch).toBe(true)
      expect(diff.trustMatch).toBe(true)
      expect(diff.differences).toHaveLength(0)
      expect(diff.statementDifferences).toHaveLength(0)
      expect(diff.trustDifferences).toHaveLength(0)
      expect(diff.summary.totalDifferences).toBe(0)
    })

    it('reports identical for two identical SignedVerificationReceipt objects', () => {
      const a = makeSignedReceipt()
      const b = makeSignedReceipt()
      const diff = compareReceipts(a, b)

      expect(diff.match).toBe(true)
      expect(diff.statementMatch).toBe(true)
      expect(diff.trustMatch).toBe(true)
      expect(diff.differences).toHaveLength(0)
    })

    it('normalizes hex cases and 0x prefixes', () => {
      const a = makeReceipt('valid', { videoHash: H64('aaaa') })
      const b = makeReceipt('valid', { videoHash: `0x${H64('AAAA')}` })
      const diff = compareReceipts(a, b)

      expect(diff.statementMatch).toBe(true)
    })

    it('normalizes network aliases (e.g. testnet vs full passphrase)', () => {
      const a = makeReceipt('valid', { network: 'testnet' })
      const b = makeReceipt('valid', { network: 'Test SDF Network ; September 2015' })
      const diff = compareReceipts(a, b)

      expect(diff.trustMatch).toBe(true)
    })
  })

  describe('canonical statement differences', () => {
    it('detects mismatched videoHash', () => {
      const a = makeReceipt('valid', { videoHash: H64('1111') })
      const b = makeReceipt('valid', { videoHash: H64('9999') })
      const diff = compareReceipts(a, b)

      expect(diff.match).toBe(false)
      expect(diff.statementMatch).toBe(false)
      expect(diff.trustMatch).toBe(true)
      expect(diff.statementDifferences).toEqual([
        {
          category: 'statement',
          field: 'videoHash',
          base: H64('1111'),
          target: H64('9999'),
        },
      ])
    })

    it('detects mismatched metadataHash', () => {
      const a = makeReceipt('valid', { metadataHash: H64('2222') })
      const b = makeReceipt('valid', { metadataHash: H64('8888') })
      const diff = compareReceipts(a, b)

      expect(diff.statementMatch).toBe(false)
      expect(diff.statementDifferences.some((d) => d.field === 'metadataHash')).toBe(true)
    })

    it('detects mismatched tier', () => {
      const a = makeReceipt('valid', { tier: 'silent' })
      const b = makeReceipt('valid', { tier: 'source' })
      const diff = compareReceipts(a, b)

      expect(diff.statementMatch).toBe(false)
      expect(diff.statementDifferences).toContainEqual({
        category: 'statement',
        field: 'tier',
        base: 'silent',
        target: 'source',
      })
    })

    it('detects mismatched proofId', () => {
      const a = makeReceipt('valid', { proofId: H64('aaaa') })
      const b = makeReceipt('valid', { proofId: H64('bbbb') })
      const diff = compareReceipts(a, b)

      expect(diff.statementMatch).toBe(false)
      expect(diff.statementDifferences.some((d) => d.field === 'proofId')).toBe(true)
    })

    it('detects mismatched circuitVersion on signed receipts', () => {
      const a = makeSignedReceipt({ circuitVersion: '1.0.0' })
      const b = makeSignedReceipt({ circuitVersion: '2.0.0' })
      const diff = compareReceipts(a, b)

      expect(diff.statementMatch).toBe(false)
      expect(diff.statementDifferences).toContainEqual({
        category: 'statement',
        field: 'circuitVersion',
        base: '1.0.0',
        target: '2.0.0',
      })
    })

    it('detects mismatched verifierScope and epoch', () => {
      const a = makeReceipt('valid', { verifierScope: '0', epoch: 1 })
      const b = makeReceipt('valid', { verifierScope: '1', epoch: 2 })
      const diff = compareReceipts(a, b)

      expect(diff.statementMatch).toBe(false)
      expect(diff.statementDifferences.some((d) => d.field === 'verifierScope')).toBe(true)
      expect(diff.statementDifferences.some((d) => d.field === 'epoch')).toBe(true)
    })
  })

  describe('trust differences', () => {
    it('detects mismatched network (e.g. testnet vs mainnet)', () => {
      const a = makeReceipt('valid', { network: 'testnet' })
      const b = makeReceipt('valid', { network: 'public' })
      const diff = compareReceipts(a, b)

      expect(diff.match).toBe(false)
      expect(diff.statementMatch).toBe(true)
      expect(diff.trustMatch).toBe(false)
      expect(diff.trustDifferences.some((d) => d.field === 'network')).toBe(true)
    })

    it('detects mismatched contractId', () => {
      const a = makeReceipt('valid', { contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' })
      const b = makeReceipt('valid', { contractId: 'CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' })
      const diff = compareReceipts(a, b)

      expect(diff.trustMatch).toBe(false)
      expect(diff.trustDifferences.some((d) => d.field === 'contractId')).toBe(true)
    })

    it('detects verification outcome mismatch (valid vs revoked)', () => {
      const a = makeReceipt('valid')
      const b = makeReceipt('revoked')
      const diff = compareReceipts(a, b)

      expect(diff.trustMatch).toBe(false)
      expect(diff.trustDifferences).toContainEqual({
        category: 'trust',
        field: 'result',
        base: 'valid',
        target: 'revoked',
      })
    })

    it('detects signer mismatch on signed receipts', () => {
      const a = makeSignedReceipt({ signer: { keyId: 'key-alpha', algorithm: 'ECDSA_P256_SHA256' } })
      const b = makeSignedReceipt({ signer: { keyId: 'key-beta', algorithm: 'ECDSA_P256_SHA256' } })
      const diff = compareReceipts(a, b)

      expect(diff.trustMatch).toBe(false)
      expect(diff.trustDifferences).toContainEqual({
        category: 'trust',
        field: 'signerKeyId',
        base: 'key-alpha',
        target: 'key-beta',
      })
    })

    it('detects transactionHash mismatch', () => {
      const a = makeSignedReceipt({ transactionHash: H64('1111') })
      const b = makeSignedReceipt({ transactionHash: H64('2222') })
      const diff = compareReceipts(a, b)

      expect(diff.trustMatch).toBe(false)
      expect(diff.trustDifferences.some((d) => d.field === 'transactionHash')).toBe(true)
    })
  })

  describe('combined statement and trust differences', () => {
    it('reports both statement and trust differences simultaneously', () => {
      const a = makeReceipt('valid', { videoHash: H64('1111'), network: 'testnet' })
      const b = makeReceipt('revoked', { videoHash: H64('2222'), network: 'public' })
      const diff = compareReceipts(a, b)

      expect(diff.match).toBe(false)
      expect(diff.statementMatch).toBe(false)
      expect(diff.trustMatch).toBe(false)
      expect(diff.summary.totalDifferences).toBe(diff.differences.length)
      expect(diff.summary.statementDifferencesCount).toBe(diff.statementDifferences.length)
      expect(diff.summary.trustDifferencesCount).toBe(diff.trustDifferences.length)
    })
  })
})

describe('formatComparisonResult', () => {
  it('formats matching comparison cleanly', () => {
    const a = makeReceipt('valid')
    const diff = compareReceipts(a, a)
    const text = formatComparisonResult(diff)

    expect(text).toContain('✅ IDENTICAL')
    expect(text).toContain('Canonical Statement: ✅ MATCH')
    expect(text).toContain('Trust & Environment: ✅ MATCH')
    expect(text).toContain('Overall match:   YES')
  })

  it('formats mismatch with both categories', () => {
    const a = makeReceipt('valid', { videoHash: H64('1111') })
    const b = makeReceipt('revoked', { videoHash: H64('2222') })
    const diff = compareReceipts(a, b)
    const text = formatComparisonResult(diff)

    expect(text).toContain('❌ DIFFERENCES DETECTED')
    expect(text).toContain('Canonical Statement: ❌ MISMATCH')
    expect(text).toContain('videoHash')
    expect(text).toContain('Trust & Environment: ❌ MISMATCH')
    expect(text).toContain('result')
  })
})

describe('CLI main dispatcher handling compare-receipt', () => {
  let tempDir: string
  let stdoutChunks: string[]
  let stderrChunks: string[]
  let exitCode: number | null

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'compare-cli-test-'))
    stdoutChunks = []
    stderrChunks = []
    exitCode = null

    vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: any) => {
      stdoutChunks.push(String(chunk))
      return true
    }) as any)

    vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: any) => {
      stderrChunks.push(String(chunk))
      return true
    }) as any)

    vi.spyOn(process, 'exit').mockImplementation(((code?: any) => {
      exitCode = typeof code === 'number' ? code : 0
      throw new Error(`process.exit: ${exitCode}`)
    }) as any)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    try {
      rmSync(tempDir, { recursive: true, force: true })
    } catch {
      // ignore
    }
  })

  async function invokeMain(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
    try {
      await main(args)
      return { stdout: stdoutChunks.join(''), stderr: stderrChunks.join(''), code: 0 }
    } catch (err: any) {
      if (err.message.startsWith('process.exit:')) {
        return { stdout: stdoutChunks.join(''), stderr: stderrChunks.join(''), code: exitCode ?? 0 }
      }
      throw err
    }
  }

  it('exits 0 when receipts match completely (text format)', async () => {
    const r1 = makeReceipt('valid')
    const path1 = join(tempDir, 'r1.json')
    const path2 = join(tempDir, 'r2.json')
    writeFileSync(path1, JSON.stringify(r1))
    writeFileSync(path2, JSON.stringify(r1))

    const res = await invokeMain(['compare-receipt', '--base', path1, '--target', path2])
    expect(res.code).toBe(0)
    expect(res.stdout).toContain('✅ IDENTICAL')
    expect(res.stdout).toContain('Canonical Statement: ✅ MATCH')
    expect(res.stdout).toContain('Trust & Environment: ✅ MATCH')
  })

  it('exits 0 and emits deterministic JSON with --output json', async () => {
    const r1 = makeReceipt('valid')
    const path1 = join(tempDir, 'r1.json')
    const path2 = join(tempDir, 'r2.json')
    writeFileSync(path1, JSON.stringify(r1))
    writeFileSync(path2, JSON.stringify(r1))

    const res = await invokeMain(['compare-receipt', '-b', path1, '-t', path2, '-o', 'json'])
    expect(res.code).toBe(0)
    const parsed: ReceiptComparisonResult = JSON.parse(res.stdout)
    expect(parsed.match).toBe(true)
    expect(parsed.statementMatch).toBe(true)
    expect(parsed.trustMatch).toBe(true)
    expect(parsed.differences).toEqual([])
  })

  it('exits 1 when differences exist between receipts', async () => {
    const r1 = makeReceipt('valid', { videoHash: H64('1111') })
    const r2 = makeReceipt('revoked', { videoHash: H64('2222') })
    const path1 = join(tempDir, 'r1.json')
    const path2 = join(tempDir, 'r2.json')
    writeFileSync(path1, JSON.stringify(r1))
    writeFileSync(path2, JSON.stringify(r2))

    const res = await invokeMain(['compare-receipt', '--base', path1, '--target', path2, '--output', 'json'])
    expect(res.code).toBe(1)
    const parsed: ReceiptComparisonResult = JSON.parse(res.stdout)
    expect(parsed.match).toBe(false)
    expect(parsed.statementMatch).toBe(false)
    expect(parsed.trustMatch).toBe(false)
    expect(parsed.statementDifferences.some((d) => d.field === 'videoHash')).toBe(true)
    expect(parsed.trustDifferences.some((d) => d.field === 'result')).toBe(true)
  })

  it('works with positional arguments', async () => {
    const r1 = makeReceipt('valid')
    const path1 = join(tempDir, 'r1.json')
    const path2 = join(tempDir, 'r2.json')
    writeFileSync(path1, JSON.stringify(r1))
    writeFileSync(path2, JSON.stringify(r1))

    const res = await invokeMain(['compare-receipt', path1, path2])
    expect(res.code).toBe(0)
    expect(res.stdout).toContain('✅ IDENTICAL')
  })

  it('works with compare alias', async () => {
    const r1 = makeReceipt('valid')
    const path1 = join(tempDir, 'r1.json')
    const path2 = join(tempDir, 'r2.json')
    writeFileSync(path1, JSON.stringify(r1))
    writeFileSync(path2, JSON.stringify(r1))

    const res = await invokeMain(['compare', '--base', path1, '--target', path2])
    expect(res.code).toBe(0)
  })

  it('exits 2 for missing arguments', async () => {
    const res = await invokeMain(['compare-receipt'])
    expect(res.code).toBe(2)
    expect(res.stderr).toContain('--base and --target are required')
  })

  it('exits 2 for invalid --output format', async () => {
    const path1 = join(tempDir, 'r1.json')
    const path2 = join(tempDir, 'r2.json')
    writeFileSync(path1, '{}')
    writeFileSync(path2, '{}')

    const res = await invokeMain(['compare-receipt', '-b', path1, '-t', path2, '-o', 'yaml'])
    expect(res.code).toBe(2)
    expect(res.stderr).toContain('invalid value "yaml" for --output')
  })

  it('exits 8 for missing input file', async () => {
    const res = await invokeMain(['compare-receipt', '-b', 'nonexistent-a.json', '-t', 'nonexistent-b.json'])
    expect(res.code).toBe(8)
    expect(res.stderr).toContain('failed to read base receipt')
  })

  it('exits 8 for invalid receipt JSON', async () => {
    const path1 = join(tempDir, 'r1.json')
    const path2 = join(tempDir, 'r2.json')
    writeFileSync(path1, '{ broken json')
    writeFileSync(path2, '{}')

    const res = await invokeMain(['compare-receipt', '-b', path1, '-t', path2])
    expect(res.code).toBe(8)
    expect(res.stderr).toContain('invalid base receipt')
  })
})

describe('CLI compare-receipt compiled bundle e2e', { timeout: 30000 }, () => {
  const cliPath = resolve(__dirname, '../dist/cli.js')
  let tempDir: string

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'compare-bundle-test-'))
  })

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true })
    } catch {
      // ignore
    }
  })

  it('executes dist/cli.js and exits 0 on match', () => {
    const r1 = makeReceipt('valid')
    const path1 = join(tempDir, 'r1.json')
    const path2 = join(tempDir, 'r2.json')
    writeFileSync(path1, JSON.stringify(r1))
    writeFileSync(path2, JSON.stringify(r1))

    const res = spawnSync(process.execPath, [cliPath, 'compare-receipt', path1, path2], {
      encoding: 'utf-8',
    })
    expect(res.status).toBe(0)
    expect(res.stdout).toContain('✅ IDENTICAL')
  })

  it('executes dist/cli.js and exits 1 on mismatch with json output', () => {
    const r1 = makeReceipt('valid', { videoHash: H64('1111') })
    const r2 = makeReceipt('valid', { videoHash: H64('2222') })
    const path1 = join(tempDir, 'r1.json')
    const path2 = join(tempDir, 'r2.json')
    writeFileSync(path1, JSON.stringify(r1))
    writeFileSync(path2, JSON.stringify(r2))

    const res = spawnSync(process.execPath, [cliPath, 'compare-receipt', '-b', path1, '-t', path2, '-o', 'json'], {
      encoding: 'utf-8',
    })
    expect(res.status).toBe(1)
    const parsed = JSON.parse(res.stdout)
    expect(parsed.match).toBe(false)
    expect(parsed.statementDifferences.some((d: any) => d.field === 'videoHash')).toBe(true)
  })
})
