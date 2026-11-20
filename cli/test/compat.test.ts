import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Networks, StrKey } from '@stellar/stellar-sdk'
import { createProofManifest, serializeManifest } from '../src/manifest.js'
import {
  checkCompatibility,
  formatCompatReport,
  runCheckCompat,
  COMPAT_EXIT_CODES,
} from '../src/compat.js'
import { parseCliArgs, CliUsageError } from '../src/args.js'

const CONTRACT_A = StrKey.encodeContract(Uint8Array.from({ length: 32 }, (_, i) => i + 1))
const CONTRACT_B = StrKey.encodeContract(Uint8Array.from({ length: 32 }, (_, i) => i + 33))
const HEX_32 = 'ab'.repeat(32)

function makeManifest(overrides: Partial<Parameters<typeof createProofManifest>[0]> = {}) {
  return createProofManifest({
    proofId: HEX_32,
    tier: 'silent',
    network: Networks.TESTNET,
    contractId: CONTRACT_A,
    transactionRef: 'cd'.repeat(32),
    videoHash: 'ef'.repeat(32),
    metadataHash: '12'.repeat(32),
    sourceHash: '34'.repeat(32),
    timestamp: '2026-01-15T12:00:00.000Z',
    ...overrides,
  })
}

describe('checkCompatibility', () => {
  it('returns compatible when network and contract match', () => {
    const manifest = makeManifest()
    const report = checkCompatibility(manifest, {
      contractId: CONTRACT_A,
      network: Networks.TESTNET,
    })

    expect(report).toEqual({
      compatible: true,
      status: 'compatible',
      network: {
        match: true,
        bundle: Networks.TESTNET,
        selected: Networks.TESTNET,
      },
      contractId: {
        match: true,
        bundle: CONTRACT_A,
        selected: CONTRACT_A,
      },
      manifestVersion: 2,
      protocol: 'harpocrates',
      tier: 'silent',
      proofId: HEX_32,
    })
    expect(COMPAT_EXIT_CODES[report.status]).toBe(0)
  })

  it('resolves network aliases when comparing', () => {
    const manifest = makeManifest({ network: Networks.PUBLIC })
    const report = checkCompatibility(manifest, {
      contractId: CONTRACT_A,
      network: 'mainnet',
    })

    expect(report.compatible).toBe(true)
    expect(report.status).toBe('compatible')
    expect(report.network.selected).toBe(Networks.PUBLIC)
  })

  it('detects network_mismatch', () => {
    const manifest = makeManifest({ network: Networks.PUBLIC })
    const report = checkCompatibility(manifest, {
      contractId: CONTRACT_A,
      network: 'testnet',
    })

    expect(report.compatible).toBe(false)
    expect(report.status).toBe('network_mismatch')
    expect(report.network.match).toBe(false)
    expect(report.contractId.match).toBe(true)
    expect(COMPAT_EXIT_CODES[report.status]).toBe(4)
  })

  it('detects contract_mismatch', () => {
    const manifest = makeManifest({ contractId: CONTRACT_A })
    const report = checkCompatibility(manifest, {
      contractId: CONTRACT_B,
      network: 'testnet',
    })

    expect(report.compatible).toBe(false)
    expect(report.status).toBe('contract_mismatch')
    expect(report.network.match).toBe(true)
    expect(report.contractId.match).toBe(false)
    expect(COMPAT_EXIT_CODES[report.status]).toBe(5)
  })

  it('detects incompatible when both network and contract mismatch', () => {
    const manifest = makeManifest({
      network: Networks.PUBLIC,
      contractId: CONTRACT_A,
    })
    const report = checkCompatibility(manifest, {
      contractId: CONTRACT_B,
      network: 'testnet',
    })

    expect(report.compatible).toBe(false)
    expect(report.status).toBe('incompatible')
    expect(report.network.match).toBe(false)
    expect(report.contractId.match).toBe(false)
    expect(COMPAT_EXIT_CODES[report.status]).toBe(5)
  })

  it('formats compatible and mismatched reports cleanly', () => {
    const okText = formatCompatReport(
      checkCompatibility(makeManifest(), {
        contractId: CONTRACT_A,
        network: 'testnet',
      }),
    )
    expect(okText).toContain('Compatibility: compatible')
    expect(okText).toContain(`Network:       MATCH (${Networks.TESTNET})`)
    expect(okText).toContain(`Contract:      MATCH (${CONTRACT_A})`)

    const mismatchText = formatCompatReport(
      checkCompatibility(makeManifest({ network: Networks.PUBLIC }), {
        contractId: CONTRACT_B,
        network: 'testnet',
      }),
    )
    expect(mismatchText).toContain('Compatibility: incompatible')
    expect(mismatchText).toContain(`Network:       MISMATCH (bundle: ${Networks.PUBLIC}, selected: ${Networks.TESTNET})`)
    expect(mismatchText).toContain(`Contract:      MISMATCH (bundle: ${CONTRACT_A}, selected: ${CONTRACT_B})`)
  })
})

describe('check-compat CLI argument parsing and execution', () => {
  let tmpDir: string
  let manifestPath: string
  let stdoutChunks: string[]
  let stderrChunks: string[]
  const originalContractEnv = process.env.HARPOCRATES_CONTRACT_ID

  const makeIo = () => ({
    readText: async (path: string) => readFileSync(path, 'utf-8'),
    writeStdout: (text: string) => {
      stdoutChunks.push(text)
    },
    writeStderr: (text: string) => {
      stderrChunks.push(text)
    },
  })

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'harpocrates-compat-'))
    manifestPath = join(tmpDir, 'manifest.json')
    writeFileSync(manifestPath, serializeManifest(makeManifest()), 'utf-8')
    stdoutChunks = []
    stderrChunks = []
    delete process.env.HARPOCRATES_CONTRACT_ID
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
    if (originalContractEnv === undefined) {
      delete process.env.HARPOCRATES_CONTRACT_ID
    } else {
      process.env.HARPOCRATES_CONTRACT_ID = originalContractEnv
    }
  })

  it('parses check-compat flags and rejects unknown options', () => {
    const parsed = parseCliArgs([
      'check-compat',
      '-m',
      manifestPath,
      '--contract-id',
      CONTRACT_A,
      '--network',
      'testnet',
      '-o',
      'json',
    ])
    expect(parsed.command).toBe('check-compat')
    expect(parsed.flags.manifest).toBe(manifestPath)
    expect(parsed.flags['contract-id']).toBe(CONTRACT_A)
    expect(parsed.flags.network).toBe('testnet')
    expect(parsed.flags.output).toBe('json')

    expect(() =>
      parseCliArgs(['check-compat', '--unknown-flag', '1']),
    ).toThrow(CliUsageError)
  })

  it('exits 0 with JSON output when manifest matches selected config', async () => {
    const parsed = parseCliArgs([
      'check-compat',
      '--manifest',
      manifestPath,
      '--contract-id',
      CONTRACT_A,
      '--network',
      'testnet',
      '--output',
      'json',
    ])
    const code = await runCheckCompat(parsed.flags, makeIo())

    expect(code).toBe(0)
    const report = JSON.parse(stdoutChunks.join(''))
    expect(report.compatible).toBe(true)
    expect(report.status).toBe('compatible')
    expect(report.contractId.match).toBe(true)
    expect(report.network.match).toBe(true)
  })

  it('exits 4 on network_mismatch', async () => {
    const parsed = parseCliArgs([
      'check-compat',
      '-m',
      manifestPath,
      '--contract-id',
      CONTRACT_A,
      '--network',
      'mainnet',
      '-o',
      'json',
    ])
    const code = await runCheckCompat(parsed.flags, makeIo())

    expect(code).toBe(4)
    const report = JSON.parse(stdoutChunks.join(''))
    expect(report.compatible).toBe(false)
    expect(report.status).toBe('network_mismatch')
  })

  it('exits 5 on contract_mismatch with text output', async () => {
    const parsed = parseCliArgs([
      'check-compat',
      '--manifest',
      manifestPath,
      '--contract-id',
      CONTRACT_B,
      '--network',
      'testnet',
    ])
    const code = await runCheckCompat(parsed.flags, makeIo())

    expect(code).toBe(5)
    expect(stdoutChunks.join('')).toContain('Compatibility: contract_mismatch')
  })

  it('exits 5 with status incompatible when both network and contract mismatch', async () => {
    const parsed = parseCliArgs([
      'check-compat',
      '--manifest',
      manifestPath,
      '--contract-id',
      CONTRACT_B,
      '--network',
      'mainnet',
      '--output',
      'json',
    ])
    const code = await runCheckCompat(parsed.flags, makeIo())

    expect(code).toBe(5)
    const report = JSON.parse(stdoutChunks.join(''))
    expect(report.status).toBe('incompatible')
  })

  it('exits 2 when --manifest is missing', async () => {
    const code = await runCheckCompat({ 'contract-id': CONTRACT_A }, makeIo())
    expect(code).toBe(2)
    expect(stderrChunks.join('')).toContain('--manifest is required')
  })

  it('exits 2 when --contract-id is missing', async () => {
    const code = await runCheckCompat({ manifest: manifestPath }, makeIo())
    expect(code).toBe(2)
    expect(stderrChunks.join('')).toContain('--contract-id is required')
  })

  it('exits 2 when --output is invalid', async () => {
    const code = await runCheckCompat(
      {
        manifest: manifestPath,
        'contract-id': CONTRACT_A,
        output: 'xml',
      },
      makeIo(),
    )
    expect(code).toBe(2)
    expect(stderrChunks.join('')).toContain('invalid --output')
  })

  it('exits 8 when --contract-id is malformed', async () => {
    const code = await runCheckCompat(
      {
        manifest: manifestPath,
        'contract-id': 'NOT_A_CONTRACT_ID',
      },
      makeIo(),
    )
    expect(code).toBe(8)
    expect(stderrChunks.join('')).toContain('invalid --contract-id')
  })

  it('exits 8 when manifest is malformed or unreadable', async () => {
    const badPath = join(tmpDir, 'bad.json')
    writeFileSync(badPath, '{"not":"a valid manifest"}', 'utf-8')

    const code = await runCheckCompat(
      {
        manifest: badPath,
        'contract-id': CONTRACT_A,
      },
      makeIo(),
    )
    expect(code).toBe(8)
    expect(stderrChunks.join('')).toContain('invalid or unreadable manifest')
  })
})
