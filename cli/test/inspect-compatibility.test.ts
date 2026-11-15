import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import {
  inspectBundleCompatibility,
  compatibilityExitCode,
  formatCompatibilityReport,
  COMPATIBILITY_REPORT_PROTOCOL,
  MAX_COMPATIBILITY_BUNDLE_BYTES,
} from '../src/inspect-compatibility.js'
import { createProofManifest } from '../src/manifest.js'
import { createReceipt } from '../src/receipt.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = resolve(__filename, '..')
const cliRoot = resolve(__dirname, '..')
const distCli = resolve(cliRoot, 'dist', 'cli.js')

const CONTRACT_A = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4'
const CONTRACT_B = 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526'
const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015'
const MAINNET_PASSPHRASE = 'Public Global Stellar Network ; September 2015'
const PROOF_ID = 'b'.repeat(64)
const SOURCE_HASH = 'a'.repeat(64)
const VIDEO_HASH = 'c'.repeat(64)
const METADATA_HASH = 'd'.repeat(64)
const TX_HASH = 'e'.repeat(64)

function sampleManifest(overrides: Partial<Parameters<typeof createProofManifest>[0]> = {}) {
  return createProofManifest({
    proofId: PROOF_ID,
    tier: 'source',
    network: TESTNET_PASSPHRASE,
    contractId: CONTRACT_A,
    transactionRef: TX_HASH,
    videoHash: VIDEO_HASH,
    metadataHash: METADATA_HASH,
    sourceHash: SOURCE_HASH,
    timestamp: '2026-08-01T00:00:00.000Z',
    verifierScope: '7',
    epoch: 2,
    selectiveDisclosure: {
      schemaHash: '1'.repeat(64),
      publicInputs: '00ff',
      predicateCommitment: '2'.repeat(64),
      circuitVersion: 3,
    },
    ...overrides,
  })
}

describe('inspectBundleCompatibility unit suite', () => {
  it('reports compatible=true for a matching verification bundle and never invokes network fetch', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    try {
      const manifest = sampleManifest()
      const receipt = createReceipt(
        manifest,
        { status: 'confirmed', txHash: TX_HASH, ledger: 120, contractMatch: true },
        null,
        'valid',
      )
      const bundle = {
        protocol: 'harpocrates-verification-bundle',
        version: 1,
        network: TESTNET_PASSPHRASE,
        contractId: CONTRACT_A,
        manifest,
        receipt,
        trustSnapshot: {
          networkPassphrase: TESTNET_PASSPHRASE,
          contractId: CONTRACT_A,
          verifierScope: '7',
          circuitVersion: '3',
        },
      }

      const report = inspectBundleCompatibility(JSON.stringify(bundle), {
        network: 'testnet',
        contractId: CONTRACT_A,
        tier: 'source',
        verifierScope: '7',
        circuitVersion: '3',
      })

      expect(report.protocol).toBe(COMPATIBILITY_REPORT_PROTOCOL)
      expect(report.version).toBe(1)
      expect(report.compatible).toBe(true)
      expect(report.readOnly).toBe(true)
      expect(report.bundleKind).toBe('bundle')
      expect(report.mismatches).toEqual([])
      expect(compatibilityExitCode(report)).toBe(0)
      expect(formatCompatibilityReport(report)).toContain('Compatibility: COMPATIBLE')
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      fetchSpy.mockRestore()
    }
  })

  it('supports standalone manifests, verification receipts, and signed receipts', () => {
    const manifest = sampleManifest()
    const manifestReport = inspectBundleCompatibility(JSON.stringify(manifest), {
      network: TESTNET_PASSPHRASE,
      contractId: CONTRACT_A,
    })
    expect(manifestReport.compatible).toBe(true)
    expect(manifestReport.bundleKind).toBe('manifest')

    const vReceipt = createReceipt(
      manifest,
      { status: 'pending', txHash: TX_HASH },
      null,
      'pending',
    )
    const vrReport = inspectBundleCompatibility(JSON.stringify(vReceipt), {
      network: 'testnet',
      contractId: CONTRACT_A,
    })
    expect(vrReport.compatible).toBe(true)
    expect(vrReport.bundleKind).toBe('verification-receipt')

    const signedReceipt = {
      protocol: 'harpocrates-verification-receipt',
      version: 1,
      result: 'verified',
      verifiedAt: '2026-08-01T00:05:00.000Z',
      proofId: PROOF_ID,
      videoHash: VIDEO_HASH,
      metadataHash: METADATA_HASH,
      tier: 'source',
      networkPassphrase: TESTNET_PASSPHRASE,
      contractId: CONTRACT_A,
      ledgerSequence: 100,
      transactionHash: TX_HASH,
      circuitVersion: '3',
      verifierVersion: '1.0.0',
      signer: { keyId: 'k1', algorithm: 'ECDSA_P256_SHA256' },
      signature: 'AAAA',
    }
    const srReport = inspectBundleCompatibility(JSON.stringify(signedReceipt), {
      network: 'testnet',
      contractId: CONTRACT_A,
      tier: 'source',
      circuitVersion: '3',
    })
    expect(srReport.compatible).toBe(true)
    expect(srReport.bundleKind).toBe('signed-receipt')
  })

  it('returns exit code 4 on network mismatch and exit code 5 on contract mismatch', () => {
    const manifest = sampleManifest()

    const netMismatch = inspectBundleCompatibility(JSON.stringify(manifest), {
      network: MAINNET_PASSPHRASE,
      contractId: CONTRACT_A,
    })
    expect(netMismatch.compatible).toBe(false)
    expect(netMismatch.mismatches).toEqual(['network'])
    expect(compatibilityExitCode(netMismatch)).toBe(4)

    const contractMismatch = inspectBundleCompatibility(JSON.stringify(manifest), {
      network: 'testnet',
      contractId: CONTRACT_B,
    })
    expect(contractMismatch.compatible).toBe(false)
    expect(contractMismatch.mismatches).toEqual(['contract_id'])
    expect(compatibilityExitCode(contractMismatch)).toBe(5)
  })

  it('enforces identity tier separation, verifierScope, and circuitVersion when explicitly selected', () => {
    const manifest = sampleManifest({ tier: 'silent', selectiveDisclosure: undefined })

    const tierMismatch = inspectBundleCompatibility(JSON.stringify(manifest), {
      network: 'testnet',
      contractId: CONTRACT_A,
      tier: 'seal',
    })
    expect(tierMismatch.compatible).toBe(false)
    expect(tierMismatch.mismatches).toContain('identity_tier')
    expect(compatibilityExitCode(tierMismatch)).toBe(8)

    const missingCircuit = inspectBundleCompatibility(JSON.stringify(manifest), {
      network: 'testnet',
      contractId: CONTRACT_A,
      circuitVersion: '3',
    })
    expect(missingCircuit.compatible).toBe(false)
    expect(missingCircuit.mismatches).toContain('circuit_version')
    expect(compatibilityExitCode(missingCircuit)).toBe(8)
  })

  it('fails closed when internal bundle components disagree on network or contractId', () => {
    const manifest = sampleManifest()
    const inconsistentBundle = {
      protocol: 'harpocrates-verification-bundle',
      version: 1,
      manifest,
      trustSnapshot: {
        networkPassphrase: MAINNET_PASSPHRASE,
        contractId: CONTRACT_B,
      },
    }

    const report = inspectBundleCompatibility(JSON.stringify(inconsistentBundle), {
      network: 'testnet',
      contractId: CONTRACT_A,
    })
    expect(report.compatible).toBe(false)
    expect(report.mismatches).toContain('bundle_integrity')
    expect(compatibilityExitCode(report)).toBe(8)
  })

  it('rejects private/secret fields, malformed JSON, and oversized inputs', () => {
    expect(() =>
      inspectBundleCompatibility('{not-json', { network: 'testnet', contractId: CONTRACT_A }),
    ).toThrow(/not valid JSON/)

    const withSecret = {
      protocol: 'harpocrates-verification-bundle',
      version: 1,
      manifest: sampleManifest(),
      trustSnapshot: { witnessData: 'private' },
    }
    expect(() =>
      inspectBundleCompatibility(JSON.stringify(withSecret), {
        network: 'testnet',
        contractId: CONTRACT_A,
      }),
    ).toThrow(/forbidden private or secret fields/)

    const oversized = ' '.repeat(MAX_COMPATIBILITY_BUNDLE_BYTES + 10)
    expect(() =>
      inspectBundleCompatibility(oversized, { network: 'testnet', contractId: CONTRACT_A }),
    ).toThrow(/1 MiB limit/)
  })
})

describe('CLI command: inspect-compatibility', () => {
  let tempDir: string
  let bundlePath: string
  let originalBytes: Buffer

  beforeAll(() => {
    tempDir = resolve(tmpdir(), `harpocrates-compat-${Date.now()}-${Math.random().toString(36).slice(2)}`)
    mkdirSync(tempDir, { recursive: true })
    const bundle = {
      protocol: 'harpocrates-verification-bundle',
      version: 1,
      manifest: sampleManifest(),
      trustSnapshot: {
        networkPassphrase: TESTNET_PASSPHRASE,
        contractId: CONTRACT_A,
      },
    }
    bundlePath = join(tempDir, 'bundle.json')
    writeFileSync(bundlePath, JSON.stringify(bundle, null, 2), 'utf-8')
    originalBytes = readFileSync(bundlePath)
  })

  afterAll(() => {
    if (tempDir && existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true })
    }
  })

  function runCli(args: string[], input?: string, env?: NodeJS.ProcessEnv) {
    return spawnSync(process.execPath, [distCli, ...args], {
      cwd: cliRoot,
      encoding: 'utf-8',
      input,
      env: { ...process.env, ...env },
    })
  }

  it('exits 0 with deterministic JSON output and leaves bundle file untouched', () => {
    const res = runCli([
      'inspect-compatibility',
      '--bundle',
      bundlePath,
      '--network',
      'testnet',
      '--contract-id',
      CONTRACT_A,
      '--output',
      'json',
    ])

    expect(res.status).toBe(0)
    expect(res.stderr).toBe('')
    const parsed = JSON.parse(res.stdout.trim())
    expect(parsed.compatible).toBe(true)
    expect(parsed.readOnly).toBe(true)
    expect(readFileSync(bundlePath).equals(originalBytes)).toBe(true)
  })

  it('requires explicit --network and --contract-id rather than implicit defaults (exits 2)', () => {
    const missingNetwork = runCli(
      ['inspect-compatibility', '--bundle', bundlePath, '--contract-id', CONTRACT_A],
      undefined,
      { HARPOCRATES_CONTRACT_ID: CONTRACT_A },
    )
    expect(missingNetwork.status).toBe(2)
    expect(missingNetwork.stdout).toBe('')
    expect(missingNetwork.stderr).toContain('--network is required')

    const missingContract = runCli(
      ['inspect-compatibility', '--bundle', bundlePath, '--network', 'testnet'],
      undefined,
      { HARPOCRATES_CONTRACT_ID: CONTRACT_A },
    )
    expect(missingContract.status).toBe(2)
    expect(missingContract.stdout).toBe('')
    expect(missingContract.stderr).toContain('--contract-id is required')
  })

  it('exits 4 on network mismatch, 5 on contract mismatch, and 8 on invalid bundle via stdin', () => {
    const netRes = runCli([
      'inspect-compatibility',
      '-b',
      bundlePath,
      '--network',
      'mainnet',
      '--contract-id',
      CONTRACT_A,
      '-o',
      'json',
    ])
    expect(netRes.status).toBe(4)
    expect(JSON.parse(netRes.stdout.trim()).mismatches).toEqual(['network'])

    const contractRes = runCli([
      'inspect-compatibility',
      '-b',
      bundlePath,
      '--network',
      'testnet',
      '--contract-id',
      CONTRACT_B,
    ])
    expect(contractRes.status).toBe(5)
    expect(contractRes.stdout).toContain('Compatibility: INCOMPATIBLE')

    const badStdin = runCli(
      ['inspect-compatibility', '-b', '-', '--network', 'testnet', '--contract-id', CONTRACT_A, '-o', 'json'],
      '{"not":"a valid bundle"}',
    )
    expect(badStdin.status).toBe(8)
    expect(badStdin.stdout).toBe('')
    expect(badStdin.stderr).toContain('invalid or unreadable bundle')
  })
})
