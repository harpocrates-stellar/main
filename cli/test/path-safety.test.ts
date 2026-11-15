import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  existsSync,
  linkSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import {
  SameFileCollisionError,
  assertDistinctInputOutputPaths,
  pathsResolveToSameFile,
} from '../src/path-safety.js'
import { createProofManifest, serializeManifest } from '../src/manifest.js'
import { createReceipt } from '../src/receipt.js'
import { main } from '../src/cli.js'

const VALID_CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4'
const SAMPLE_TX_HASH = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const SAMPLE_VIDEO_HASH = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'

class ExitSignal extends Error {
  readonly code: number
  constructor(code: number) {
    super(`exit(${code})`)
    this.code = code
  }
}

function tryFileSymlink(target: string, linkPath: string): boolean {
  try {
    symlinkSync(target, linkPath, 'file')
    return true
  } catch (err) {
    if (process.platform === 'win32' && (err as NodeJS.ErrnoException).code === 'EPERM') {
      return false
    }
    throw err
  }
}

describe('path-safety unit and CLI collision rejection', () => {
  let tempDir: string
  let realSubDir: string
  let metadataPath: string
  let manifestPath: string
  let receiptPath: string
  let originalMetadataBytes: Buffer
  let originalManifestBytes: Buffer
  let originalReceiptBytes: Buffer
  let stdoutChunks: string[]
  let stderrChunks: string[]

  beforeEach(() => {
    stdoutChunks = []
    stderrChunks = []
    tempDir = resolve(tmpdir(), `harpocrates-paths-${Date.now()}-${Math.random().toString(36).slice(2)}`)
    realSubDir = join(tempDir, 'real-dir')
    mkdirSync(realSubDir, { recursive: true })

    metadataPath = join(realSubDir, 'source-metadata.json')
    writeFileSync(
      metadataPath,
      JSON.stringify(
        {
          protocol: 'harpocrates',
          version: 1,
          tier: 'silent',
          sourceHash: 'a'.repeat(64),
          proofId: 'b'.repeat(64),
          timestamp: '2026-08-01T12:00:00.000Z',
        },
        null,
        2,
      ),
      'utf-8',
    )
    originalMetadataBytes = readFileSync(metadataPath)

    const manifest = createProofManifest({
      proofId: 'b'.repeat(64),
      tier: 'silent',
      network: 'Test SDF Network ; September 2015',
      contractId: VALID_CONTRACT_ID,
      transactionRef: SAMPLE_TX_HASH,
      videoHash: SAMPLE_VIDEO_HASH,
      metadataHash: 'c'.repeat(64),
      sourceHash: 'a'.repeat(64),
      timestamp: '2026-08-01T12:00:00.000Z',
    })
    manifestPath = join(realSubDir, 'manifest.json')
    writeFileSync(manifestPath, serializeManifest(manifest), 'utf-8')
    originalManifestBytes = readFileSync(manifestPath)

    const receipt = createReceipt(
      manifest,
      { status: 'confirmed', txHash: SAMPLE_TX_HASH, ledger: 12, contractMatch: true },
      null,
      'valid',
    )
    receiptPath = join(realSubDir, 'receipt.json')
    writeFileSync(receiptPath, JSON.stringify(receipt, null, 2), 'utf-8')
    originalReceiptBytes = readFileSync(receiptPath)

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

  async function runMain(args: string[]) {
    stdoutChunks = []
    stderrChunks = []
    try {
      await main(args)
      return { code: 0, stdout: stdoutChunks.join(''), stderr: stderrChunks.join('') }
    } catch (err) {
      if (err instanceof ExitSignal) {
        return { code: err.code, stdout: stdoutChunks.join(''), stderr: stderrChunks.join('') }
      }
      throw err
    }
  }

  it('rejects identical and relative-aliased paths in manifest and c2pa while preserving exact source bytes', async () => {
    const relativeMetaAlias = join(realSubDir, '..', 'real-dir', '.', 'source-metadata.json')

    const mSame = await runMain([
      'manifest',
      '--input',
      metadataPath,
      '--output',
      relativeMetaAlias,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--tx-hash',
      SAMPLE_TX_HASH,
      '--video-hash',
      SAMPLE_VIDEO_HASH,
    ])
    expect(mSame.code).toBe(8)
    expect(mSame.stdout).toBe('')
    expect(mSame.stderr).toContain('refusing to overwrite source data')
    expect(readFileSync(metadataPath).equals(originalMetadataBytes)).toBe(true)

    const c2paSameManifest = await runMain([
      'c2pa',
      '--manifest',
      manifestPath,
      '--receipt',
      receiptPath,
      '--output',
      manifestPath,
    ])
    expect(c2paSameManifest.code).toBe(8)
    expect(c2paSameManifest.stdout).toBe('')
    expect(readFileSync(manifestPath).equals(originalManifestBytes)).toBe(true)

    const c2paSameReceipt = await runMain([
      'c2pa',
      '--manifest',
      manifestPath,
      '--receipt',
      receiptPath,
      '--output',
      join(realSubDir, '..', 'real-dir', 'receipt.json'),
    ])
    expect(c2paSameReceipt.code).toBe(8)
    expect(c2paSameReceipt.stdout).toBe('')
    expect(readFileSync(receiptPath).equals(originalReceiptBytes)).toBe(true)
  })

  it('resolves symlinked directories, file symlinks, and hardlinks before opening output', async () => {
    const aliasDir = join(tempDir, 'dir-alias')
    symlinkSync(realSubDir, aliasDir, process.platform === 'win32' ? 'junction' : 'dir')

    // Symlinked directory alias -> must be rejected and bytes preserved
    const viaDirAlias = join(aliasDir, 'manifest.json')
    expect(await pathsResolveToSameFile(manifestPath, viaDirAlias)).toBe(true)

    const c2paDirAlias = await runMain([
      'c2pa',
      '--manifest',
      manifestPath,
      '--output',
      viaDirAlias,
    ])
    expect(c2paDirAlias.code).toBe(8)
    expect(readFileSync(manifestPath).equals(originalManifestBytes)).toBe(true)

    // Hardlink alias -> same inode/file identity -> must be rejected and bytes preserved
    const hardlinkMeta = join(tempDir, 'hardlink-metadata.json')
    linkSync(metadataPath, hardlinkMeta)
    await expect(assertDistinctInputOutputPaths([metadataPath], hardlinkMeta)).rejects.toBeInstanceOf(
      SameFileCollisionError,
    )
    const manifestHardlinkRes = await runMain([
      'manifest',
      '--input',
      metadataPath,
      '--output',
      hardlinkMeta,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--tx-hash',
      SAMPLE_TX_HASH,
      '--video-hash',
      SAMPLE_VIDEO_HASH,
    ])
    expect(manifestHardlinkRes.code).toBe(8)
    expect(readFileSync(metadataPath).equals(originalMetadataBytes)).toBe(true)

    // Direct file symlink alias (both --output as symlink and --input as symlink)
    const fileSymlinkManifest = join(tempDir, 'symlink-manifest.json')
    if (tryFileSymlink(manifestPath, fileSymlinkManifest)) {
      const outAsSymlink = await runMain([
        'c2pa',
        '--manifest',
        manifestPath,
        '--output',
        fileSymlinkManifest,
      ])
      expect(outAsSymlink.code).toBe(8)
      expect(readFileSync(manifestPath).equals(originalManifestBytes)).toBe(true)

      const inAsSymlink = await runMain([
        'c2pa',
        '--manifest',
        fileSymlinkManifest,
        '--output',
        manifestPath,
      ])
      expect(inAsSymlink.code).toBe(8)
      expect(readFileSync(manifestPath).equals(originalManifestBytes)).toBe(true)
    }
  })

  it('continues to write normally when --output is a distinct target file', async () => {
    const distinctManifestOut = join(tempDir, 'new-manifest.json')
    const okManifest = await runMain([
      'manifest',
      '--input',
      metadataPath,
      '--output',
      distinctManifestOut,
      '--contract-id',
      VALID_CONTRACT_ID,
      '--tx-hash',
      SAMPLE_TX_HASH,
      '--video-hash',
      SAMPLE_VIDEO_HASH,
    ])
    expect(okManifest.code).toBe(0)
    expect(existsSync(distinctManifestOut)).toBe(true)
    expect(readFileSync(metadataPath).equals(originalMetadataBytes)).toBe(true)

    const distinctC2paOut = join(tempDir, 'new-c2pa.json')
    const okC2pa = await runMain([
      'c2pa',
      '--manifest',
      manifestPath,
      '--receipt',
      receiptPath,
      '--output',
      distinctC2paOut,
    ])
    expect(okC2pa.code).toBe(0)
    expect(existsSync(distinctC2paOut)).toBe(true)
    expect(readFileSync(manifestPath).equals(originalManifestBytes)).toBe(true)
    expect(readFileSync(receiptPath).equals(originalReceiptBytes)).toBe(true)
  })
})
