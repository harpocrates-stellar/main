import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest'
import { Readable } from 'node:stream'
import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import {
  MAX_MANIFEST_INPUT_BYTES,
  InputSizeLimitError,
  readBoundedStream,
  readBoundedJson,
} from '../src/bounded-input.js'
import { createProofManifest, serializeManifest } from '../src/manifest.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = resolve(__filename, '..')
const cliRoot = resolve(__dirname, '..')
const distCli = resolve(cliRoot, 'dist', 'cli.js')

const VALID_CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4'
const SAMPLE_TX_HASH = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const SAMPLE_VIDEO_HASH = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'

describe('readBoundedStream & readBoundedJson unit suite', () => {
  it('accepts streamed input at exact byte limit and parses JSON cleanly', async () => {
    const payload = JSON.stringify({ protocol: 'harpocrates', ok: true })
    const limit = Buffer.byteLength(payload, 'utf-8')
    const stream = Readable.from([payload.slice(0, 10), payload.slice(10)])

    const parsed = await readBoundedJson<{ protocol: string; ok: boolean }>(stream, {
      maxBytes: limit,
      label: 'manifest',
    })
    expect(parsed).toEqual({ protocol: 'harpocrates', ok: true })
  })

  it('rejects streamed input at maxBytes + 1 before JSON.parse is invoked', async () => {
    const parseSpy = vi.spyOn(JSON, 'parse')
    try {
      const payload = '{"a":"' + 'x'.repeat(128) + '"}'
      const limit = Buffer.byteLength(payload, 'utf-8') - 1
      const stream = Readable.from([payload])

      await expect(
        readBoundedJson(stream, { maxBytes: limit, label: 'manifest' }),
      ).rejects.toMatchObject({
        name: 'InputSizeLimitError',
        code: 'INPUT_LIMIT_EXCEEDED',
        label: 'manifest',
        maxBytes: limit,
        message: `manifest exceeds the ${limit}-byte input limit`,
      })
      expect(parseSpy).not.toHaveBeenCalled()
    } finally {
      parseSpy.mockRestore()
    }
  })

  it('stops pulling chunks immediately after crossing the limit and never leaks input bytes', async () => {
    let chunksProduced = 0
    const secretMarker = 'PRIVATE_WITNESS_SECRET_DO_NOT_ECHO'
    const infiniteLike = new Readable({
      highWaterMark: 1024,
      read() {
        setImmediate(() => {
          chunksProduced += 1
          if (chunksProduced > 100) {
            this.push(null)
            return
          }
          this.push(Buffer.from(`${secretMarker}:${'a'.repeat(1024)}`, 'utf-8'))
        })
      },
    })

    let caught: unknown
    try {
      await readBoundedStream(infiniteLike, { maxBytes: 2048, label: 'manifest' })
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(InputSizeLimitError)
    expect((caught as Error).message).toBe('manifest exceeds the 2048-byte input limit')
    expect((caught as Error).message).not.toContain(secretMarker)
    expect(chunksProduced).toBeLessThanOrEqual(4)
  })
})

describe('CLI standard-input bounds and clean JSON stdout', () => {
  let tempDir: string
  let keysPath: string

  beforeAll(() => {
    tempDir = resolve(tmpdir(), `harpocrates-stdin-${Date.now()}-${Math.random().toString(36).slice(2)}`)
    mkdirSync(tempDir, { recursive: true })
    keysPath = join(tempDir, 'keys.json')
    writeFileSync(keysPath, '{}', 'utf-8')
  })

  afterAll(() => {
    if (tempDir && existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true })
    }
  })

  function runCliWithStdin(args: string[], input: string) {
    return spawnSync(process.execPath, [distCli, ...args], {
      cwd: cliRoot,
      encoding: 'utf-8',
      input,
    })
  }

  function makeValidManifestJson(): string {
    const manifest = createProofManifest({
      proofId: 'b'.repeat(64),
      tier: 'silent',
      network: 'Test SDF Network ; September 2015',
      contractId: VALID_CONTRACT_ID,
      transactionRef: SAMPLE_TX_HASH,
      videoHash: SAMPLE_VIDEO_HASH,
      metadataHash: '5'.repeat(64),
      sourceHash: 'a'.repeat(64),
      timestamp: '2026-07-24T12:00:00.000Z',
    })
    return serializeManifest(manifest)
  }

  it('accepts a valid stdin manifest padded to exact 1 MiB (1048576 bytes) with --output json', () => {
    const baseJson = makeValidManifestJson()
    const exact1MiB = baseJson + ' '.repeat(MAX_MANIFEST_INPUT_BYTES - Buffer.byteLength(baseJson, 'utf-8'))
    expect(Buffer.byteLength(exact1MiB, 'utf-8')).toBe(MAX_MANIFEST_INPUT_BYTES)

    const res = runCliWithStdin(
      ['verify', '--manifest', '-', '--contract-id', VALID_CONTRACT_ID, '--offline', '--output', 'json'],
      exact1MiB,
    )

    expect(res.status).toBe(6)
    expect(res.stderr).toBe('')
    const receipt = JSON.parse(res.stdout.trim())
    expect(receipt.result).toBe('pending')
    expect(receipt.manifest.proofId).toBe('b'.repeat(64))
  })

  it('rejects a stdin manifest of 1 MiB + 1 byte with a stable stderr error and empty stdout', () => {
    const baseJson = makeValidManifestJson()
    const overByOne =
      baseJson + ' '.repeat(MAX_MANIFEST_INPUT_BYTES + 1 - Buffer.byteLength(baseJson, 'utf-8'))
    expect(Buffer.byteLength(overByOne, 'utf-8')).toBe(MAX_MANIFEST_INPUT_BYTES + 1)

    const res = runCliWithStdin(
      ['verify', '--manifest', '-', '--contract-id', VALID_CONTRACT_ID, '--offline', '--output', 'json'],
      overByOne,
    )

    expect(res.status).toBe(8)
    expect(res.stdout).toBe('')
    expect(res.stderr.trim()).toBe('harpocrates: manifest exceeds the 1 MiB input limit')
  })

  it('preserves clean empty stdout for oversized stdin across manifest, c2pa, and verify-receipt', () => {
    const oversized = '{"padding":"' + 'x'.repeat(MAX_MANIFEST_INPUT_BYTES) + '"}'

    const manifestRes = runCliWithStdin(
      [
        'manifest',
        '--input',
        '-',
        '--contract-id',
        VALID_CONTRACT_ID,
        '--tx-hash',
        SAMPLE_TX_HASH,
        '--video-hash',
        SAMPLE_VIDEO_HASH,
      ],
      oversized,
    )
    expect(manifestRes.status).toBe(8)
    expect(manifestRes.stdout).toBe('')
    expect(manifestRes.stderr.trim()).toBe('harpocrates: metadata exceeds the 1 MiB input limit')

    const c2paRes = runCliWithStdin(['c2pa', '--manifest', '-'], oversized)
    expect(c2paRes.status).toBe(8)
    expect(c2paRes.stdout).toBe('')
    expect(c2paRes.stderr.trim()).toBe('harpocrates: manifest exceeds the 1 MiB input limit')

    const verifyReceiptRes = runCliWithStdin(
      ['verify-receipt', '--receipt', '-', '--keys', keysPath, '--output', 'json'],
      oversized,
    )
    expect(verifyReceiptRes.status).toBe(8)
    expect(verifyReceiptRes.stdout).toBe('')
    expect(verifyReceiptRes.stderr.trim()).toBe('harpocrates: receipt exceeds the 1 MiB input limit')
  })
})
