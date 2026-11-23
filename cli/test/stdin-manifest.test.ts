import { describe, it, expect } from 'vitest'
import { Readable } from 'node:stream'
import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import {
  parseManifest,
  createProofManifest,
  serializeManifest,
  readBoundedManifest,
  MAX_MANIFEST_BYTES,
} from '../src/manifest.js'
import { readText } from '../src/cli.js'

const CLI_PATH = resolve(__dirname, '../dist/cli.js')
const VALID_CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M'

const VALID_MANIFEST_INPUT = {
  proofId: 'a'.repeat(64),
  tier: 'silent' as const,
  network: 'Test SDF Network ; September 2015',
  contractId: VALID_CONTRACT_ID,
  transactionRef: 'b'.repeat(64),
  videoHash: 'c'.repeat(64),
  metadataHash: 'd'.repeat(64),
  sourceHash: 'e'.repeat(64),
  timestamp: '2026-07-24T12:00:00.000Z',
}

function runCliWithStdin(
  args: string[],
  input: string | Buffer | Readable,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((res, rej) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''

    child.stdout.setEncoding('utf-8')
    child.stdout.on('data', (data) => {
      stdout += data
    })

    child.stderr.setEncoding('utf-8')
    child.stderr.on('data', (data) => {
      stderr += data
    })

    child.on('error', (err) => {
      rej(err)
    })

    child.on('close', (code) => {
      res({ code, stdout, stderr })
    })

    child.stdin.on('error', () => {
      // Ignore EPIPE/EOF if child exits early due to oversized input
    })

    if (input instanceof Readable) {
      input.pipe(child.stdin)
    } else {
      child.stdin.end(input)
    }
  })
}

describe('Bounded stream reading', () => {
  it('reads stream within limit successfully', async () => {
    const content = '{"hello":"world"}'
    const stream = Readable.from([content])
    const result = await readBoundedManifest(stream)
    expect(result).toBe(content)
  })

  it('accepts stream exactly at the 1 MiB boundary', async () => {
    const chunk = Buffer.alloc(1024, 'a')
    async function* generate() {
      for (let i = 0; i < 1024; i++) {
        yield chunk
      }
    }
    const stream = Readable.from(generate())
    const result = await readBoundedManifest(stream, MAX_MANIFEST_BYTES)
    expect(Buffer.byteLength(result)).toBe(MAX_MANIFEST_BYTES)
  })

  it('rejects stream exceeding 1 MiB boundary and destroys stream', async () => {
    let chunksGenerated = 0
    async function* generate() {
      for (let i = 0; i < 100; i++) {
        chunksGenerated++
        yield Buffer.alloc(64 * 1024, 'a') // 64 KiB chunks
      }
    }
    const stream = Readable.from(generate())

    await expect(readBoundedManifest(stream, MAX_MANIFEST_BYTES)).rejects.toThrow(
      'input exceeds 1048576 byte limit',
    )
    expect(stream.destroyed).toBe(true)
    // Stream should have aborted well before generating all 100 chunks (~6.4 MiB)
    expect(chunksGenerated).toBeLessThan(30)
  })

  it('readText helper enforces 1 MiB bound and destroys source stream', async () => {
    const stream = Readable.from([
      Buffer.alloc(MAX_MANIFEST_BYTES, 'x'),
      Buffer.from('overflow'),
    ])

    await expect(readText(stream)).rejects.toThrow('input exceeds 1 MiB limit')
    expect(stream.destroyed).toBe(true)
  })
})

describe('parseManifest size bound before JSON parsing', () => {
  it('rejects oversized raw string before JSON parsing', () => {
    const oversized = ' '.repeat(MAX_MANIFEST_BYTES + 1)
    expect(() => parseManifest(oversized)).toThrow('manifest exceeds 1 MiB limit')
  })

  it('accepts valid manifest padded up to 1 MiB boundary', () => {
    const manifest = createProofManifest(VALID_MANIFEST_INPUT)
    const json = serializeManifest(manifest)
    const paddingNeeded = MAX_MANIFEST_BYTES - Buffer.byteLength(json, 'utf-8')
    const padded = json + ' '.repeat(paddingNeeded)
    expect(Buffer.byteLength(padded, 'utf-8')).toBe(MAX_MANIFEST_BYTES)
    expect(parseManifest(padded)).toEqual(manifest)
  })
})

describe('CLI headless verification with standard-input manifest', () => {
  it('rejects oversized streamed input on stdin and preserves clean stdout for JSON callers', async () => {
    async function* generateOversized() {
      for (let i = 0; i < 35; i++) {
        yield Buffer.alloc(64 * 1024, 'x') // 35 * 64 KiB = 2.24 MiB
      }
    }
    const stream = Readable.from(generateOversized())

    const res = await runCliWithStdin(
      [
        'verify',
        '--contract-id',
        VALID_CONTRACT_ID,
        '--manifest',
        '-',
        '--output',
        'json',
      ],
      stream,
    )

    expect(res.code).toBe(8)
    // Preserves clean stdout for callers expecting JSON output
    expect(res.stdout).toBe('')
    // Stable error message on stderr
    expect(res.stderr).toContain('harpocrates: invalid or unreadable manifest')
  })

  it('rejects 1 MiB + 1 byte streamed input on stdin with clean stdout', async () => {
    const payload = Buffer.concat([
      Buffer.alloc(MAX_MANIFEST_BYTES, ' '),
      Buffer.from('x'),
    ])

    const res = await runCliWithStdin(
      [
        'verify',
        '--contract-id',
        VALID_CONTRACT_ID,
        '--manifest',
        '-',
        '--output',
        'json',
      ],
      payload,
    )

    expect(res.code).toBe(8)
    expect(res.stdout).toBe('')
    expect(res.stderr).toContain('harpocrates: invalid or unreadable manifest')
  })

  it('accepts valid manifest from standard input with --output json', async () => {
    const manifest = createProofManifest(VALID_MANIFEST_INPUT)
    const json = serializeManifest(manifest)

    const res = await runCliWithStdin(
      [
        'verify',
        '--contract-id',
        VALID_CONTRACT_ID,
        '--manifest',
        '-',
        '--output',
        'json',
        '--offline',
      ],
      json,
    )

    // Offline verify exits 6 (pending)
    expect(res.code).toBe(6)
    expect(res.stderr).toBe('')
    const parsed = JSON.parse(res.stdout)
    expect(parsed.result).toBe('pending')
    expect(parsed.manifest.proofId).toBe(VALID_MANIFEST_INPUT.proofId)
  })

  it('accepts valid manifest from standard input with default text output', async () => {
    const manifest = createProofManifest(VALID_MANIFEST_INPUT)
    const json = serializeManifest(manifest)

    const res = await runCliWithStdin(
      [
        'verify',
        '--contract-id',
        VALID_CONTRACT_ID,
        '--manifest',
        '-',
        '--offline',
      ],
      json,
    )

    expect(res.code).toBe(6)
    expect(res.stderr).toBe('')
    expect(res.stdout).toContain('Harpocrates Verification Receipt')
    expect(res.stdout).toContain('PENDING')
  })

  it('rejects malformed non-JSON input on stdin and preserves clean stdout', async () => {
    const res = await runCliWithStdin(
      [
        'verify',
        '--contract-id',
        VALID_CONTRACT_ID,
        '--manifest',
        '-',
        '--output',
        'json',
      ],
      'not a valid json manifest',
    )

    expect(res.code).toBe(8)
    expect(res.stdout).toBe('')
    expect(res.stderr).toContain('harpocrates: invalid or unreadable manifest')
  })

  it('rejects oversized manifest in c2pa export command from stdin', async () => {
    const oversized = Buffer.alloc(MAX_MANIFEST_BYTES + 1024, ' ')
    const res = await runCliWithStdin(['c2pa', '--manifest', '-'], oversized)

    expect(res.code).toBe(8)
    expect(res.stdout).toBe('')
    expect(res.stderr).toContain('harpocrates: invalid or unreadable manifest')
  })
})
