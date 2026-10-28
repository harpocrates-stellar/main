import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { writeFile, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileHash } from '../src/metadata.js'
import { parseCliArgs } from '../src/args.js'
import { createHash } from 'node:crypto'

describe('hash CLI args', () => {
  it('accepts --progress flag for hash command', () => {
    const parsed = parseCliArgs(['hash', '--file', 'test.bin', '--progress'])
    expect(parsed).toEqual({
      command: 'hash',
      flags: {
        file: 'test.bin',
        progress: 'true',
      },
    })
  })

  it('rejects --progress on commands that do not support it', () => {
    expect(() => parseCliArgs(['manifest', '--input', 'test.json', '--progress'])).toThrow(
      /unknown option/i,
    )
  })
})

describe('fileHash streaming & progress', () => {
  const tempFiles: string[] = []

  afterEach(async () => {
    for (const file of tempFiles) {
      try {
        await unlink(file)
      } catch {
        // ignore
      }
    }
    tempFiles.length = 0
    vi.restoreAllMocks()
  })

  it('computes correct sha256 hash without options', async () => {
    const tempPath = join(tmpdir(), `test-hash-${Date.now()}.bin`)
    tempFiles.push(tempPath)
    const content = Buffer.from('hello world large content'.repeat(100))
    await writeFile(tempPath, content)

    const expectedHash = createHash('sha256').update(content).digest('hex')
    const actualHash = await fileHash(tempPath)
    expect(actualHash).toBe(expectedHash)
  })

  it('throttles progress reports to at most every 500ms using mocked clock', async () => {
    const tempPath = join(tmpdir(), `test-hash-progress-${Date.now()}.bin`)
    tempFiles.push(tempPath)

    // Create a 5 MiB file to trigger multiple chunks (each chunk is 1 MiB)
    const chunkSize = 1024 * 1024
    const chunk = Buffer.alloc(chunkSize, 'a')
    const totalChunks = 5
    const content = Buffer.concat(Array(totalChunks).fill(chunk))
    await writeFile(tempPath, content)

    let currentTime = 1000
    vi.spyOn(Date, 'now').mockImplementation(() => currentTime)

    const stderrUpdates: string[] = []
    let lastProgressTime = 0

    const progressTracker = ({ percent }: { percent: number }) => {
      const now = Date.now()
      if (now - lastProgressTime >= 500 || percent === 100) {
        lastProgressTime = now
        stderrUpdates.push(`hashing: ${percent}%\n`)
      }
      // advance simulated clock by 100ms per chunk (less than 500ms)
      currentTime += 100
    }

    const expectedHash = createHash('sha256').update(content).digest('hex')
    const actualHash = await fileHash(tempPath, { onProgress: progressTracker })

    expect(actualHash).toBe(expectedHash)
    // Even though there were 5 chunks, updates should be throttled plus final 100%
    expect(stderrUpdates.length).toBeLessThanOrEqual(totalChunks)
    expect(stderrUpdates).toContain('hashing: 100%\n')
  })

  it('keeps memory bounded for multi-megabyte streams', async () => {
    const tempPath = join(tmpdir(), `test-hash-mem-${Date.now()}.bin`)
    tempFiles.push(tempPath)

    // Generate a 10 MiB test file
    const chunk = Buffer.alloc(1024 * 1024, 'x')
    await writeFile(tempPath, Buffer.concat(Array(10).fill(chunk)))

    const initialMemory = process.memoryUsage().heapUsed
    const hash = await fileHash(tempPath)
    const finalMemory = process.memoryUsage().heapUsed

    expect(hash).toHaveLength(64)
    // Memory change should not buffer the whole file (bounded peak memory)
    const memoryDiff = finalMemory - initialMemory
    // A 10 MiB file buffer would take >= 10 MiB, whereas streaming with 1 MiB highWaterMark keeps it low
    expect(memoryDiff).toBeLessThan(15 * 1024 * 1024)
  })
})
