import { describe, expect, it, vi } from 'vitest'
import {
  BatchVerifier,
  computeChunkedSha256,
  deriveSelectedInputIdentity,
  orderBatchItemsBySelection,
  tryParseManifest,
  type BatchConfig,
} from './batchVerifier'

describe('batchVerifier', () => {
  describe('computeChunkedSha256', () => {
    it('computes sha256 for small files', async () => {
      const content = 'Harpocrates test video payload'
      const file = new File([content], 'test.mp4', { type: 'video/mp4' })
      const hash = await computeChunkedSha256(file)

      // Compare with WebCrypto direct digest
      const direct = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content))))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

      expect(hash).toBe(direct)
    })

    it('respects AbortSignal during hashing', async () => {
      const controller = new AbortController()
      controller.abort()

      const file = new File(['data'], 'test.mp4', { type: 'video/mp4' })
      await expect(computeChunkedSha256(file, controller.signal)).rejects.toThrow('Operation cancelled.')
    })
  })

  describe('tryParseManifest', () => {
    it('parses valid Harpocrates JSON manifest', async () => {
      const manifestJson = JSON.stringify({
        protocol: 'harpocrates',
        version: 1,
        proofId: '0x123',
        tier: 'silent',
        network: 'testnet',
        contractId: 'CC123',
        transactionRef: '0xabc',
        videoHash: '1111222233334444555566667777888811112222333344445555666677778888',
        metadataHash: 'aaaa222233334444555566667777888811112222333344445555666677778888',
        sourceHash: '1111222233334444555566667777888811112222333344445555666677778888',
        timestamp: '2026-07-25T00:00:00Z',
      })

      const file = new File([manifestJson], 'receipt.json', { type: 'application/json' })
      const result = await tryParseManifest(file)
      expect(result).not.toBeNull()
      expect(result?.protocol).toBe('harpocrates')
      expect(result?.videoHash).toBe('1111222233334444555566667777888811112222333344445555666677778888')
    })

    it('returns null for non-json or invalid manifest format', async () => {
      const file = new File(['not json'], 'receipt.txt', { type: 'text/plain' })
      const result = await tryParseManifest(file)
      expect(result).toBeNull()
    })
  })

  describe('BatchVerifier Worker Pool', () => {
    it('enforces per-file size limits upfront', async () => {
      const config: Partial<BatchConfig> = {
        maxFileSizeBytes: 100, // 100 bytes max
        maxTotalSizeBytes: 1000,
      }
      const verifier = new BatchVerifier(config)

      const fileNormal = new File(['short'], 'ok.mp4', { type: 'video/mp4' })
      const fileOversized = new File(['a'.repeat(200)], 'large.mp4', { type: 'video/mp4' })

      const { items } = await verifier.runBatch([fileNormal, fileOversized])

      const oversizedItem = items.find((i) => i.fileName === 'large.mp4')
      expect(oversizedItem?.status).toBe('oversized')
      expect(oversizedItem?.message).toContain('exceeds size limit')
    })

    it('enforces max total batch size limit', async () => {
      const config: Partial<BatchConfig> = {
        maxFileSizeBytes: 1000,
        maxTotalSizeBytes: 250, // total 250 bytes max
      }
      const verifier = new BatchVerifier(config)

      const f1 = new File(['a'.repeat(150)], 'f1.mp4')
      const f2 = new File(['b'.repeat(150)], 'f2.mp4')

      const { items } = await verifier.runBatch([f1, f2])
      const f2Item = items.find((i) => i.fileName === 'f2.mp4')
      expect(f2Item?.status).toBe('oversized')
      expect(f2Item?.message).toContain('Total batch size limit exceeded')
    })

    it('detects duplicate files in batch', async () => {
      const verifier = new BatchVerifier({
        maxConcurrency: 1,
        apiBase: 'http://127.0.0.1:5050',
      })

      // Mock global fetch for stego extract
      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation((url: string) => {
          if (url.includes('/api/stego/extract')) {
            return Promise.resolve({
              ok: true,
              json: () => Promise.resolve({ metadata: { protocol: 'harpocrates' } }),
            })
          }
          if (url.includes('/api/proofs/by-video/')) {
            return Promise.resolve({
              ok: true,
              json: () => Promise.resolve({ events: [] }),
            })
          }
          return Promise.reject(new Error('Unknown url'))
        }),
      )

      const f1 = new File(['identical content payload'], 'video1.mp4', { type: 'video/mp4' })
      const f2 = new File(['identical content payload'], 'video2.mp4', { type: 'video/mp4' })

      const { items } = await verifier.runBatch([f1, f2])

      const dupItem = items.find((i) => i.fileName === 'video2.mp4')
      expect(dupItem?.status).toBe('duplicate')
      expect(dupItem?.duplicateOf).toBe('video1.mp4')
      expect(dupItem?.message).toContain('Duplicate file detected')

      vi.unstubAllGlobals()
    })

    it('isolates single file failures without failing entire batch', async () => {
      const verifier = new BatchVerifier({ maxConcurrency: 2 })

      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation((url: string) => {
          if (url.includes('/api/stego/extract')) {
            // Cause error for corrupted file
            return Promise.resolve({
              ok: false,
              status: 400,
            })
          }
          if (url.includes('/api/proofs/by-video/')) {
            return Promise.resolve({
              ok: true,
              json: () => Promise.resolve({ events: [] }),
            })
          }
          return Promise.reject(new Error('Network error'))
        }),
      )

      const fGood = new File(['good content'], 'good.mp4')
      const fBad = new File(['bad content'], 'bad.mp4')

      const { items } = await verifier.runBatch([fGood, fBad])

      expect(items).toHaveLength(2)
      const badItem = items.find((i) => i.fileName === 'bad.mp4')
      expect(badItem?.status).toBe('malformed')

      vi.unstubAllGlobals()
    })

    it('supports batch cancellation', async () => {
      const verifier = new BatchVerifier({ maxConcurrency: 1 })
      const f1 = new File(['content 1'], 'f1.mp4')
      const f2 = new File(['content 2'], 'f2.mp4')

      const promise = verifier.runBatch([f1, f2])
      verifier.cancel()
      const { items } = await promise

      expect(items.some((i) => i.status === 'cancelled')).toBe(true)
    })

    it('keeps batch result ordering and duplicate ownership stable when concurrent items finish out of order', async () => {
      const verifier = new BatchVerifier({
        maxConcurrency: 4,
        apiBase: 'http://127.0.0.1:5050',
      })

      const slowPrimary = new File(['shared-payload-alpha'], '01_slow_primary.mp4', {
        type: 'video/mp4',
        lastModified: 1001,
      })
      const mediumUnique = new File(['unique-payload-beta'], '02_medium_unique.mp4', {
        type: 'video/mp4',
        lastModified: 1002,
      })
      const fastUnique = new File(['unique-payload-gamma'], '03_fast_unique.mp4', {
        type: 'video/mp4',
        lastModified: 1003,
      })
      const fastDuplicateCopy = new File(['shared-payload-alpha'], '04_fast_dup_copy.mp4', {
        type: 'video/mp4',
        lastModified: 1004,
      })

      // Force reverse completion latency during arrayBuffer reads so slot #3 and #2 finish before #0
      const realArrayBuffer = File.prototype.arrayBuffer
      const arrayBufferSpy = vi.spyOn(File.prototype, 'arrayBuffer').mockImplementation(async function (this: File) {
        if (this.name === '01_slow_primary.mp4') {
          await new Promise((r) => setTimeout(r, 45))
        } else if (this.name === '02_medium_unique.mp4') {
          await new Promise((r) => setTimeout(r, 20))
        }
        return realArrayBuffer.call(this)
      })

      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation((url: string) => {
          if (url.includes('/api/stego/extract')) {
            return Promise.resolve({
              ok: true,
              json: () => Promise.resolve({ metadata: { protocol: 'harpocrates' } }),
            })
          }
          if (url.includes('/api/proofs/by-video/')) {
            return Promise.resolve({
              ok: true,
              json: () => Promise.resolve({ events: [] }),
            })
          }
          return Promise.reject(new Error('Unknown url'))
        }),
      )

      const progressSnapshots: string[][] = []
      const { items } = await verifier.runBatch(
        [slowPrimary, mediumUnique, fastUnique, fastDuplicateCopy],
        (_prog, snapshot) => {
          progressSnapshots.push(snapshot.map((entry) => entry.fileName))
        },
      )

      const expectedNames = [
        '01_slow_primary.mp4',
        '02_medium_unique.mp4',
        '03_fast_unique.mp4',
        '04_fast_dup_copy.mp4',
      ]

      for (const names of progressSnapshots) {
        expect(names).toEqual(expectedNames)
      }

      expect(items.map((i) => i.fileName)).toEqual(expectedNames)
      expect(items.map((i) => i.inputIndex)).toEqual([0, 1, 2, 3])
      expect(items[0].inputIdentity).toBe(deriveSelectedInputIdentity(slowPrimary, 0))
      expect(items[3].inputIdentity).toBe(deriveSelectedInputIdentity(fastDuplicateCopy, 3))

      // Even though slot #3 finished hashing before slot #0, slot #0 remains primary and #3 is duplicate
      expect(items[0].status).not.toBe('duplicate')
      expect(items[3].status).toBe('duplicate')
      expect(items[3].duplicateOf).toBe('01_slow_primary.mp4')

      expect(orderBatchItemsBySelection([items[2], items[0], items[3], items[1]]).map((i) => i.inputIndex)).toEqual([
        0, 1, 2, 3,
      ])

      arrayBufferSpy.mockRestore()
      vi.unstubAllGlobals()
    })
  })
})
