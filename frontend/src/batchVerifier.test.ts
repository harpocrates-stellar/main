import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  BatchVerifier,
  computeChunkedSha256,
  orderBatchResults,
  tryParseManifest,
  type BatchConfig,
  type BatchItemResult,
} from './batchVerifier'
import * as verificationFlow from './verificationFlow'

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
    afterEach(() => {
      vi.restoreAllMocks()
      vi.unstubAllGlobals()
    })

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

      vi.spyOn(verificationFlow, 'verifyArtifact').mockImplementation(async ({ file }) => {
        if (file.name === 'bad.mp4') {
          return {
            outcome: 'malformed',
            message: 'Malformed evidence: embedded metadata could not be parsed.',
            events: [],
            chainProof: null,
          }
        }
        return {
          outcome: 'confirmed',
          message: 'Confirmed on chain.',
          events: [],
          chainProof: null,
        }
      })

      const fGood = new File(['good content'], 'good.mp4')
      const fBad = new File(['bad content'], 'bad.mp4')

      const { items } = await verifier.runBatch([fGood, fBad])

      expect(items).toHaveLength(2)
      const goodItem = items.find((i) => i.fileName === 'good.mp4')
      const badItem = items.find((i) => i.fileName === 'bad.mp4')
      expect(goodItem?.status).toBe('confirmed')
      expect(badItem?.status).toBe('malformed')
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

    it('keeps result ordering stable when items complete concurrently out of order', async () => {
      const verifier = new BatchVerifier({
        maxConcurrency: 3,
        apiBase: 'http://127.0.0.1:5050',
        contractId: '',
      })

      const files = [
        new File(['payload-slow-first'], 'slow-first.mp4', { type: 'video/mp4' }),
        new File(['payload-medium-second'], 'medium-second.mp4', { type: 'video/mp4' }),
        new File(['payload-fast-third'], 'fast-third.mp4', { type: 'video/mp4' }),
      ]

      const delaysByName: Record<string, number> = {
        'slow-first.mp4': 60,
        'medium-second.mp4': 30,
        'fast-third.mp4': 5,
      }
      const completionOrder: string[] = []

      vi.spyOn(verificationFlow, 'verifyArtifact').mockImplementation(async ({ file }) => {
        const delay = delaysByName[file.name] ?? 0
        await new Promise((resolve) => setTimeout(resolve, delay))
        completionOrder.push(file.name)
        return {
          outcome: 'confirmed',
          message: `Verified ${file.name}`,
          events: [],
          chainProof: null,
        }
      })

      const progressSnapshots: Array<{
        isDone: boolean
        activeCount: number
        names: string[]
        indices: Array<number | undefined>
      }> = []
      const { items } = await verifier.runBatch(files, (progress, currentItems) => {
        progressSnapshots.push({
          isDone: progress.isDone,
          activeCount: progress.activeCount,
          names: currentItems.map((i) => i.fileName),
          indices: currentItems.map((i) => i.inputIndex),
        })
      })

      // Items completed asynchronously in reverse order (fast -> medium -> slow)
      expect(completionOrder).toEqual(['fast-third.mp4', 'medium-second.mp4', 'slow-first.mp4'])

      // Every progress snapshot and final output preserves original input order
      for (const snap of progressSnapshots) {
        expect(snap.names).toEqual(['slow-first.mp4', 'medium-second.mp4', 'fast-third.mp4'])
        expect(snap.indices).toEqual([0, 1, 2])
        if (snap.isDone) {
          expect(snap.activeCount).toBe(0)
        }
      }
      expect(items.map((i) => i.fileName)).toEqual(['slow-first.mp4', 'medium-second.mp4', 'fast-third.mp4'])
      expect(items.map((i) => i.inputIndex)).toEqual([0, 1, 2])
    })

    it('associates results with explicit input identities including duplicate filenames', async () => {
      const verifier = new BatchVerifier({
        maxConcurrency: 2,
        apiBase: 'http://127.0.0.1:5050',
        contractId: '',
      })

      vi.spyOn(verificationFlow, 'verifyArtifact').mockResolvedValue({
        outcome: 'confirmed',
        message: 'Verified',
        events: [],
        chainProof: null,
      })

      // Pass inputs out of inputIndex order with identical file names
      const { items } = await verifier.runBatch([
        {
          id: 'sel-b',
          inputIndex: 4,
          file: new File(['second clip bytes'], 'evidence.mp4', { type: 'video/mp4' }),
        },
        {
          id: 'sel-a',
          inputIndex: 1,
          file: new File(['first clip bytes'], 'evidence.mp4', { type: 'video/mp4' }),
        },
      ])

      expect(items.map((i) => ({ id: i.id, inputIndex: i.inputIndex }))).toEqual([
        { id: 'sel-a', inputIndex: 1 },
        { id: 'sel-b', inputIndex: 4 },
      ])
      expect(items[0].videoHash).not.toBe(items[1].videoHash)
    })

    it('assigns canonical vs duplicate deterministically by input order under concurrent hashing', async () => {
      const verifier = new BatchVerifier({
        maxConcurrency: 2,
        apiBase: 'http://127.0.0.1:5050',
        contractId: '',
      })

      const verifiedFiles: string[] = []
      vi.spyOn(verificationFlow, 'verifyArtifact').mockImplementation(async ({ file }) => {
        verifiedFiles.push(file.name)
        return {
          outcome: 'confirmed',
          message: 'Verified on chain.',
          events: [],
          chainProof: null,
        }
      })

      const sharedPayload = 'identical concurrent duplicate payload'
      const slowOriginal = new File([sharedPayload], 'first-selected.mp4', { type: 'video/mp4' })
      const fastDuplicate = new File([sharedPayload], 'second-selected.mp4', { type: 'video/mp4' })

      // Delay arrayBuffer() on index 0 so index 1 finishes hashing first
      const originalArrayBuffer = slowOriginal.arrayBuffer.bind(slowOriginal)
      vi.spyOn(slowOriginal, 'arrayBuffer').mockImplementation(async () => {
        await new Promise((resolve) => setTimeout(resolve, 40))
        return originalArrayBuffer()
      })

      const { items } = await verifier.runBatch([slowOriginal, fastDuplicate])

      // Only one verification pass should have run despite concurrent hashing
      expect(verifiedFiles).toHaveLength(1)
      // Index 0 must remain the canonical item and index 1 must be its duplicate
      expect(items[0].fileName).toBe('first-selected.mp4')
      expect(items[0].inputIndex).toBe(0)
      expect(items[0].status).toBe('confirmed')
      expect(items[0].duplicateOf).toBeNull()

      expect(items[1].fileName).toBe('second-selected.mp4')
      expect(items[1].inputIndex).toBe(1)
      expect(items[1].status).toBe('duplicate')
      expect(items[1].duplicateOf).toBe('first-selected.mp4')
    })

    it('preserves input order across mixed oversized, failed, and succeeded concurrent items', async () => {
      const verifier = new BatchVerifier({
        maxConcurrency: 3,
        maxFileSizeBytes: 50,
        maxTotalSizeBytes: 500,
        apiBase: 'http://127.0.0.1:5050',
        contractId: '',
      })

      const slowFailFile = new File(['slow-fail'], 'slow-fail.mp4')
      const oversizedFile = new File(['x'.repeat(100)], 'oversized-mid.mp4')
      const fastOkFile = new File(['fast-ok'], 'fast-ok.mp4')

      vi.spyOn(verificationFlow, 'verifyArtifact').mockImplementation(async ({ file }) => {
        if (file.name === 'slow-fail.mp4') {
          await new Promise((resolve) => setTimeout(resolve, 40))
          return {
            outcome: 'unavailable',
            message: 'Verification services are unavailable.',
            events: [],
            chainProof: null,
          }
        }
        return {
          outcome: 'confirmed',
          message: 'Verified on chain.',
          events: [],
          chainProof: null,
        }
      })

      const { items } = await verifier.runBatch([slowFailFile, oversizedFile, fastOkFile])

      expect(items.map((i) => ({ name: i.fileName, index: i.inputIndex, status: i.status }))).toEqual([
        { name: 'slow-fail.mp4', index: 0, status: 'unavailable' },
        { name: 'oversized-mid.mp4', index: 1, status: 'oversized' },
        { name: 'fast-ok.mp4', index: 2, status: 'confirmed' },
      ])
    })
  })

  describe('orderBatchResults', () => {
    const makeItem = (id: string, inputIndex?: number): BatchItemResult => ({
      id,
      inputIndex,
      file: new File(['x'], `${id}.mp4`),
      fileName: `${id}.mp4`,
      fileSizeBytes: 1,
      status: 'confirmed',
      videoHash: null,
      metadataHash: null,
      sourceHash: null,
      tier: null,
      chainStatus: null,
      message: 'ok',
      events: [],
      chainProof: null,
      duplicateOf: null,
      manifest: null,
      durationMs: 10,
      failureReason: null,
    })

    it('orders by inputIndex without mutating the source array and handles boundary cases', () => {
      const source = [
        makeItem('unindexed-a', undefined),
        makeItem('idx-2', 2),
        makeItem('nan-idx', Number.NaN),
        makeItem('idx-0-first', 0),
        makeItem('idx-0-second', 0),
        makeItem('idx-1', 1),
      ]

      const ordered = orderBatchResults(source)

      expect(ordered.map((i) => i.id)).toEqual([
        'idx-0-first',
        'idx-0-second',
        'idx-1',
        'idx-2',
        'unindexed-a',
        'nan-idx',
      ])
      // Source array was not mutated
      expect(source[0].id).toBe('unindexed-a')
      expect(orderBatchResults([])).toEqual([])
    })
  })
})
