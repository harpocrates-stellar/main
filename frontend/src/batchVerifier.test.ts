import { describe, expect, it, vi } from 'vitest'
import { CheckpointStorage } from './lib/checkpointStorage'
import {
  BatchCheckpointError,
  BatchVerifier,
  computeChunkedSha256,
  createBatchCheckpoint,
  loadBatchCheckpointFromStorage,
  saveBatchCheckpointToStorage,
  tryParseManifest,
  validateBatchCheckpoint,
  type BatchConfig,
  type BatchVerificationCheckpoint,
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

    it('persists only non-secret fingerprints and completed results in checkpoints and resumes without re-hashing completed items', async () => {
      const manifestOne = JSON.stringify({
        protocol: 'harpocrates',
        version: 1,
        proofId: 'aa'.repeat(32),
        tier: 'silent',
        network: 'testnet',
        contractId: '',
        transactionRef: 'tx1',
        videoHash: 'aa'.repeat(32),
        metadataHash: 'bb'.repeat(32),
        sourceHash: 'aa'.repeat(32),
        timestamp: '2026-01-01T00:00:00.000Z',
        verifierScope: '0',
        epoch: 0,
      })

      const fileCompleted = new File([manifestOne], '/private/user/path/completed_receipt.json', {
        type: 'application/json',
        lastModified: 1700001000,
      })
      const filePending = new File(['synthetic-video-payload-two'], '/private/user/path/pending_clip.mp4', {
        type: 'video/mp4',
        lastModified: 1700002000,
      })
      const fileDuplicateOfPending = new File(['synthetic-video-payload-two'], '/private/user/path/dup_clip.mp4', {
        type: 'video/mp4',
        lastModified: 1700003000,
      })

      const baseConfig: Partial<BatchConfig> = {
        maxConcurrency: 1,
        maxFileSizeBytes: 10 * 1024 * 1024,
        maxTotalSizeBytes: 50 * 1024 * 1024,
        apiBase: 'http://127.0.0.1:5050/',
        contractId: 'CTESTCONTRACT123',
        networkPassphrase: 'Test SDF Network ; September 2015',
        wallet: 'GSECRETWALLETADDRESS',
      }

      const verifier = new BatchVerifier(baseConfig)

      // First run: let item 0 (manifest) finish, then cancel when item 1 starts hashing
      await verifier.runBatch([fileCompleted, filePending, fileDuplicateOfPending], (_prog, snapshot) => {
        if (snapshot[0]?.status === 'manifest-valid' && snapshot[1]?.status === 'hashing') {
          verifier.cancel()
        }
      })

      const checkpoint = verifier.createCheckpoint([fileCompleted, filePending, fileDuplicateOfPending])
      const serialized = JSON.stringify(checkpoint)

      // Privacy invariants: zero raw paths, zero media bytes, zero wallet secrets, and only completed entries saved
      expect(serialized).not.toContain('/private/user/path')
      expect(serialized).not.toContain('completed_receipt.json')
      expect(serialized).not.toContain('pending_clip.mp4')
      expect(serialized).not.toContain('synthetic-video-payload-two')
      expect(serialized).not.toContain('GSECRETWALLETADDRESS')
      expect(checkpoint.inputFingerprints).toHaveLength(3)
      expect(checkpoint.completedEntries).toHaveLength(1)
      expect(checkpoint.completedEntries[0].inputIndex).toBe(0)
      expect(checkpoint.completedEntries[0].status).toBe('manifest-valid')

      // Storage round-trip check
      const memStorage = new CheckpointStorage<BatchVerificationCheckpoint>()
      expect(saveBatchCheckpointToStorage(checkpoint, memStorage)).toBe(true)
      expect(loadBatchCheckpointFromStorage(memStorage)).toEqual(checkpoint)

      // Resume batch: item 0 must NOT have .text() called again; items 1 & 2 finish cleanly
      const textSpy = vi.spyOn(fileCompleted, 'text')
      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation((url: string) => {
          if (url.includes('/api/stego/extract')) {
            return Promise.resolve({
              ok: true,
              json: () => Promise.resolve({ metadata: { protocol: 'harpocrates' } }),
            })
          }
          return Promise.resolve({ ok: true, json: () => Promise.resolve({ events: [] }) })
        }),
      )

      const resumedVerifier = new BatchVerifier(baseConfig)
      const resumed = await resumedVerifier.resumeBatch(
        [fileCompleted, filePending, fileDuplicateOfPending],
        serialized,
      )

      expect(resumed.resumedCount).toBe(1)
      expect(textSpy).not.toHaveBeenCalled()
      expect(resumed.items[0].status).toBe('manifest-valid')
      expect(resumed.items[1].status).not.toBe('cancelled')
      expect(resumed.items[2].status).toBe('duplicate')
      expect(resumed.items[2].duplicateOf).toBe('/private/user/path/pending_clip.mp4')

      textSpy.mockRestore()
      vi.unstubAllGlobals()
    })

    it('rejects checkpoint resume fail-closed when files, policy, or network context no longer match', async () => {
      const f1 = new File(['alpha'], 'a.mp4', { type: 'video/mp4', lastModified: 100 })
      const f2 = new File(['beta'], 'b.mp4', { type: 'video/mp4', lastModified: 200 })

      const cfg: Partial<BatchConfig> = {
        maxFileSizeBytes: 5_000_000,
        maxTotalSizeBytes: 20_000_000,
        apiBase: 'http://127.0.0.1:5050',
        contractId: 'CREGISTRY_A',
        networkPassphrase: 'Test SDF Network ; September 2015',
      }

      const checkpoint = createBatchCheckpoint([f1, f2], [], cfg)

      // Reordered files -> files_mismatch
      expect(() => validateBatchCheckpoint(checkpoint, [f2, f1], cfg)).toThrowError(BatchCheckpointError)
      try {
        validateBatchCheckpoint(checkpoint, [f2, f1], cfg)
      } catch (err) {
        expect((err as BatchCheckpointError).code).toBe('files_mismatch')
      }

      // Modified file bytes/size -> files_mismatch
      const f1Modified = new File(['alpha-tampered'], 'a.mp4', { type: 'video/mp4', lastModified: 100 })
      expect(() => validateBatchCheckpoint(checkpoint, [f1Modified, f2], cfg)).toThrow(/Selected input at index 0/)

      // Policy mismatch -> policy_mismatch
      try {
        validateBatchCheckpoint(checkpoint, [f1, f2], { ...cfg, maxFileSizeBytes: 1_000_000 })
        throw new Error('expected policy_mismatch')
      } catch (err) {
        expect((err as BatchCheckpointError).code).toBe('policy_mismatch')
      }

      // Network / contract / passphrase mismatch -> network_mismatch
      for (const badNet of [
        { ...cfg, apiBase: 'https://other-api.example' },
        { ...cfg, contractId: 'CREGISTRY_B' },
        { ...cfg, networkPassphrase: 'Public Global Stellar Network ; September 2015' },
      ]) {
        const verifier = new BatchVerifier(badNet)
        await expect(verifier.resumeBatch([f1, f2], checkpoint)).rejects.toMatchObject({
          code: 'network_mismatch',
        })
      }

      // Malformed / unsupported version
      expect(() => validateBatchCheckpoint('{bad-json', [f1, f2], cfg)).toThrowError(BatchCheckpointError)
      expect(() =>
        validateBatchCheckpoint({ ...checkpoint, version: 99 }, [f1, f2], cfg),
      ).toThrow(/Unsupported batch checkpoint version/)
    })
  })
})
