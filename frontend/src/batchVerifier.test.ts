import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  BatchCheckpointError,
  BatchVerifier,
  classifyBatchOutcome,
  computeBatchFingerprints,
  computeChunkedSha256,
  computeFileFingerprint,
  tryParseManifest,
  validateBatchCheckpoint,
  type BatchConfig,
  type BatchVerificationCheckpoint,
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
  })

  describe('Resumable Checkpoints', () => {
    it('computes nonsecret file fingerprints sensitive to content changes', async () => {
      const f1 = new File(['alpha payload'], 'clip.mp4', { type: 'video/mp4', lastModified: 1700000000000 })
      const f2 = new File(['omega payload'], 'clip.mp4', { type: 'video/mp4', lastModified: 1700000000000 })

      const fp1 = await computeFileFingerprint(f1, 0)
      const fp2 = await computeFileFingerprint(f2, 0)

      expect(fp1.fileName).toBe('clip.mp4')
      expect(fp1.fileSizeBytes).toBe(f1.size)
      expect(fp1.sampleHash).toMatch(/^[0-9a-f]{64}$/)
      expect(fp1.sampleHash).not.toBe(fp2.sampleHash)
    })

    it('resumes a cancelled batch without re-verifying completed items and persists no secrets', async () => {
      const fetchMock = vi.fn().mockImplementation((url: string) => {
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
      })
      vi.stubGlobal('fetch', fetchMock)

      const config: Partial<BatchConfig> = {
        maxConcurrency: 1,
        maxFileSizeBytes: 1024 * 1024,
        maxTotalSizeBytes: 5 * 1024 * 1024,
        apiBase: 'http://127.0.0.1:5050',
        contractId: '',
        network: 'testnet',
        wallet: 'GSECRETWALLETADDRESS',
      }

      const f1 = new File(['synthetic-media-one'], 'one.mp4', { type: 'video/mp4', lastModified: 1000 })
      const f2 = new File(['synthetic-media-two'], 'two.mp4', { type: 'video/mp4', lastModified: 2000 })

      const verifier1 = new BatchVerifier(config)
      let savedCheckpoint: BatchVerificationCheckpoint | null = null

      const firstRun = await verifier1.runBatch([f1, f2], undefined, {
        onCheckpoint: (cp) => {
          savedCheckpoint = cp
          if (cp.completed.length === 1) {
            verifier1.cancel()
          }
        },
      })

      expect(firstRun.items[0].status).not.toBe('pending')
      expect(firstRun.items[0].status).not.toBe('cancelled')
      expect(firstRun.items[1].status).toBe('cancelled')
      expect(savedCheckpoint).not.toBeNull()
      expect(savedCheckpoint!.completed).toHaveLength(1)
      expect(savedCheckpoint!.completed[0].index).toBe(0)

      // Checkpoint must persist only nonsecret fingerprints & completed results
      const serialized = JSON.stringify(savedCheckpoint)
      expect(serialized).not.toContain('synthetic-media-one')
      expect(serialized).not.toContain('synthetic-media-two')
      expect(serialized).not.toContain('GSECRETWALLETADDRESS')

      const callsAfterFirstRun = fetchMock.mock.calls.length

      // Resume with a fresh verifier instance using the exact same files & context
      const verifier2 = new BatchVerifier(config)
      const resumed = await verifier2.resumeBatch([f1, f2], savedCheckpoint!)

      expect(resumed.items[0].status).toBe(firstRun.items[0].status)
      expect(resumed.items[1].status).not.toBe('cancelled')
      expect(resumed.items[1].status).not.toBe('pending')
      expect(resumed.checkpoint.completed).toHaveLength(2)

      // Only the second file should have triggered network calls
      const callsDuringResume = fetchMock.mock.calls.length - callsAfterFirstRun
      expect(callsDuringResume).toBe(callsAfterFirstRun)

      vi.unstubAllGlobals()
    })

    it('rejects resume when input files, policy, or network context no longer match', async () => {
      const config: Partial<BatchConfig> = {
        maxConcurrency: 1,
        maxFileSizeBytes: 1024,
        maxTotalSizeBytes: 4096,
        apiBase: 'http://127.0.0.1:5050',
        contractId: 'CTEST123',
        network: 'testnet',
      }

      const f1 = new File(['payload-a'], 'a.mp4', { type: 'video/mp4', lastModified: 1000 })
      const f2 = new File(['payload-b'], 'b.mp4', { type: 'video/mp4', lastModified: 2000 })

      const fingerprints = await computeBatchFingerprints([f1, f2])
      const verifier = new BatchVerifier(config)
      const validCheckpoint: BatchVerificationCheckpoint = {
        protocol: 'harpocrates-batch-checkpoint',
        version: 1,
        createdAt: '2026-11-19T00:00:00.000Z',
        updatedAt: '2026-11-19T00:00:00.000Z',
        policy: { maxFileSizeBytes: 1024, maxTotalSizeBytes: 4096 },
        networkContext: { apiBase: 'http://127.0.0.1:5050', contractId: 'CTEST123', network: 'testnet' },
        files: fingerprints,
        completed: [],
      }

      // 1. Modified file content
      const f2Modified = new File(['payload-x'], 'b.mp4', { type: 'video/mp4', lastModified: 2000 })
      await expect(verifier.resumeBatch([f1, f2Modified], validCheckpoint)).rejects.toMatchObject({
        name: 'BatchCheckpointError',
        reason: 'files-mismatch',
      })

      // 2. Reordered files
      await expect(verifier.resumeBatch([f2, f1], validCheckpoint)).rejects.toMatchObject({
        name: 'BatchCheckpointError',
        reason: 'files-mismatch',
      })

      // 3. Policy mismatch
      const policyVerifier = new BatchVerifier({ ...config, maxFileSizeBytes: 2048 })
      await expect(policyVerifier.resumeBatch([f1, f2], validCheckpoint)).rejects.toMatchObject({
        name: 'BatchCheckpointError',
        reason: 'policy-mismatch',
      })

      // 4. Network context mismatch (contractId, apiBase, or network)
      const networkVerifier = new BatchVerifier({ ...config, network: 'mainnet' })
      await expect(networkVerifier.resumeBatch([f1, f2], validCheckpoint)).rejects.toMatchObject({
        name: 'BatchCheckpointError',
        reason: 'network-mismatch',
      })

      const contractVerifier = new BatchVerifier({ ...config, contractId: 'COTHER999' })
      await expect(contractVerifier.resumeBatch([f1, f2], validCheckpoint)).rejects.toMatchObject({
        name: 'BatchCheckpointError',
        reason: 'network-mismatch',
      })

      // 5. Invalid completed status (e.g. 'cancelled' injected into completed)
      const invalidStatusCheckpoint = {
        ...validCheckpoint,
        completed: [
          {
            index: 0,
            fileName: 'a.mp4',
            fileSizeBytes: f1.size,
            status: 'cancelled' as const,
            videoHash: null,
            metadataHash: null,
            sourceHash: null,
            tier: null,
            chainStatus: null,
            message: 'Cancelled',
            duplicateOf: null,
            failureReason: null,
            durationMs: 1,
          },
        ],
      }
      const validation = validateBatchCheckpoint(invalidStatusCheckpoint, fingerprints, verifier.getConfig())
      expect(validation.ok).toBe(false)
      if (!validation.ok) {
        expect(validation.reason).toBe('invalid-format')
      }
      await expect(verifier.resumeBatch([f1, f2], invalidStatusCheckpoint)).rejects.toBeInstanceOf(
        BatchCheckpointError,
      )
    })
  })

  describe('Per-item cancellation and result classification', () => {
    afterEach(() => {
      vi.restoreAllMocks()
    })

    it('classifies batch outcomes into verified, skipped, cancelled, failed, and in-progress', () => {
      expect(classifyBatchOutcome('confirmed')).toBe('verified')
      expect(classifyBatchOutcome('manifest-valid')).toBe('verified')
      expect(classifyBatchOutcome('duplicate')).toBe('skipped')
      expect(classifyBatchOutcome('oversized')).toBe('skipped')
      expect(classifyBatchOutcome('cancelled')).toBe('cancelled')
      expect(classifyBatchOutcome('error')).toBe('failed')
      expect(classifyBatchOutcome('malformed')).toBe('failed')
      expect(classifyBatchOutcome('unavailable')).toBe('failed')
      expect(classifyBatchOutcome('revoked')).toBe('failed')
      expect(classifyBatchOutcome('metadata-only')).toBe('failed')
      expect(classifyBatchOutcome('database-only')).toBe('failed')
      expect(classifyBatchOutcome('manifest-invalid')).toBe('failed')
      expect(classifyBatchOutcome('pending')).toBe('in-progress')
      expect(classifyBatchOutcome('hashing')).toBe('in-progress')
      expect(classifyBatchOutcome('processing')).toBe('in-progress')
    })

    it('cancels a queued item without stopping unrelated items and distinguishes verified, skipped, cancelled, and failed', async () => {
      const verifySpy = vi.spyOn(verificationFlow, 'verifyArtifact').mockImplementation(async ({ file }) => {
        if (file.name === 'bad.mp4') {
          return {
            outcome: 'malformed',
            message: 'Malformed synthetic evidence.',
            events: [],
            chainProof: null,
          }
        }
        return {
          outcome: 'confirmed',
          message: 'Confirmed synthetic evidence.',
          events: [],
          chainProof: null,
        }
      })

      const verifier = new BatchVerifier({
        maxConcurrency: 1,
        maxFileSizeBytes: 100,
        maxTotalSizeBytes: 1000,
        contractId: '',
      })

      const fVerified = new File(['verified-1'], 'verified.mp4', { type: 'video/mp4' })
      const fQueuedToCancel = new File(['cancel-me'], 'cancel-queued.mp4', { type: 'video/mp4' })
      const fFailed = new File(['failed-1'], 'bad.mp4', { type: 'video/mp4' })
      const fSkipped = new File(['x'.repeat(200)], 'oversized.mp4', { type: 'video/mp4' })

      let cancelledQueued = false
      const { items, summary } = await verifier.runBatch(
        [fVerified, fQueuedToCancel, fFailed, fSkipped],
        (_progress, currentItems) => {
          if (!cancelledQueued) {
            const target = currentItems.find((i) => i.fileName === 'cancel-queued.mp4' && i.status === 'pending')
            if (target) {
              cancelledQueued = verifier.cancelItem(target.id)
            }
          }
        },
      )

      expect(cancelledQueued).toBe(true)
      expect(verifySpy).toHaveBeenCalledTimes(2) // verified.mp4 and bad.mp4 only
      expect(items.find((i) => i.fileName === 'verified.mp4')?.status).toBe('confirmed')
      expect(items.find((i) => i.fileName === 'cancel-queued.mp4')?.status).toBe('cancelled')
      expect(items.find((i) => i.fileName === 'bad.mp4')?.status).toBe('malformed')
      expect(items.find((i) => i.fileName === 'oversized.mp4')?.status).toBe('oversized')

      expect(summary.verified).toBe(1)
      expect(summary.skipped).toBe(1)
      expect(summary.cancelled).toBe(1)
      expect(summary.failed).toBe(1)
    })

    it('cancels an active item mid-flight without aborting unrelated items and releases its hash for later duplicates', async () => {
      let resolveActive!: () => void
      let activeStarted!: () => void
      const activeStartedPromise = new Promise<void>((resolve) => {
        activeStarted = resolve
      })
      let activeSignalAborted = false

      vi.spyOn(verificationFlow, 'verifyArtifact').mockImplementation(async ({ file, signal }) => {
        if (file.name === 'active.mp4') {
          activeStarted()
          await new Promise<void>((resolve) => {
            resolveActive = resolve
            signal?.addEventListener(
              'abort',
              () => {
                activeSignalAborted = true
                resolve()
              },
              { once: true },
            )
          })
          return {
            outcome: 'confirmed',
            message: 'Should not overwrite cancelled state.',
            events: [],
            chainProof: null,
          }
        }
        return {
          outcome: 'confirmed',
          message: 'Unrelated item confirmed.',
          events: [],
          chainProof: null,
        }
      })

      const verifier = new BatchVerifier({
        maxConcurrency: 2,
        contractId: '',
      })

      // Third file has identical content to active.mp4; since active.mp4 is cancelled,
      // later-copy.mp4 must still be verified rather than skipped as a duplicate.
      const fActive = new File(['shared-payload'], 'active.mp4', { type: 'video/mp4' })
      const fUnrelated = new File(['unrelated-payload'], 'unrelated.mp4', { type: 'video/mp4' })
      const fLaterCopy = new File(['shared-payload'], 'later-copy.mp4', { type: 'video/mp4' })

      const batchPromise = verifier.runBatch([fActive, fUnrelated, fLaterCopy])
      await activeStartedPromise

      const activeItem = verifier.getItems().find((i) => i.fileName === 'active.mp4')
      expect(activeItem).toBeDefined()
      expect(verifier.cancelItem(activeItem!.id)).toBe(true)
      resolveActive()

      const { items, summary } = await batchPromise

      expect(activeSignalAborted).toBe(true)
      expect(items.find((i) => i.fileName === 'active.mp4')?.status).toBe('cancelled')
      expect(items.find((i) => i.fileName === 'unrelated.mp4')?.status).toBe('confirmed')
      expect(items.find((i) => i.fileName === 'later-copy.mp4')?.status).toBe('confirmed')
      expect(summary.cancelled).toBe(1)
      expect(summary.verified).toBe(2)
      expect(summary.skipped).toBe(0)
      expect(summary.failed).toBe(0)
    })

    it('returns false when cancelling unknown, already-completed, or already-cancelled items', async () => {
      vi.spyOn(verificationFlow, 'verifyArtifact').mockResolvedValue({
        outcome: 'confirmed',
        message: 'Confirmed.',
        events: [],
        chainProof: null,
      })

      const verifier = new BatchVerifier({ maxConcurrency: 1, contractId: '' })
      const f1 = new File(['done-payload'], 'done.mp4', { type: 'video/mp4' })
      const { items } = await verifier.runBatch([f1])

      expect(verifier.cancelItem('non-existent-id')).toBe(false)
      expect(verifier.cancelItem(items[0].id)).toBe(false)
      expect(verifier.getItems()[0].status).toBe('confirmed')
    })
  })
})
