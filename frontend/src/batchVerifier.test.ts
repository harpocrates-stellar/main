import { describe, expect, it, vi } from 'vitest'
import {
  BatchVerifier,
  computeChunkedSha256,
  formatBytes,
  isSupportedFormat,
  runBatchPreflight,
  tryParseManifest,
  type BatchConfig,
} from './batchVerifier'

const { StegoError, extractMetadata } = vi.hoisted(() => {
  class StegoError extends Error {
    constructor() {
      super('Malformed evidence')
      this.name = 'MalformedEvidenceError'
    }
  }
  return {
    StegoError,
    extractMetadata: vi.fn().mockImplementation(async (file: { name?: string }) => {
      if (file?.name && (file.name.includes('bad') || file.name.includes('corrupt'))) {
        throw new StegoError()
      }
      return { protocol: 'harpocrates' }
    }),
  }
})

vi.mock('./stego', () => ({
  extractMetadata,
  MalformedEvidenceError: StegoError,
}))

vi.mock('./stellar', () => ({
  getProofByVideoHash: vi.fn().mockResolvedValue(null),
}))

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

  describe('Batch Preflight Report (issue #1167)', () => {
    describe('formatBytes', () => {
      it('formats byte boundaries correctly', () => {
        expect(formatBytes(0)).toBe('0 B')
        expect(formatBytes(500)).toBe('500 B')
        expect(formatBytes(1024)).toBe('1.0 KB')
        expect(formatBytes(1048576)).toBe('1.0 MB')
        expect(formatBytes(1572864)).toBe('1.5 MB')
        expect(formatBytes(1073741824)).toBe('1.0 GB')
      })
    })

    describe('isSupportedFormat', () => {
      it('accepts supported video formats and JSON receipts', () => {
        expect(isSupportedFormat({ name: 'evidence.mp4' }).isSupported).toBe(true)
        expect(isSupportedFormat({ name: 'clip.MOV' }).isSupported).toBe(true)
        expect(isSupportedFormat({ name: 'capture.webm' }).isSupported).toBe(true)
        expect(isSupportedFormat({ name: 'scene.mkv' }).isSupported).toBe(true)
        expect(isSupportedFormat({ name: 'record.avi' }).isSupported).toBe(true)
        expect(isSupportedFormat({ name: 'receipt.json' }).isSupported).toBe(true)
        expect(isSupportedFormat({ name: 'custom', type: 'video/mp4' }).isSupported).toBe(true)
        expect(isSupportedFormat({ name: 'custom', type: 'application/json' }).isSupported).toBe(true)
      })

      it('rejects unsupported extensions and formats with helpful reasons', () => {
        const textResult = isSupportedFormat({ name: 'notes.txt', type: 'text/plain' })
        expect(textResult.isSupported).toBe(false)
        expect(textResult.reason).toContain("Unsupported format '.txt'")

        const pdfResult = isSupportedFormat({ name: 'brief.pdf', type: 'application/pdf' })
        expect(pdfResult.isSupported).toBe(false)

        const exeResult = isSupportedFormat({ name: 'malware.exe' })
        expect(exeResult.isSupported).toBe(false)
      })
    })

    describe('runBatchPreflight', () => {
      it('calculates totalBytes and detects duplicate inputs and unsupported formats', () => {
        const f1 = new File(['video-one-data'], 'video1.mp4', { type: 'video/mp4' })
        const f2 = new File(['video-one-data'], 'video1.mp4', { type: 'video/mp4' }) // Duplicate input
        const f3 = new File(['doc'], 'notes.txt', { type: 'text/plain' }) // Unsupported format
        const f4 = new File(['valid-two-data'], 'video2.webm', { type: 'video/webm' })

        const report = runBatchPreflight([f1, f2, f3, f4])

        expect(report.totalFiles).toBe(4)
        expect(report.totalBytes).toBe(f1.size + f2.size + f3.size + f4.size)
        expect(report.duplicateCount).toBe(1)
        expect(report.duplicates[0].fileName).toBe('video1.mp4')
        expect(report.duplicates[0].duplicateOf).toBe('video1.mp4')
        expect(report.unsupportedCount).toBe(1)
        expect(report.unsupported[0].fileName).toBe('notes.txt')
        expect(report.validCount).toBe(2) // f1 and f4
        expect(report.hasIssues).toBe(true)
        expect(report.canProceed).toBe(true)
      })

      it('handles boundary case: empty file batch', () => {
        const report = runBatchPreflight([])
        expect(report.totalFiles).toBe(0)
        expect(report.totalBytes).toBe(0)
        expect(report.validCount).toBe(0)
        expect(report.duplicateCount).toBe(0)
        expect(report.unsupportedCount).toBe(0)
        expect(report.oversizedCount).toBe(0)
        expect(report.hasIssues).toBe(false)
        expect(report.canProceed).toBe(false)
      })

      it('handles boundary case: files exceeding size limits', () => {
        const small = new File(['small'], 'small.mp4')
        const large = new File(['a'.repeat(500)], 'huge.mp4')

        const report = runBatchPreflight([small, large], { maxFileSizeBytes: 100 })
        expect(report.oversizedCount).toBe(1)
        expect(report.oversized[0].fileName).toBe('huge.mp4')
        expect(report.validCount).toBe(1)
      })
    })

    describe('Verifier execution guarantees', () => {
      it('completes preflight first and does NOT hash or prove unsupported or duplicate input items', async () => {
        const verifier = new BatchVerifier()
        const fValid = new File(['valid video content'], 'valid.mp4', { type: 'video/mp4' })
        const fDup = new File(['valid video content'], 'valid.mp4', { type: 'video/mp4' })
        const fUnsup = new File(['unsupported binary'], 'unsupported.bin', { type: 'application/octet-stream' })

        const { items, summary, preflight } = await verifier.runBatch([fValid, fDup, fUnsup])

        // Verify preflight report was generated
        expect(preflight).toBeDefined()
        expect(preflight.totalFiles).toBe(3)
        expect(preflight.duplicateCount).toBe(1)
        expect(preflight.unsupportedCount).toBe(1)
        expect(preflight.validCount).toBe(1)

        // Verify items terminal statuses
        const dupItem = items.find((i) => i.id !== items[0].id && i.fileName === 'valid.mp4')
        expect(dupItem?.status).toBe('duplicate')
        expect(dupItem?.videoHash).toBeNull() // NO hashing was performed on duplicate input

        const unsupItem = items.find((i) => i.fileName === 'unsupported.bin')
        expect(unsupItem?.status).toBe('unsupported')
        expect(unsupItem?.videoHash).toBeNull() // NO hashing was performed on unsupported file
        expect(unsupItem?.message).toContain("Unsupported format '.bin'")

        // Summary assertions
        expect(summary.totalFiles).toBe(3)
        expect(summary.duplicates).toBe(1)
        expect(summary.unsupported).toBe(1)
      })
    })
  })
})
