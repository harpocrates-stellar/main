import { describe, expect, it } from 'vitest'
import type { BatchItemResult, BatchPreflightReport } from './batchVerifier'
import {
  exportBatchCSV,
  exportBatchJSON,
  exportPreflightReportCSV,
  exportPreflightReportJSON,
  exportReceiptCollection,
  sanitizeBatchResults,
} from './batchExport'

describe('batchExport', () => {
  const mockItems: BatchItemResult[] = [
    {
      id: 'item-1',
      file: new File(['media bytes'], 'evidence1.mp4', { type: 'video/mp4' }),
      fileName: 'evidence1.mp4',
      fileSizeBytes: 1024,
      status: 'confirmed',
      videoHash: '1111222233334444555566667777888811112222333344445555666677778888',
      metadataHash: 'aaaa222233334444555566667777888811112222333344445555666677778888',
      sourceHash: '1111222233334444555566667777888811112222333344445555666677778888',
      tier: 'silent',
      chainStatus: 'Active',
      message: 'Confirmed evidence',
      events: [],
      chainProof: null,
      duplicateOf: null,
      manifest: null,
      durationMs: 120,
      failureReason: null,
    },
    {
      id: 'item-2',
      file: new File(['oversized media'], 'large.mp4', { type: 'video/mp4' }),
      fileName: 'large.mp4',
      fileSizeBytes: 200000000,
      status: 'oversized',
      videoHash: null,
      metadataHash: null,
      sourceHash: null,
      tier: null,
      chainStatus: null,
      message: 'File exceeds size limit',
      events: [],
      chainProof: null,
      duplicateOf: null,
      manifest: null,
      durationMs: 5,
      failureReason: 'Per-file limit exceeded',
    },
  ]

  it('sanitizeBatchResults strips raw File handles and media buffers', () => {
    const sanitized = sanitizeBatchResults(mockItems)
    expect(sanitized).toHaveLength(2)
    expect(sanitized[0].fileName).toBe('evidence1.mp4')
    expect((sanitized[0] as Record<string, unknown>).file).toBeUndefined()
  })

  it('exportBatchJSON produces valid privacy-safe JSON', () => {
    const jsonStr = exportBatchJSON(mockItems)
    const parsed = JSON.parse(jsonStr) as Record<string, unknown>
    expect(parsed.protocol).toBe('harpocrates-batch-report')
    expect(parsed.totalCount).toBe(2)
    expect(jsonStr).not.toContain('media bytes')
  })

  it('exportBatchCSV produces properly formatted CSV with headers', () => {
    const csvStr = exportBatchCSV(mockItems)
    expect(csvStr).toContain('File Name,Size (Bytes),Status,Video Hash')
    expect(csvStr).toContain('evidence1.mp4,1024,confirmed')
    expect(csvStr).toContain('large.mp4,200000000,oversized')
  })

  it('exportReceiptCollection exports valid manifest collections', () => {
    const collectionJson = exportReceiptCollection(mockItems)
    const parsed = JSON.parse(collectionJson) as Record<string, unknown>
    expect(parsed.protocol).toBe('harpocrates-receipt-collection')
    expect(parsed.totalItems).toBe(1)
  })

  describe('Preflight report exports (issue #1167)', () => {
    const mockPreflight: BatchPreflightReport = {
      totalFiles: 3,
      totalBytes: 5000000,
      validCount: 1,
      duplicateCount: 1,
      unsupportedCount: 1,
      oversizedCount: 0,
      hasIssues: true,
      canProceed: true,
      completedAt: '2026-11-22T20:00:00.000Z',
      duplicates: [
        {
          index: 1,
          fileName: 'evidence1.mp4',
          fileSizeBytes: 1024,
          duplicateOf: 'evidence1.mp4',
          reason: "Duplicate input matching 'evidence1.mp4' (1024 bytes).",
        },
      ],
      unsupported: [
        {
          index: 2,
          fileName: 'notes.txt',
          fileSizeBytes: 200,
          mimeType: 'text/plain',
          extension: '.txt',
          reason: "Unsupported format '.txt'.",
        },
      ],
      oversized: [],
    }

    it('exportPreflightReportJSON outputs structured preflight JSON', () => {
      const json = exportPreflightReportJSON(mockPreflight)
      const parsed = JSON.parse(json) as Record<string, unknown>
      expect(parsed.protocol).toBe('harpocrates-preflight-report')
      expect(parsed.totalFiles).toBe(3)
      expect(parsed.totalBytes).toBe(5000000)
      expect(parsed.validCount).toBe(1)
      expect(parsed.duplicateCount).toBe(1)
      expect(parsed.unsupportedCount).toBe(1)
      expect(parsed.duplicates).toHaveLength(1)
      expect(parsed.unsupported).toHaveLength(1)
    })

    it('exportPreflightReportCSV outputs formatted CSV report', () => {
      const csv = exportPreflightReportCSV(mockPreflight)
      expect(csv).toContain('Category,File Name,Size (Bytes),Details,Reason')
      expect(csv).toContain('Duplicate Input,evidence1.mp4,1024,Duplicate of evidence1.mp4')
      expect(csv).toContain('Unsupported Format,notes.txt,200')
    })

    it('exportBatchJSON embeds preflight metrics when provided', () => {
      const json = exportBatchJSON(mockItems, mockPreflight)
      const parsed = JSON.parse(json) as Record<string, unknown>
      expect(parsed.protocol).toBe('harpocrates-batch-report')
      expect(parsed.preflight).toBeDefined()
      const pf = parsed.preflight as Record<string, unknown>
      expect(pf.totalFiles).toBe(3)
      expect(pf.duplicateCount).toBe(1)
      expect(pf.unsupportedCount).toBe(1)
    })
  })
})
