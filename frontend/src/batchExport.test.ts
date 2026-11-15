import { describe, expect, it } from 'vitest'
import type { BatchItemResult } from './batchVerifier'
import {
  exportBatchCSV,
  exportBatchJSON,
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

  it('exportBatchJSON produces valid privacy-safe JSON with completeness summary', () => {
    const jsonStr = exportBatchJSON(mockItems)
    const parsed = JSON.parse(jsonStr) as {
      protocol: string
      totalCount: number
      completeness: {
        verified: number
        failed: number
        cancelled: number
        incomplete: number
        unresolvedChecks: number
        isComplete: boolean
      }
    }
    expect(parsed.protocol).toBe('harpocrates-batch-report')
    expect(parsed.totalCount).toBe(2)
    expect(parsed.completeness).toMatchObject({
      verified: 1,
      failed: 1,
      cancelled: 0,
      incomplete: 0,
      unresolvedChecks: 0,
      isComplete: true,
    })
    expect(jsonStr).not.toContain('media bytes')

    const interruptedJson = JSON.parse(exportBatchJSON(mockItems, { isInterrupted: true })) as {
      completeness: { isComplete: boolean; isInterrupted: boolean; runState: string }
    }
    expect(interruptedJson.completeness.isInterrupted).toBe(true)
    expect(interruptedJson.completeness.isComplete).toBe(false)
    expect(interruptedJson.completeness.runState).toBe('interrupted')
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
})
