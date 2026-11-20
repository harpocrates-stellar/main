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

  it('orders JSON, CSV, and receipt exports by original inputIndex rather than completion order', () => {
    const completionOrderedItems: BatchItemResult[] = [
      {
        ...mockItems[0],
        id: 'input-third',
        inputIndex: 2,
        fileName: 'third.mp4',
        videoHash: '3333222233334444555566667777888811112222333344445555666677778888',
        durationMs: 0,
      },
      {
        ...mockItems[0],
        id: 'input-first',
        inputIndex: 0,
        fileName: 'first.mp4',
        videoHash: '1111222233334444555566667777888811112222333344445555666677778888',
        durationMs: 250,
      },
      {
        ...mockItems[1],
        id: 'input-second',
        inputIndex: 1,
        fileName: 'second.mp4',
        durationMs: 15,
      },
    ]

    const sanitized = sanitizeBatchResults(completionOrderedItems)
    expect(sanitized.map((item) => ({ id: item.id, inputIndex: item.inputIndex, fileName: item.fileName }))).toEqual([
      { id: 'input-first', inputIndex: 0, fileName: 'first.mp4' },
      { id: 'input-second', inputIndex: 1, fileName: 'second.mp4' },
      { id: 'input-third', inputIndex: 2, fileName: 'third.mp4' },
    ])
    // 0 ms duration is preserved instead of coerced to null
    expect(sanitized[2].durationMs).toBe(0)

    const parsedJson = JSON.parse(exportBatchJSON(completionOrderedItems)) as {
      results: Array<{ id: string; inputIndex: number; fileName: string }>
    }
    expect(parsedJson.results.map((r) => r.id)).toEqual(['input-first', 'input-second', 'input-third'])

    const csvLines = exportBatchCSV(completionOrderedItems).split('\n')
    expect(csvLines[0]).toContain('Input Index,Input ID')
    expect(csvLines[1]).toContain('first.mp4')
    expect(csvLines[1].endsWith(',0,input-first')).toBe(true)
    expect(csvLines[2]).toContain('second.mp4')
    expect(csvLines[2].endsWith(',1,input-second')).toBe(true)
    expect(csvLines[3]).toContain('third.mp4')
    expect(csvLines[3].endsWith(',2,input-third')).toBe(true)

    const receipts = JSON.parse(exportReceiptCollection(completionOrderedItems)) as {
      receipts: Array<{ videoHash: string }>
    }
    expect(receipts.receipts.map((r) => r.videoHash)).toEqual([
      '1111222233334444555566667777888811112222333344445555666677778888',
      '3333222233334444555566667777888811112222333344445555666677778888',
    ])
  })

  it('preserves caller order and assigns fallback inputIndex when legacy items omit inputIndex', () => {
    const sanitized = sanitizeBatchResults(mockItems)
    expect(sanitized.map((i) => ({ id: i.id, inputIndex: i.inputIndex }))).toEqual([
      { id: 'item-1', inputIndex: 0 },
      { id: 'item-2', inputIndex: 1 },
    ])
  })
})
