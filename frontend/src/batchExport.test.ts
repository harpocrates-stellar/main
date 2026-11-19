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

  it('exportBatchCSV neutralizes spreadsheet formula prefixes while preserving digests and numeric fields', () => {
    const formulaItems: BatchItemResult[] = [
      {
        ...mockItems[0],
        fileName: '=HYPERLINK("http://evil.example","click")',
        message: '+cmd|"/C calc"!A0',
        duplicateOf: '-1+1',
        failureReason: '@SUM(1,2)',
      },
      {
        ...mockItems[0],
        id: 'item-tab-cr',
        fileName: '\t=1+1',
        message: '\r=2+2',
      },
    ]

    const csvStr = exportBatchCSV(formulaItems)
    const lines = csvStr.split('\n')
    expect(lines).toHaveLength(3)

    // Formula prefixes are neutralized with a leading apostrophe
    expect(lines[1]).toContain('"\'=HYPERLINK(""http://evil.example"",""click"")"')
    expect(lines[1]).toContain('"\'+cmd|""/C calc""!A0"')
    expect(lines[1]).toContain('\'-1+1')
    expect(lines[1]).toContain('"\'@SUM(1,2)"')

    // Tab and CR prefixes are neutralized
    expect(lines[2]).toContain("'\t=1+1")
    expect(lines[2]).toContain('"\'\r=2+2"')

    // Exact digest and numeric fields remain unescaped
    expect(lines[1]).toContain(',1024,confirmed,1111222233334444555566667777888811112222333344445555666677778888,')
    expect(lines[1]).toContain(',120')

    // Machine-readable JSON export preserves raw unescaped values
    const jsonStr = exportBatchJSON(formulaItems)
    const parsed = JSON.parse(jsonStr) as { results: Array<{ fileName: string; message: string }> }
    expect(parsed.results[0].fileName).toBe('=HYPERLINK("http://evil.example","click")')
    expect(parsed.results[0].message).toBe('+cmd|"/C calc"!A0')
  })
})
