import { describe, expect, it } from 'vitest'
import type { BatchItemResult } from './batchVerifier'
import {
  BATCH_EXPORT_FORMAT_SEMANTICS,
  exportBatchCSV,
  exportBatchJSON,
  exportReceiptCollection,
  neutralizeSpreadsheetFormula,
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

  it('neutralizes spreadsheet formula prefixes in CSV text columns while keeping digests, amounts, and JSON exact', () => {
    expect(BATCH_EXPORT_FORMAT_SEMANTICS.csv.neutralizesFormulaPrefixes).toBe(true)
    expect(BATCH_EXPORT_FORMAT_SEMANTICS.json.neutralizesFormulaPrefixes).toBe(false)

    expect(neutralizeSpreadsheetFormula('=CMD|\' /C calc\'!A0')).toBe('\'=CMD|\' /C calc\'!A0')
    expect(neutralizeSpreadsheetFormula('+SUM(1,2)')).toBe('\'+SUM(1,2)')
    expect(neutralizeSpreadsheetFormula('-2+3')).toBe('\'-2+3')
    expect(neutralizeSpreadsheetFormula('@SUM(A1:A2)')).toBe('\'@SUM(A1:A2)')
    expect(neutralizeSpreadsheetFormula('\t=1+1')).toBe('\'\t=1+1')
    expect(neutralizeSpreadsheetFormula('  =HYPERLINK("http://evil.invalid")')).toBe(
      '\'  =HYPERLINK("http://evil.invalid")',
    )
    expect(neutralizeSpreadsheetFormula('benign_clip.mp4')).toBe('benign_clip.mp4')

    const videoHash = 'deadbeef'.repeat(8)
    const metadataHash = 'cafebabe'.repeat(8)
    const sourceHash = '01234567'.repeat(8)

    const riskyItems: BatchItemResult[] = [
      {
        id: 'formula-1',
        file: new File(['synthetic'], '=SUM(1,1).mp4', { type: 'video/mp4' }),
        fileName: '=SUM(1,1).mp4',
        fileSizeBytes: 65536,
        status: 'error',
        videoHash,
        metadataHash,
        sourceHash,
        tier: 'silent',
        chainStatus: 'Active',
        message: '+cmd|" /C calc"!A0',
        events: [],
        chainProof: null,
        duplicateOf: '@IMPORTXML("https://evil.invalid","//a")',
        manifest: null,
        durationMs: 345,
        failureReason: '-10+20,\r=INJECT()',
      },
    ]

    const csv = exportBatchCSV(riskyItems)
    expect(csv).toContain('"\'=SUM(1,1).mp4",65536,error,')
    expect(csv).toContain(`${videoHash},${metadataHash},${sourceHash},silent,Active`)
    expect(csv).toContain('"\'+cmd|"" /C calc""!A0"')
    expect(csv).toContain('"\'@IMPORTXML(""https://evil.invalid"",""//a"")"')
    expect(csv).toContain('"\'-10+20,\r=INJECT()",345')

    const json = JSON.parse(exportBatchJSON(riskyItems)) as {
      results: Array<{ fileName: string; message: string; duplicateOf: string; videoHash: string; fileSizeBytes: number }>
    }
    expect(json.results[0].fileName).toBe('=SUM(1,1).mp4')
    expect(json.results[0].message).toBe('+cmd|" /C calc"!A0')
    expect(json.results[0].duplicateOf).toBe('@IMPORTXML("https://evil.invalid","//a")')
    expect(json.results[0].videoHash).toBe(videoHash)
    expect(json.results[0].fileSizeBytes).toBe(65536)
  })
})
