import { describe, expect, it } from 'vitest'
import type { BatchItemResult } from './batchVerifier'
import {
  DEFAULT_MAX_ARCHIVE_FILENAME_LENGTH,
  boundArchiveFilename,
  buildBatchArchiveEntries,
  exportBatchArchiveManifest,
  exportBatchCSV,
  exportBatchJSON,
  exportReceiptCollection,
  sanitizeBatchResults,
  type BatchArchiveManifest,
} from './batchExport'
import { summarizeBatchCompleteness } from './batchVerifier'

function makeItem(overrides: Partial<BatchItemResult> & { id: string; fileName: string }): BatchItemResult {
  const { id, fileName, ...rest } = overrides
  return {
    id,
    file: new File(['synthetic media'], fileName, { type: 'video/mp4' }),
    fileName,
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
    ...rest,
  }
}

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
    expect(sanitized[0].sourceItemId).toBe('item-1')
    expect(sanitized[0].fileName).toBe('evidence1.mp4')
    expect(sanitized[0].archiveFileName).toBe('evidence1.mp4')
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

  it('boundArchiveFilename sanitizes traversal, unsafe characters, reserved names, and enforces max length', () => {
    expect(boundArchiveFilename('../../secret/folder/clip:01?.mp4')).toBe('clip_01.mp4')
    expect(boundArchiveFilename('..\\..\\CON.mp4')).toBe('item_CON.mp4')
    expect(boundArchiveFilename('...///...')).toBe('item')

    const longName = `${'a'.repeat(180)}.mp4`
    const bounded = boundArchiveFilename(longName)
    expect(bounded.length).toBeLessThanOrEqual(DEFAULT_MAX_ARCHIVE_FILENAME_LENGTH)
    expect(bounded.endsWith('.mp4')).toBe(true)

    const withDir = boundArchiveFilename('clip.mp4', { directory: '../receipts/2026', extension: 'json' })
    expect(withDir).toBe('receipts/2026/clip.json')
  })

  it('boundArchiveFilename fails closed on invalid maxLength bounds', () => {
    expect(() => boundArchiveFilename('clip.mp4', { maxLength: 0 })).toThrow(RangeError)
    expect(() => boundArchiveFilename('clip.mp4', { maxLength: 10 })).toThrow(RangeError)
    expect(() => boundArchiveFilename('clip.mp4', { maxLength: 300 })).toThrow(RangeError)
    expect(() => boundArchiveFilename('clip.mp4', { maxLength: 32.5 })).toThrow(RangeError)
  })

  it('buildBatchArchiveEntries prevents duplicate output paths deterministically across collisions and truncation', () => {
    const sharedPrefix = 'x'.repeat(30)
    const items: BatchItemResult[] = [
      makeItem({ id: 'src-1', fileName: 'evidence.mp4' }),
      makeItem({ id: 'src-2', fileName: 'Evidence.mp4' }),
      makeItem({ id: 'src-3', fileName: 'nested/dir/evidence.mp4' }),
      makeItem({ id: 'src-4', fileName: `${sharedPrefix}-first.mp4` }),
      makeItem({ id: 'src-5', fileName: `${sharedPrefix}-second.mp4` }),
    ]

    const firstRun = buildBatchArchiveEntries(items, { maxLength: 24 })
    const secondRun = buildBatchArchiveEntries(items, { maxLength: 24 })

    expect(firstRun.map((e) => e.outputPath)).toEqual(secondRun.map((e) => e.outputPath))

    const lowerPaths = firstRun.map((e) => e.outputPath.toLowerCase())
    expect(new Set(lowerPaths).size).toBe(items.length)

    for (const entry of firstRun) {
      expect(entry.outputPath.length).toBeLessThanOrEqual(24)
    }

    expect(firstRun[0].outputPath).toBe('evidence.mp4')
    expect(firstRun[1].outputPath).toBe('Evidence-2.mp4')
    expect(firstRun[2].outputPath).toBe('evidence-3.mp4')

    // Preserves 1:1 association between every exported result and its source item
    expect(firstRun.map((e) => e.sourceItemId)).toEqual(['src-1', 'src-2', 'src-3', 'src-4', 'src-5'])
    expect(firstRun.map((e) => e.sourceFileName)).toEqual(items.map((i) => i.fileName))
    expect(firstRun.map((e) => e.result.sourceItemId)).toEqual(['src-1', 'src-2', 'src-3', 'src-4', 'src-5'])
    expect(firstRun.map((e) => e.result.archiveFileName)).toEqual(firstRun.map((e) => e.outputPath))
  })

  it('exportBatchArchiveManifest serializes bounded collision-safe archive entries without raw media', () => {
    const items: BatchItemResult[] = [
      makeItem({ id: 'a', fileName: 'clip.mp4' }),
      makeItem({ id: 'b', fileName: 'clip.mp4' }),
    ]
    const json = exportBatchArchiveManifest(items, { directory: 'reports', extension: '.json', maxLength: 32 })
    const parsed = JSON.parse(json) as BatchArchiveManifest

    expect(parsed.protocol).toBe('harpocrates-batch-archive')
    expect(parsed.version).toBe(1)
    expect(parsed.maxFileNameLength).toBe(32)
    expect(parsed.totalEntries).toBe(2)
    expect(parsed.entries[0].outputPath).toBe('reports/clip.json')
    expect(parsed.entries[1].outputPath).toBe('reports/clip-2.json')
    expect(parsed.entries[0].sourceItemId).toBe('a')
    expect(parsed.entries[1].sourceItemId).toBe('b')
    expect(json).not.toContain('synthetic media')
  })
})
