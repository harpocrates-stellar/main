import { describe, expect, it } from 'vitest'
import type { BatchItemResult } from './batchVerifier'
import {
  buildBatchArchiveEntries,
  exportBatchArchiveManifest,
  exportBatchCSV,
  exportBatchJSON,
  exportReceiptCollection,
  MAX_ARCHIVE_PATH_LENGTH,
  MAX_ARCHIVE_STEM_LENGTH,
  sanitizeArchiveStem,
  sanitizeBatchResults,
} from './batchExport'

function makeItem(overrides: Partial<BatchItemResult> & { id: string; fileName: string }): BatchItemResult {
  return {
    id: overrides.id,
    file: new File(['synthetic'], overrides.fileName, { type: 'video/mp4' }),
    fileName: overrides.fileName,
    fileSizeBytes: overrides.fileSizeBytes ?? 1024,
    status: overrides.status ?? 'confirmed',
    videoHash: overrides.videoHash ?? null,
    metadataHash: overrides.metadataHash ?? null,
    sourceHash: overrides.sourceHash ?? null,
    tier: overrides.tier ?? null,
    chainStatus: overrides.chainStatus ?? null,
    message: overrides.message ?? 'Verified',
    events: overrides.events ?? [],
    chainProof: overrides.chainProof ?? null,
    duplicateOf: overrides.duplicateOf ?? null,
    manifest: overrides.manifest ?? null,
    durationMs: overrides.durationMs ?? 10,
    failureReason: overrides.failureReason ?? null,
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

  it('sanitizeBatchResults strips raw File handles and preserves source item association', () => {
    const sanitized = sanitizeBatchResults(mockItems)
    expect(sanitized).toHaveLength(2)
    expect(sanitized[0].fileName).toBe('evidence1.mp4')
    expect(sanitized[0].sourceItemId).toBe('item-1')
    expect(sanitized[0].sourceIndex).toBe(0)
    expect(sanitized[0].outputPath).toBe('items/evidence1.json')
    expect((sanitized[0] as Record<string, unknown>).file).toBeUndefined()
  })

  it('exportBatchJSON produces valid privacy-safe JSON with bounded archive entries', () => {
    const jsonStr = exportBatchJSON(mockItems)
    const parsed = JSON.parse(jsonStr) as Record<string, unknown>
    expect(parsed.protocol).toBe('harpocrates-batch-report')
    expect(parsed.totalCount).toBe(2)
    expect(Array.isArray(parsed.archiveEntries)).toBe(true)
    expect(jsonStr).not.toContain('media bytes')
  })

  it('exportBatchCSV produces properly formatted CSV with headers and output paths', () => {
    const csvStr = exportBatchCSV(mockItems)
    expect(csvStr).toContain('File Name,Size (Bytes),Status,Video Hash')
    expect(csvStr).toContain('evidence1.mp4,1024,confirmed')
    expect(csvStr).toContain('large.mp4,200000000,oversized')
    expect(csvStr).toContain('item-1,items/evidence1.json')
  })

  it('exportReceiptCollection exports valid manifest collections and item associations', () => {
    const collectionJson = exportReceiptCollection(mockItems)
    const parsed = JSON.parse(collectionJson) as {
      protocol: string
      totalItems: number
      itemAssociations: Array<{ sourceItemId: string; outputPath: string }>
    }
    expect(parsed.protocol).toBe('harpocrates-receipt-collection')
    expect(parsed.totalItems).toBe(1)
    expect(parsed.itemAssociations).toEqual([
      expect.objectContaining({
        sourceItemId: 'item-1',
        outputPath: 'items/evidence1.receiptjson',
      }),
    ])
  })

  it('bounds archive stems, strips path traversal, and guards Windows reserved names', () => {
    const overlong = `${'a'.repeat(160)}.mp4`
    const stem = sanitizeArchiveStem(overlong)
    expect(stem.length).toBeLessThanOrEqual(MAX_ARCHIVE_STEM_LENGTH)
    expect(sanitizeArchiveStem('../../secret/folder/field_clip?.mp4')).toBe('field_clip')
    expect(sanitizeArchiveStem('CON.mp4')).toBe('item-CON')
    expect(sanitizeArchiveStem('...')).toBe('item')
  })

  it('generates collision-safe deterministic output paths and preserves source mappings', () => {
    const longPrefix = 'field-footage-camera-alpha-north-sector-incident-recording'
    const colliding = [
      makeItem({
        id: 'src-a',
        fileName: 'cam1/clip.mp4',
        videoHash: 'aaaa1111'.padEnd(64, '0'),
      }),
      makeItem({
        id: 'src-b',
        fileName: 'cam2/CLIP.mp4',
        videoHash: 'bbbb2222'.padEnd(64, '0'),
      }),
      makeItem({
        id: 'src-c',
        fileName: `${longPrefix}-part-one.mp4`,
        fileSizeBytes: 2048,
      }),
      makeItem({
        id: 'src-d',
        fileName: `${longPrefix}-part-two.mp4`,
        fileSizeBytes: 4096,
      }),
      makeItem({
        id: 'src-e',
        fileName: 'cam1/clip.mp4',
        videoHash: 'aaaa1111'.padEnd(64, '0'),
      }),
    ]

    const firstRun = buildBatchArchiveEntries(colliding)
    const secondRun = buildBatchArchiveEntries(colliding)
    expect(secondRun).toEqual(firstRun)

    const lowerPaths = firstRun.map((entry) => entry.outputPath.toLowerCase())
    expect(new Set(lowerPaths).size).toBe(colliding.length)
    for (let i = 0; i < colliding.length; i += 1) {
      expect(firstRun[i].outputPath.length).toBeLessThanOrEqual(MAX_ARCHIVE_PATH_LENGTH)
      expect(firstRun[i].sourceItemId).toBe(colliding[i].id)
      expect(firstRun[i].sourceIndex).toBe(i)
      expect(firstRun[i].sourceFileName).toBe(colliding[i].fileName)
      expect(firstRun[i].collisionResolved).toBe(true)
    }

    const archiveJson = JSON.parse(exportBatchArchiveManifest(colliding)) as {
      protocol: string
      totalEntries: number
      entries: Array<{ sourceItemId: string; outputPath: string }>
    }
    expect(archiveJson.protocol).toBe('harpocrates-batch-archive-manifest')
    expect(archiveJson.totalEntries).toBe(5)
    expect(archiveJson.entries.map((e) => e.sourceItemId)).toEqual(['src-a', 'src-b', 'src-c', 'src-d', 'src-e'])
  })

  it('rejects directory configurations that exceed the bounded archive path budget', () => {
    expect(() =>
      buildBatchArchiveEntries(mockItems, {
        directory: 'nested/'.repeat(20),
      }),
    ).toThrow(/exceed bounded archive path budget/)
    expect(() => sanitizeArchiveStem('clip.mp4', 2)).toThrow(/at least 4 characters/)
  })
})
