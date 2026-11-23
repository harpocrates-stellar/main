import { describe, expect, it } from 'vitest'
import type { BatchItemResult } from './batchVerifier'
import {
  BATCH_COMPARISON_PROTOCOL,
  BATCH_COMPARISON_VERSION,
  BATCH_REPORT_PROTOCOL,
  BATCH_REPORT_VERSION,
  compareBatchManifests,
  deriveStatementIdentity,
  exportBatchCSV,
  exportBatchComparisonJSON,
  exportBatchJSON,
  exportReceiptCollection,
  parseBatchResultManifest,
  sanitizeBatchResults,
  type BatchResultManifest,
  type CleanBatchReportItem,
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

function makeReportItem(overrides: Partial<CleanBatchReportItem> = {}): CleanBatchReportItem {
  return {
    fileName: 'evidence.mp4',
    fileSizeBytes: 1024,
    status: 'confirmed',
    videoHash: '1111222233334444555566667777888811112222333344445555666677778888',
    metadataHash: 'aaaa222233334444555566667777888811112222333344445555666677778888',
    sourceHash: '1111222233334444555566667777888811112222333344445555666677778888',
    tier: 'silent',
    chainStatus: 'Active',
    message: 'Confirmed evidence',
    duplicateOf: null,
    failureReason: null,
    durationMs: 120,
    ...overrides,
  }
}

function makeManifest(
  results: CleanBatchReportItem[],
  exportedAt = '2026-11-19T00:00:00.000Z',
): BatchResultManifest {
  return {
    protocol: BATCH_REPORT_PROTOCOL,
    version: BATCH_REPORT_VERSION,
    exportedAt,
    totalCount: results.length,
    results,
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

  describe('deterministic batch comparison export', () => {
    const hashA = 'aaaa1111222233334444555566667777aaaa1111222233334444555566667777'
    const hashB = 'bbbb1111222233334444555566667777bbbb1111222233334444555566667777'
    const hashC = 'cccc1111222233334444555566667777cccc1111222233334444555566667777'
    const hashD = 'dddd1111222233334444555566667777dddd1111222233334444555566667777'

    it('separates trust-context changes from added and removed files by statement identity', () => {
      const baseline = makeManifest(
        [
          makeReportItem({
            fileName: 'unchanged.mp4',
            videoHash: hashA,
            status: 'confirmed',
            tier: 'silent',
            chainStatus: 'Active',
          }),
          makeReportItem({
            fileName: 'revoked-later.mp4',
            videoHash: hashB,
            status: 'confirmed',
            tier: 'source',
            chainStatus: 'Active',
          }),
          makeReportItem({
            fileName: 'removed.mp4',
            videoHash: hashC,
            status: 'confirmed',
            tier: 'seal',
            chainStatus: 'Active',
          }),
        ],
        '2026-11-19T01:00:00.000Z',
      )

      const candidate = makeManifest(
        [
          makeReportItem({
            fileName: 'unchanged-renamed.mp4',
            videoHash: hashA.toUpperCase(),
            status: 'confirmed',
            tier: 'silent',
            chainStatus: 'Active',
            durationMs: 999,
          }),
          makeReportItem({
            fileName: 'revoked-later.mp4',
            videoHash: hashB,
            status: 'revoked',
            tier: 'source',
            chainStatus: 'Revoked',
          }),
          makeReportItem({
            fileName: 'added.mp4',
            videoHash: hashD,
            status: 'confirmed',
            tier: 'silent',
            chainStatus: 'Active',
          }),
        ],
        '2026-11-19T02:00:00.000Z',
      )

      const report = compareBatchManifests(baseline, candidate)

      expect(report.protocol).toBe(BATCH_COMPARISON_PROTOCOL)
      expect(report.version).toBe(BATCH_COMPARISON_VERSION)
      expect(report.summary).toEqual({
        baselineCount: 3,
        candidateCount: 3,
        addedCount: 1,
        removedCount: 1,
        trustContextChangedCount: 1,
        unchangedCount: 1,
      })

      expect(report.unchanged).toEqual([`video:${hashA}`])
      expect(report.added).toHaveLength(1)
      expect(report.added[0].statementId).toBe(`video:${hashD}`)
      expect(report.added[0].fileName).toBe('added.mp4')

      expect(report.removed).toHaveLength(1)
      expect(report.removed[0].statementId).toBe(`video:${hashC}`)
      expect(report.removed[0].fileName).toBe('removed.mp4')

      expect(report.trustContextChanges).toHaveLength(1)
      expect(report.trustContextChanges[0]).toEqual({
        statementId: `video:${hashB}`,
        fileName: 'revoked-later.mp4',
        baselineFileName: 'revoked-later.mp4',
        videoHash: hashB,
        changedFields: ['chainStatus', 'status'],
        before: {
          status: 'confirmed',
          tier: 'source',
          chainStatus: 'Active',
          metadataHash: 'aaaa222233334444555566667777888811112222333344445555666677778888',
          sourceHash: '1111222233334444555566667777888811112222333344445555666677778888',
        },
        after: {
          status: 'revoked',
          tier: 'source',
          chainStatus: 'Revoked',
          metadataHash: 'aaaa222233334444555566667777888811112222333344445555666677778888',
          sourceHash: '1111222233334444555566667777888811112222333344445555666677778888',
        },
      })
    })

    it('produces byte-for-byte deterministic JSON regardless of input item order', () => {
      const itemA = makeReportItem({ fileName: 'a.mp4', videoHash: hashA })
      const itemB = makeReportItem({ fileName: 'b.mp4', videoHash: hashB, status: 'confirmed' })
      const itemBRevoked = makeReportItem({
        fileName: 'b.mp4',
        videoHash: hashB,
        status: 'revoked',
        chainStatus: 'Revoked',
      })
      const itemC = makeReportItem({ fileName: 'c.mp4', videoHash: hashC })
      const itemD = makeReportItem({ fileName: 'd.mp4', videoHash: hashD })

      const jsonOrder1 = exportBatchComparisonJSON(
        JSON.stringify(makeManifest([itemA, itemB, itemC])),
        JSON.stringify(makeManifest([itemBRevoked, itemD, itemA])),
      )

      const jsonOrder2 = exportBatchComparisonJSON(
        JSON.stringify(makeManifest([itemC, itemA, itemB])),
        JSON.stringify(makeManifest([itemA, itemD, itemBRevoked])),
      )

      expect(jsonOrder1).toBe(jsonOrder2)
    })

    it('derives distinct statement identities for hashed, duplicate, and unhashed items', () => {
      expect(deriveStatementIdentity(makeReportItem({ videoHash: hashA.toUpperCase() }))).toBe(
        `video:${hashA}`,
      )
      expect(
        deriveStatementIdentity(
          makeReportItem({ fileName: 'copy.mp4', status: 'duplicate', videoHash: hashA }),
        ),
      ).toBe(`duplicate:${hashA}:copy.mp4`)
      expect(
        deriveStatementIdentity(
          makeReportItem({ fileName: 'oversized.mp4', fileSizeBytes: 500, videoHash: null }),
        ),
      ).toBe('file:oversized.mp4:500')
    })

    it('fails closed on unsupported manifest version, malformed JSON, count mismatch, or duplicate statement identity', () => {
      expect(() => parseBatchResultManifest('{not valid json')).toThrow(/malformed JSON/)

      expect(() =>
        parseBatchResultManifest(
          JSON.stringify({
            protocol: BATCH_REPORT_PROTOCOL,
            version: 2,
            exportedAt: '2026-11-19T00:00:00.000Z',
            totalCount: 0,
            results: [],
          }),
        ),
      ).toThrow(/Unsupported batch result manifest version/)

      expect(() =>
        parseBatchResultManifest(
          JSON.stringify({
            protocol: BATCH_REPORT_PROTOCOL,
            version: 1,
            exportedAt: '2026-11-19T00:00:00.000Z',
            totalCount: 2,
            results: [makeReportItem()],
          }),
        ),
      ).toThrow(/totalCount must match results\.length/)

      const duplicateManifest = makeManifest([
        makeReportItem({ fileName: 'first.mp4', videoHash: hashA }),
        makeReportItem({ fileName: 'second.mp4', videoHash: hashA }),
      ])
      expect(() =>
        compareBatchManifests(duplicateManifest, makeManifest([])),
      ).toThrow(/Duplicate statement identity in baseline manifest/)
    })
  })
})
