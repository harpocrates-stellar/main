import { describe, expect, it } from 'vitest'
import type { BatchItemResult } from './batchVerifier'
import {
  BatchComparisonError,
  compareBatchReports,
  exportBatchComparisonCSV,
  exportBatchComparisonJSON,
  exportBatchCSV,
  exportBatchJSON,
  exportReceiptCollection,
  parseBatchReportManifest,
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

  it('compares two versioned batch manifests by statement identity and separates trust-context changes from added/removed files', () => {
    const baselineManifest = {
      protocol: 'harpocrates-batch-report',
      version: 1,
      exportedAt: '2026-01-01T00:00:00.000Z',
      totalCount: 3,
      results: [
        {
          fileName: 'clip_stay_same.mp4',
          fileSizeBytes: 512,
          status: 'confirmed',
          videoHash: '11'.repeat(32),
          metadataHash: 'aa'.repeat(32),
          sourceHash: '11'.repeat(32),
          tier: 'silent',
          chainStatus: 'Active',
          message: 'Verified',
          duplicateOf: null,
          failureReason: null,
          durationMs: 25,
        },
        {
          fileName: 'clip_trust_change_old_name.mp4',
          fileSizeBytes: 1024,
          status: 'confirmed',
          videoHash: '22'.repeat(32),
          metadataHash: 'bb'.repeat(32),
          sourceHash: '22'.repeat(32),
          tier: 'source',
          chainStatus: 'Active',
          message: 'Verified',
          duplicateOf: null,
          failureReason: null,
          durationMs: 30,
        },
        {
          fileName: 'clip_removed.mp4',
          fileSizeBytes: 2048,
          status: 'confirmed',
          videoHash: '33'.repeat(32),
          metadataHash: 'cc'.repeat(32),
          sourceHash: '33'.repeat(32),
          tier: 'seal',
          chainStatus: 'Active',
          message: 'Verified',
          duplicateOf: null,
          failureReason: null,
          durationMs: 40,
        },
      ],
    }

    const candidateManifestOrderA = {
      protocol: 'harpocrates-batch-report',
      version: 1,
      exportedAt: '2026-02-01T00:00:00.000Z',
      totalCount: 3,
      results: [
        {
          fileName: 'clip_added.mp4',
          fileSizeBytes: 4096,
          status: 'confirmed',
          videoHash: '44'.repeat(32),
          metadataHash: 'dd'.repeat(32),
          sourceHash: '44'.repeat(32),
          tier: 'silent',
          chainStatus: 'Active',
          message: 'Verified',
          duplicateOf: null,
          failureReason: null,
          durationMs: 50,
        },
        {
          fileName: 'clip_trust_change_renamed.mp4',
          fileSizeBytes: 1024,
          status: 'revoked',
          videoHash: '22'.repeat(32),
          metadataHash: 'bb'.repeat(32),
          sourceHash: '22'.repeat(32),
          tier: 'source',
          chainStatus: 'Revoked',
          message: 'Revoked on-chain',
          duplicateOf: null,
          failureReason: null,
          durationMs: 35,
        },
        {
          fileName: 'clip_stay_same.mp4',
          fileSizeBytes: 512,
          status: 'confirmed',
          videoHash: '11'.repeat(32),
          metadataHash: 'aa'.repeat(32),
          sourceHash: '11'.repeat(32),
          tier: 'silent',
          chainStatus: 'Active',
          message: 'Verified',
          duplicateOf: null,
          failureReason: null,
          durationMs: 20,
        },
      ],
    }

    const candidateManifestOrderB = {
      ...candidateManifestOrderA,
      results: [...candidateManifestOrderA.results].reverse(),
    }

    const diffA = exportBatchComparisonJSON(JSON.stringify(baselineManifest), JSON.stringify(candidateManifestOrderA))
    const diffB = exportBatchComparisonJSON(baselineManifest, candidateManifestOrderB)
    expect(diffB).toBe(diffA)

    const report = compareBatchReports(baselineManifest, candidateManifestOrderA)
    expect(report.summary).toEqual({
      baselineCount: 3,
      candidateCount: 3,
      trustContextChangedCount: 1,
      addedCount: 1,
      removedCount: 1,
      unchangedCount: 1,
    })
    expect(report.trustContextChanges[0]).toMatchObject({
      baselineFileName: 'clip_trust_change_old_name.mp4',
      candidateFileName: 'clip_trust_change_renamed.mp4',
      before: { status: 'confirmed', chainStatus: 'Active', tier: 'source' },
      after: { status: 'revoked', chainStatus: 'Revoked', tier: 'source' },
      changedFields: ['status', 'chainStatus'],
    })
    expect(report.added.map((i) => i.fileName)).toEqual(['clip_added.mp4'])
    expect(report.removed.map((i) => i.fileName)).toEqual(['clip_removed.mp4'])
    expect(report.unchanged.map((i) => i.fileName)).toEqual(['clip_stay_same.mp4'])

    const csvDiff = exportBatchComparisonCSV(baselineManifest, candidateManifestOrderA)
    expect(csvDiff).toContain('Category,Statement ID,Baseline File,Candidate File')
    expect(csvDiff).toContain('trust-context-changed')
    expect(csvDiff).toContain('status;chainStatus')
    expect(csvDiff).toContain('clip_added.mp4')
    expect(csvDiff).toContain('clip_removed.mp4')
  })

  it('rejects malformed, wrong-protocol, unsupported-version, and conflicting batch manifests fail-closed', () => {
    expect(() => parseBatchReportManifest('{not-json')).toThrowError(BatchComparisonError)
    expect(() => parseBatchReportManifest({ protocol: 'wrong-protocol', version: 1, results: [] })).toThrow(
      /Unsupported batch report protocol/,
    )
    expect(() => parseBatchReportManifest({ protocol: 'harpocrates-batch-report', version: 2, results: [] })).toThrow(
      /Unsupported batch report schema version/,
    )

    const conflictingManifest = {
      protocol: 'harpocrates-batch-report',
      version: 1,
      totalCount: 2,
      results: [
        {
          fileName: 'a.mp4',
          fileSizeBytes: 100,
          status: 'confirmed',
          videoHash: '99'.repeat(32),
          metadataHash: 'aa'.repeat(32),
          sourceHash: '99'.repeat(32),
          tier: 'silent',
          chainStatus: 'Active',
          message: 'ok',
          duplicateOf: null,
          failureReason: null,
          durationMs: 1,
        },
        {
          fileName: 'b.mp4',
          fileSizeBytes: 100,
          status: 'revoked',
          videoHash: '99'.repeat(32),
          metadataHash: 'aa'.repeat(32),
          sourceHash: '99'.repeat(32),
          tier: 'silent',
          chainStatus: 'Revoked',
          message: 'revoked',
          duplicateOf: null,
          failureReason: null,
          durationMs: 1,
        },
      ],
    }

    expect(() => compareBatchReports(conflictingManifest, conflictingManifest)).toThrow(
      /conflicting trust outcomes/,
    )
  })
})
