import { describe, expect, it } from 'vitest'
import type { BatchItemResult } from './batchVerifier'
import {
  BatchExportConflictError,
  detectConflictingStatements,
  exportBatchCSV,
  exportBatchJSON,
  exportReceiptCollection,
  sanitizeBatchResults,
  validateBatchExportResults,
} from './batchExport'
import { summarizeBatchCompleteness } from './batchVerifier'

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

  it('rejects batch exports when two rows share a videoHash with conflicting outcomes', () => {
    const conflicting: BatchItemResult[] = [
      mockItems[0],
      {
        ...mockItems[0],
        id: 'item-conflict',
        fileName: 'evidence1-tampered.mp4',
        status: 'revoked',
        chainStatus: 'Revoked',
      },
    ]

    expect(() => exportBatchJSON(conflicting)).toThrow(BatchExportConflictError)
    expect(() => exportBatchCSV(conflicting)).toThrow(BatchExportConflictError)
    expect(() => exportReceiptCollection(conflicting)).toThrow(BatchExportConflictError)

    const conflicts = detectConflictingStatements(conflicting)
    expect(conflicts).toHaveLength(2)
    expect(conflicts[0].identifierType).toBe('videoHash')
    expect(conflicts[0].firstFileName).toBe('evidence1.mp4')
    expect(conflicts[0].conflictingFileName).toBe('evidence1-tampered.mp4')
    expect(conflicts[0].reason).toContain('status (confirmed vs revoked)')
  })

  it('rejects conflicting manifest proofId rows', () => {
    const conflictingManifests: BatchItemResult[] = [
      {
        ...mockItems[0],
        id: 'm-1',
        videoHash: 'aaaa',
        metadataHash: 'bbbb',
        manifest: {
          protocol: 'harpocrates',
          version: 1,
          proofId: 'shared-proof-id',
          tier: 'silent',
          network: 'testnet',
          contractId: 'C1',
          transactionRef: 'tx1',
          videoHash: 'aaaa',
          metadataHash: 'bbbb',
          sourceHash: 'aaaa',
          timestamp: '2026-01-01T00:00:00.000Z',
          verifierScope: '0',
          epoch: 0,
        },
      },
      {
        ...mockItems[0],
        id: 'm-2',
        fileName: 'evidence2.mp4',
        videoHash: 'cccc',
        metadataHash: 'dddd',
        manifest: {
          protocol: 'harpocrates',
          version: 1,
          proofId: 'shared-proof-id',
          tier: 'seal',
          network: 'testnet',
          contractId: 'C1',
          transactionRef: 'tx2',
          videoHash: 'cccc',
          metadataHash: 'dddd',
          sourceHash: 'cccc',
          timestamp: '2026-01-01T00:00:00.000Z',
          verifierScope: '0',
          epoch: 0,
        },
      },
    ]

    expect(() => exportReceiptCollection(conflictingManifests)).toThrow(BatchExportConflictError)
  })

  it('preserves valid unique results and expected duplicate-status rows', () => {
    const withDuplicate: BatchItemResult[] = [
      ...mockItems,
      {
        ...mockItems[0],
        id: 'item-dup',
        fileName: 'evidence1-copy.mp4',
        status: 'Duplicate',
        metadataHash: null,
        tier: null,
        chainStatus: null,
        duplicateOf: 'evidence1.mp4',
      },
    ]

    expect(validateBatchExportResults(withDuplicate)).toHaveLength(3)
    expect(() => exportBatchJSON(withDuplicate)).not.toThrow()
    expect(() => exportBatchCSV(withDuplicate)).not.toThrow()
    expect(() => exportReceiptCollection(withDuplicate)).not.toThrow()
  })

  it('reports verified, failed, cancelled and incomplete items separately in the batch summary', () => {
    const mixed: BatchItemResult[] = [
      mockItems[0],
      {
        ...mockItems[1],
        id: 'item-failed',
        fileName: 'failed.mp4',
        status: 'failed',
        failureReason: 'Proof verification failed',
      },
      {
        ...mockItems[1],
        id: 'item-cancelled',
        fileName: 'cancelled.mp4',
        status: 'cancelled',
        failureReason: 'Cancelled by user',
      },
      {
        ...mockItems[1],
        id: 'item-incomplete',
        fileName: 'incomplete.mp4',
        status: 'incomplete',
        failureReason: 'Batch interrupted',
      },
    ]

    const summary = summarizeBatchCompleteness(mixed)
    expect(summary.total).toBe(4)
    expect(summary.verified).toBe(1)
    expect(summary.failed).toBe(1)
    expect(summary.cancelled).toBe(1)
    expect(summary.incomplete).toBe(1)
    expect(summary.unresolved).toBe(3)
    expect(summary.complete).toBe(false)
  })

  it('never treats an interrupted batch as a complete verification run', () => {
    const interrupted: BatchItemResult[] = [
      mockItems[0],
      {
        ...mockItems[1],
        id: 'item-incomplete',
        fileName: 'incomplete.mp4',
        status: 'incomplete',
        failureReason: 'Batch interrupted',
      },
    ]

    const summary = summarizeBatchCompleteness(interrupted)
    expect(summary.incomplete).toBe(1)
    expect(summary.complete).toBe(false)
    expect(summary.unresolved).toBeGreaterThan(0)
  })

  it('reports a fully resolved batch as complete', () => {
    const summary = summarizeBatchCompleteness(mockItems)
    expect(summary.total).toBe(2)
    expect(summary.verified).toBe(1)
    expect(summary.failed).toBe(1)
    expect(summary.cancelled).toBe(0)
    expect(summary.incomplete).toBe(0)
    expect(summary.unresolved).toBe(0)
    expect(summary.complete).toBe(!0)
  })

  it('treats an empty batch as incomplete rather than a complete run', () => {
    const summary = summarizeBatchCompleteness([])
    expect(summary.total).toBe(0)
    expect(summary.unresolved).toBe(0)
    expect(summary.complete).toBe(false)
  })
})
