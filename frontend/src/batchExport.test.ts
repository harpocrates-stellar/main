import { describe, expect, it } from 'vitest'
import {
  BatchCheckpointError,
  type BatchItemResult,
  type BatchVerificationCheckpoint,
} from './batchVerifier'
import {
  EXPORT_PRIVACY_PROFILES,
  OWNER_ONLY_EXPORT_FIELDS,
  PUBLIC_EXPORT_FIELDS,
  assertValidExportPrivacyProfile,
  exportBatchCSV,
  exportBatchCheckpoint,
  exportBatchJSON,
  exportPreflightReportCSV,
  exportPreflightReportJSON,
  exportReceiptCollection,
  parseBatchCheckpoint,
  sanitizeBatchResults,
  type ExportPrivacyProfile,
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
      issuerNote: 'PRIVATE-ISSUER-NOTE-WHISTLEBLOWER-77',
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
      duplicateOf: 'evidence1.mp4',
      manifest: null,
      durationMs: 5,
      failureReason: 'Total batch memory limit exceeded by queueing large.mp4.',
      issuerNote: 'INTERNAL-REVIEW-ONLY',
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
    expect(parsed.privacyProfile).toBe('owner-only')
    expect(parsed.totalCount).toBe(2)
    expect(jsonStr).not.toContain('media bytes')
  })

  it('exportBatchCSV produces properly formatted CSV with headers', () => {
    const csvStr = exportBatchCSV(mockItems)
    expect(csvStr).toContain('File Name,Size (Bytes),Status,Video Hash')
    expect(csvStr).toContain('evidence1.mp4,1024,confirmed')
    expect(csvStr).toContain('large.mp4,200000000,oversized')
    expect(csvStr).toContain('PRIVATE-ISSUER-NOTE-WHISTLEBLOWER-77')
  })

  it('exportReceiptCollection exports valid manifest collections', () => {
    const collectionJson = exportReceiptCollection(mockItems)
    const parsed = JSON.parse(collectionJson) as Record<string, unknown>
    expect(parsed.protocol).toBe('harpocrates-receipt-collection')
    expect(parsed.totalItems).toBe(1)
  })

  it('exportBatchCheckpoint and parseBatchCheckpoint round-trip privacy-safe checkpoints', () => {
    const checkpoint: BatchVerificationCheckpoint = {
      protocol: 'harpocrates-batch-checkpoint',
      version: 1,
      createdAt: '2026-11-19T00:00:00.000Z',
      updatedAt: '2026-11-19T00:01:00.000Z',
      policy: { maxFileSizeBytes: 1024 * 1024, maxTotalSizeBytes: 5 * 1024 * 1024 },
      networkContext: { apiBase: 'http://127.0.0.1:5050', contractId: 'CTEST', network: 'testnet' },
      files: [
        {
          index: 0,
          fileName: 'evidence1.mp4',
          fileSizeBytes: 1024,
          lastModified: 1700000000000,
          mimeType: 'video/mp4',
          sampleHash: 'a'.repeat(64),
        },
      ],
      completed: [
        {
          index: 0,
          fileName: 'evidence1.mp4',
          fileSizeBytes: 1024,
          status: 'confirmed',
          videoHash: '1'.repeat(64),
          metadataHash: '2'.repeat(64),
          sourceHash: '3'.repeat(64),
          tier: 'silent',
          chainStatus: 'Active',
          message: 'Confirmed evidence',
          duplicateOf: null,
          failureReason: null,
          durationMs: 120.4,
        },
      ],
    }

    const exported = exportBatchCheckpoint(checkpoint)
    const parsed = parseBatchCheckpoint(exported)

    expect(parsed.protocol).toBe('harpocrates-batch-checkpoint')
    expect(parsed.completed).toHaveLength(1)
    expect(parsed.completed[0].durationMs).toBe(120)
  })

  it('parseBatchCheckpoint fails closed on malformed or non-completed checkpoint payloads', () => {
    expect(() => parseBatchCheckpoint('{invalid')).toThrow(BatchCheckpointError)
    expect(() => parseBatchCheckpoint(JSON.stringify({ protocol: 'wrong', version: 1 }))).toThrow(
      BatchCheckpointError,
    )
    expect(() =>
      parseBatchCheckpoint(
        JSON.stringify({
          protocol: 'harpocrates-batch-checkpoint',
          version: 1,
          createdAt: '2026-11-19T00:00:00.000Z',
          updatedAt: '2026-11-19T00:00:00.000Z',
          policy: { maxFileSizeBytes: 100, maxTotalSizeBytes: 200 },
          networkContext: { apiBase: 'http://127.0.0.1:5050', contractId: '', network: 'testnet' },
          files: [],
          completed: [
            {
              index: 0,
              fileName: 'a.mp4',
              fileSizeBytes: 10,
              status: 'pending',
              videoHash: null,
              metadataHash: null,
              sourceHash: null,
              tier: null,
              chainStatus: null,
              message: 'Queued',
              duplicateOf: null,
              failureReason: null,
              durationMs: null,
            },
          ],
        }),
      ),
    ).toThrow(BatchCheckpointError)
  })
})
