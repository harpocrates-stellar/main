import { describe, expect, it } from 'vitest'
import type { BatchItemResult, BatchPreflightReport } from './batchVerifier'
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

  it('documents distinct public and owner-only field sets', () => {
    expect(EXPORT_PRIVACY_PROFILES.public.fields).toEqual(PUBLIC_EXPORT_FIELDS)
    expect(EXPORT_PRIVACY_PROFILES['owner-only'].fields).toEqual(OWNER_ONLY_EXPORT_FIELDS)
    expect(PUBLIC_EXPORT_FIELDS).not.toContain('fileName')
    expect(PUBLIC_EXPORT_FIELDS).not.toContain('issuerNote')
    expect(PUBLIC_EXPORT_FIELDS).not.toContain('duplicateOf')
    expect(OWNER_ONLY_EXPORT_FIELDS).toContain('fileName')
    expect(OWNER_ONLY_EXPORT_FIELDS).toContain('issuerNote')
  })

  it('public JSON export omits raw filenames, duplicate references, diagnostics, and private issuer notes', () => {
    const jsonStr = exportBatchJSON(mockItems, 'public')
    const parsed = JSON.parse(jsonStr) as {
      privacyProfile: string
      results: Record<string, unknown>[]
    }

    expect(parsed.privacyProfile).toBe('public')
    expect(parsed.results).toHaveLength(2)
    expect(Object.keys(parsed.results[0]).sort()).toEqual([...PUBLIC_EXPORT_FIELDS].sort())
    expect(jsonStr).not.toContain('evidence1.mp4')
    expect(jsonStr).not.toContain('large.mp4')
    expect(jsonStr).not.toContain('PRIVATE-ISSUER-NOTE-WHISTLEBLOWER-77')
    expect(jsonStr).not.toContain('INTERNAL-REVIEW-ONLY')
    expect(jsonStr).not.toContain('Total batch memory limit exceeded')
  })

  it('public CSV export omits raw filenames and private issuer notes', () => {
    const csvStr = exportBatchCSV(mockItems, 'public')
    const [headerLine] = csvStr.split('\n')

    expect(headerLine).toBe(
      'Status,Video Hash,Metadata Hash,Source Hash,Tier,Chain Status,Size (Bytes),Duration (ms)',
    )
    expect(csvStr).not.toContain('evidence1.mp4')
    expect(csvStr).not.toContain('large.mp4')
    expect(csvStr).not.toContain('PRIVATE-ISSUER-NOTE-WHISTLEBLOWER-77')
    expect(csvStr).not.toContain('INTERNAL-REVIEW-ONLY')
  })

  it('fails closed when given an unsupported privacy profile', () => {
    const invalidProfile = 'unrestricted' as unknown as ExportPrivacyProfile
    expect(() => assertValidExportPrivacyProfile(invalidProfile)).toThrow(
      /Unsupported export privacy profile/,
    )
    expect(() => sanitizeBatchResults(mockItems, invalidProfile)).toThrow(
      /Unsupported export privacy profile/,
    )
    expect(() => exportBatchJSON(mockItems, invalidProfile)).toThrow(
      /Unsupported export privacy profile/,
    )
    expect(() => exportBatchCSV(mockItems, invalidProfile)).toThrow(
      /Unsupported export privacy profile/,
    )
  })
})
