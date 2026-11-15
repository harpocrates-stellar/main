import { createElement } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { BatchItemResult } from './batchVerifier'
import BatchVerificationWorkspace from './components/BatchVerificationWorkspace'
import {
  BATCH_EXPORT_FIELD_SETS,
  exportBatchCSV,
  exportBatchJSON,
  exportReceiptCollection,
  sanitizeBatchResults,
  type BatchExportPrivacyProfile,
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
      message: 'Confirmed evidence for evidence1.mp4',
      events: [],
      chainProof: null,
      duplicateOf: null,
      manifest: null,
      durationMs: 120,
      failureReason: null,
      issuerNotes: 'Confidential source desk note #42',
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
      failureReason: 'Per-file limit exceeded for large.mp4',
      issuerNotes: 'Internal intake rejection note',
    },
  ]

  it('documents public and owner-only export field sets explicitly', () => {
    expect(BATCH_EXPORT_FIELD_SETS.public).not.toContain('fileName')
    expect(BATCH_EXPORT_FIELD_SETS.public).not.toContain('issuerNotes')
    expect(BATCH_EXPORT_FIELD_SETS.public).not.toContain('failureReason')
    expect(BATCH_EXPORT_FIELD_SETS['owner-only']).toContain('fileName')
    expect(BATCH_EXPORT_FIELD_SETS['owner-only']).toContain('issuerNotes')
    expect(BATCH_EXPORT_FIELD_SETS['owner-only']).toContain('failureReason')
  })

  it('sanitizeBatchResults strips raw File handles and media buffers while defaulting to owner-only compatibility', () => {
    const sanitized = sanitizeBatchResults(mockItems)
    expect(sanitized).toHaveLength(2)
    expect(sanitized[0].fileName).toBe('evidence1.mp4')
    expect(sanitized[0].issuerNotes).toBe('Confidential source desk note #42')
    expect((sanitized[0] as Record<string, unknown>).file).toBeUndefined()
  })

  it('omits raw filenames, duplicate raw filenames, failure reasons, and issuer notes in public profile exports', () => {
    const publicItems = sanitizeBatchResults(mockItems, { privacyProfile: 'public' })
    expect(publicItems[0].itemRef).toBe('item-1')
    expect(publicItems[0].fileName).toBeUndefined()
    expect(publicItems[0].issuerNotes).toBeUndefined()
    expect(publicItems[0].failureReason).toBeUndefined()
    expect(publicItems[0].message).toBe('Confirmed evidence for [redacted-filename]')
    expect(publicItems[1].duplicateOf).toBe('item-1')

    const publicJson = exportBatchJSON(mockItems, 'public')
    expect(publicJson).not.toContain('evidence1.mp4')
    expect(publicJson).not.toContain('large.mp4')
    expect(publicJson).not.toContain('Confidential source desk note #42')
    expect(publicJson).not.toContain('Internal intake rejection note')
    const parsed = JSON.parse(publicJson) as { privacyProfile: string; fieldSet: string[] }
    expect(parsed.privacyProfile).toBe('public')
    expect(parsed.fieldSet).toEqual([...BATCH_EXPORT_FIELD_SETS.public])

    const publicCsv = exportBatchCSV(mockItems, { privacyProfile: 'public' })
    expect(publicCsv).toContain('Item Ref,Size (Bytes),Status,Video Hash')
    expect(publicCsv).not.toContain('File Name')
    expect(publicCsv).not.toContain('Issuer Notes')
    expect(publicCsv).not.toContain('evidence1.mp4')
    expect(publicCsv).not.toContain('Confidential source desk note #42')
  })

  it('exportBatchJSON produces valid privacy-safe JSON in owner-only mode', () => {
    const jsonStr = exportBatchJSON(mockItems)
    const parsed = JSON.parse(jsonStr) as Record<string, unknown>
    expect(parsed.protocol).toBe('harpocrates-batch-report')
    expect(parsed.privacyProfile).toBe('owner-only')
    expect(parsed.totalCount).toBe(2)
    expect(jsonStr).not.toContain('media bytes')
    expect(jsonStr).toContain('Confidential source desk note #42')
  })

  it('exportBatchCSV produces properly formatted CSV with headers', () => {
    const csvStr = exportBatchCSV(mockItems)
    expect(csvStr).toContain('File Name,Size (Bytes),Status,Video Hash')
    expect(csvStr).toContain('evidence1.mp4,1024,confirmed')
    expect(csvStr).toContain('large.mp4,200000000,oversized')
  })

  it('exportReceiptCollection exports valid manifest collections and strips private fields in public mode', () => {
    const itemsWithManifest: BatchItemResult[] = [
      {
        ...mockItems[0],
        manifest: {
          protocol: 'harpocrates',
          version: 1,
          proofId: mockItems[0].videoHash!,
          tier: 'silent',
          network: 'testnet',
          contractId: 'CTEST',
          transactionRef: 'tx1',
          videoHash: mockItems[0].videoHash!,
          metadataHash: mockItems[0].metadataHash!,
          sourceHash: mockItems[0].sourceHash!,
          timestamp: '2026-01-01T00:00:00.000Z',
          verifierScope: '0',
          epoch: 0,
          ...({ fileName: 'evidence1.mp4', issuerNotes: 'Secret issuer note' } as Record<string, unknown>),
        },
      },
    ]

    const publicCollection = exportReceiptCollection(itemsWithManifest, { privacyProfile: 'public' })
    expect(publicCollection).not.toContain('evidence1.mp4')
    expect(publicCollection).not.toContain('Secret issuer note')
    const parsed = JSON.parse(publicCollection) as Record<string, unknown>
    expect(parsed.protocol).toBe('harpocrates-receipt-collection')
    expect(parsed.privacyProfile).toBe('public')
    expect(parsed.totalItems).toBe(1)
  })

  it('rejects unsupported privacy profile values fail-closed', () => {
    expect(() =>
      exportBatchJSON(mockItems, { privacyProfile: 'internal-raw' as BatchExportPrivacyProfile }),
    ).toThrow(/Unsupported batch export privacy profile/)
  })

  it('renders an accessible privacy profile selector in BatchVerificationWorkspace defaulting to public', async () => {
    const user = userEvent.setup()
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock-export')
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    render(createElement(BatchVerificationWorkspace, { apiBase: 'http://127.0.0.1:5050', contractId: 'CTEST' }))
    const fileInput = document.querySelector('#batch-evidence-input') as HTMLInputElement
    await user.upload(fileInput, new File(['synthetic'], 'confidential-clip.mp4', { type: 'video/mp4' }))

    const selector = screen.getByLabelText(/Export privacy profile/i) as HTMLSelectElement
    expect(selector.value).toBe('public')

    await user.click(screen.getByRole('button', { name: /^JSON$/ }))
    const publicBlob = createObjectURL.mock.calls[0]?.[0] as Blob
    const publicText = await publicBlob.text()
    expect(publicText).not.toContain('confidential-clip.mp4')
    expect(publicText).toContain('"privacyProfile": "public"')

    await user.selectOptions(selector, 'owner-only')
    expect(selector.value).toBe('owner-only')
    await user.click(screen.getByRole('button', { name: /^JSON$/ }))
    const ownerBlob = createObjectURL.mock.calls[1]?.[0] as Blob
    const ownerText = await ownerBlob.text()
    expect(ownerText).toContain('confidential-clip.mp4')
    expect(ownerText).toContain('"privacyProfile": "owner-only"')

    createObjectURL.mockRestore()
    revokeObjectURL.mockRestore()
    clickSpy.mockRestore()
  })
})
