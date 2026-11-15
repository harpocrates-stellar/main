import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { buildExportPrivacySummary, useEvidence } from './useEvidence'

const { hashFileInWorkerMock, embedVideoMock } = vi.hoisted(() => ({
  hashFileInWorkerMock: vi.fn(),
  embedVideoMock: vi.fn(),
}))

vi.mock('../workers/fileHashWorkerClient', () => ({
  hashFileInWorker: hashFileInWorkerMock,
}))

vi.mock('../services/evidenceService', () => ({
  embedVideo: embedVideoMock,
}))

describe('useEvidence hashing progress', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('exposes byte progress and updates the Evidence Studio message', async () => {
    let finishHash!: (hash: string) => void
    hashFileInWorkerMock.mockImplementation((_file, onProgress) => {
      onProgress({ processedBytes: 512, totalBytes: 1024, percentage: 50 })
      return new Promise<string>((resolve) => {
        finishHash = resolve
      })
    })
    embedVideoMock.mockResolvedValue({
      embeddedBlob: new Blob(['embedded']),
      embeddedHash: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
    })
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: () => 'blob:embedded',
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: vi.fn(),
    })

    const { result } = renderHook(() => useEvidence())
    expect(result.current.hashProgress).toBeNull()
    let operation!: Promise<void>
    act(() => {
      operation = result.current.handleEvidence(new File(['x'], 'evidence.mp4'))
    })

    expect(result.current.hashProgress).toEqual({
      processedBytes: 512,
      totalBytes: 1024,
      percentage: 50,
    })
    expect(result.current.message).toContain('50% (512 / 1,024 bytes)')

    await act(async () => {
      finishHash('a'.repeat(64))
      await operation
    })

    expect(result.current.stage).toBe('ready')
    expect(result.current.proof?.sourceHash).toBe('a'.repeat(64))
    expect(embedVideoMock).toHaveBeenCalledOnce()
  })

  it('aborts the previous hashing worker when another file is selected', async () => {
    const signals: AbortSignal[] = []
    hashFileInWorkerMock.mockImplementation((_file, _onProgress, signal) => {
      signals.push(signal)
      return new Promise<string>((_resolve, reject) => {
        signal.addEventListener(
          'abort',
          () => reject(new DOMException('Cancelled', 'AbortError')),
          {
            once: true,
          },
        )
      })
    })

    const { result, unmount } = renderHook(() => useEvidence())
    let first!: Promise<void>
    let second!: Promise<void>
    act(() => {
      first = result.current.handleEvidence(new File(['first'], 'first.mp4'))
    })
    act(() => {
      second = result.current.handleEvidence(new File(['second'], 'second.mp4'))
    })

    expect(signals[0].aborted).toBe(true)
    expect(result.current.file?.name).toBe('second.mp4')

    unmount()
    await Promise.all([first, second])
    expect(signals[1].aborted).toBe(true)
  })

  it('surfaces a hashing failure as an error stage', async () => {
    hashFileInWorkerMock.mockRejectedValue(new Error('Evidence hashing failed.'))

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      await result.current.handleEvidence(new File(['x'], 'evidence.mp4'))
    })

    expect(result.current.stage).toBe('error')
    expect(result.current.message).toBe('Evidence hashing failed.')
    expect(embedVideoMock).not.toHaveBeenCalled()
  })

  it('ignores progress callbacks from a superseded hashing run', async () => {
    type Progress = { processedBytes: number; totalBytes: number; percentage: number }
    const callbacks: Array<(progress: Progress) => void> = []
    hashFileInWorkerMock.mockImplementation(
      (_file: File, onProgress: (progress: Progress) => void, signal: AbortSignal) => {
        callbacks.push(onProgress)
        return new Promise<string>((_resolve, reject) => {
          signal.addEventListener(
            'abort',
            () => reject(new DOMException('Cancelled', 'AbortError')),
            { once: true },
          )
        })
      },
    )

    const { result } = renderHook(() => useEvidence())
    let first!: Promise<void>
    act(() => {
      first = result.current.handleEvidence(new File(['first'], 'first.mp4'))
    })
    act(() => {
      void result.current.handleEvidence(new File(['second'], 'second.mp4'))
    })

    // The superseded run must not overwrite the new run's progress state.
    act(() => {
      callbacks[0]({ processedBytes: 9, totalBytes: 10, percentage: 90 })
    })
    expect(result.current.hashProgress).toEqual({
      processedBytes: 0,
      totalBytes: 6,
      percentage: 0,
    })

    await act(async () => {
      await first
    })
  })

  it('memoizes the digest in memory and skips the hash worker on retry with the same file', async () => {
    hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
    embedVideoMock.mockResolvedValue({
      embeddedBlob: new Blob(['embedded']),
      embeddedHash: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
    })
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: () => 'blob:embedded',
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: vi.fn(),
    })

    const { result } = renderHook(() => useEvidence())
    const sameFile = new File(['video-bytes'], 'evidence.mp4', { lastModified: 1700000000000 })

    await act(async () => {
      await result.current.handleEvidence(sameFile)
    })

    expect(hashFileInWorkerMock).toHaveBeenCalledTimes(1)
    expect(result.current.proof?.sourceHash).toBe('a'.repeat(64))

    // Retry with the exact same File instance (e.g. after a registration error or flow restart)
    await act(async () => {
      await result.current.handleEvidence(sameFile)
    })

    expect(hashFileInWorkerMock).toHaveBeenCalledTimes(1)
    expect(embedVideoMock).toHaveBeenCalledTimes(2)
    expect(result.current.proof?.sourceHash).toBe('a'.repeat(64))
  })

  it('invalidates the memoized digest and hashes again when a different file is chosen', async () => {
    hashFileInWorkerMock
      .mockResolvedValueOnce('a'.repeat(64))
      .mockResolvedValueOnce('d'.repeat(64))
      .mockResolvedValueOnce('e'.repeat(64))
    embedVideoMock.mockResolvedValue({
      embeddedBlob: new Blob(['embedded']),
      embeddedHash: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
    })
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: () => 'blob:embedded',
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: vi.fn(),
    })

    const { result } = renderHook(() => useEvidence())
    const fileA = new File(['video-bytes'], 'evidence.mp4', { lastModified: 1700000000000 })
    const fileB = new File(['video-bytes'], 'evidence.mp4', { lastModified: 1700000000000 })

    await act(async () => {
      await result.current.handleEvidence(fileA)
    })
    expect(hashFileInWorkerMock).toHaveBeenCalledTimes(1)
    expect(result.current.proof?.sourceHash).toBe('a'.repeat(64))

    // Choosing a different File instance (even with identical metadata) triggers hashing
    await act(async () => {
      await result.current.handleEvidence(fileB)
    })
    expect(hashFileInWorkerMock).toHaveBeenCalledTimes(2)
    expect(result.current.proof?.sourceHash).toBe('d'.repeat(64))

    // Choosing fileA again after it was invalidated by fileB triggers hashing again
    await act(async () => {
      await result.current.handleEvidence(fileA)
    })
    expect(hashFileInWorkerMock).toHaveBeenCalledTimes(3)
    expect(result.current.proof?.sourceHash).toBe('e'.repeat(64))
  })

  it('builds export privacy summaries and requires explicit acknowledgement only for newly exposed sensitive fields', () => {
    const baseProof = {
      fileName: 'harpocrates-clip.mp4',
      sourceHash: 'a'.repeat(64),
      videoHash: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
      proofId: 'd'.repeat(64),
      timestamp: '2026-01-01T00:00:00.000Z',
    }

    // Silent Witness with no capture-time attestation or ledger tx has no sensitive fields -> no ack needed.
    const silentSummary = buildExportPrivacySummary({
      proof: { ...baseProof, tier: 'silent' },
      networkPassphrase: 'Test SDF Network ; September 2015',
      contractId: 'C'.repeat(56),
    })
    expect(silentSummary?.metadataClasses.map((c) => c.id)).toEqual([
      'portable_manifest',
      'integrity_digests',
      'capture_timestamp',
      'zk_anonymous_credential',
    ])
    expect(silentSummary?.publicIdentifiers.map((p) => p.key)).toContain('proofId')
    expect(silentSummary?.sensitiveFields).toHaveLength(0)
    expect(silentSummary?.requiresAcknowledgement).toBe(false)
    expect(silentSummary?.canExport).toBe(true)

    // Consistent Source exposes wallet attribution -> newly exposed -> requires acknowledgement.
    const sourceUnacked = buildExportPrivacySummary({
      proof: { ...baseProof, tier: 'source' },
      wallet: 'G'.repeat(56),
      networkPassphrase: 'Test SDF Network ; September 2015',
      acknowledgedKeys: [],
    })
    expect(sourceUnacked?.newlyExposedFields.map((f) => f.key)).toEqual([
      'pseudonymous_wallet_attribution',
    ])
    expect(sourceUnacked?.requiresAcknowledgement).toBe(true)
    expect(sourceUnacked?.canExport).toBe(false)

    // Once wallet attribution is acknowledged, export is allowed without prompting again.
    const sourceAcked = buildExportPrivacySummary({
      proof: { ...baseProof, tier: 'source' },
      wallet: 'G'.repeat(56),
      networkPassphrase: 'Test SDF Network ; September 2015',
      acknowledgedKeys: ['pseudonymous_wallet_attribution'],
    })
    expect(sourceAcked?.newlyExposedFields).toHaveLength(0)
    expect(sourceAcked?.requiresAcknowledgement).toBe(false)
    expect(sourceAcked?.canExport).toBe(true)

    // When Stellar registration subsequently adds a public transaction reference, ONLY the newly exposed field requires ack.
    const afterRegistration = buildExportPrivacySummary({
      proof: { ...baseProof, tier: 'source' },
      registration: { hash: 'f'.repeat(64), status: 'SUCCESS' },
      wallet: 'G'.repeat(56),
      networkPassphrase: 'Test SDF Network ; September 2015',
      acknowledgedKeys: ['pseudonymous_wallet_attribution'],
    })
    expect(afterRegistration?.sensitiveFields).toHaveLength(2)
    expect(afterRegistration?.newlyExposedFields.map((f) => f.key)).toEqual([
      'ledger_transaction_reference',
    ])
    expect(afterRegistration?.requiresAcknowledgement).toBe(true)
    expect(afterRegistration?.canExport).toBe(false)
  })
})

