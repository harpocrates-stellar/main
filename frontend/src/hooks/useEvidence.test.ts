import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { computeBoundedProgressMilestone, useEvidence } from './useEvidence'

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

  it('avoids repeated live-region messages for unchanged percentages and bounds progress to 25% milestones', async () => {
    expect(computeBoundedProgressMilestone(0)).toBe(0)
    expect(computeBoundedProgressMilestone(24)).toBe(0)
    expect(computeBoundedProgressMilestone(25)).toBe(25)
    expect(computeBoundedProgressMilestone(49)).toBe(25)
    expect(computeBoundedProgressMilestone(50)).toBe(50)
    expect(computeBoundedProgressMilestone(100)).toBe(100)

    let emitProgress!: (p: { processedBytes: number; totalBytes: number; percentage: number }) => void
    let finishHash!: (hash: string) => void
    hashFileInWorkerMock.mockImplementation((_file, onProgress) => {
      emitProgress = onProgress
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

    const { result } = renderHook(() => useEvidence())
    let op!: Promise<void>
    act(() => {
      op = result.current.handleEvidence(new File(['video'], 'clip.mp4'))
    })

    expect(result.current.announcementHistory).toEqual(['Hashing video: 0% complete.'])

    // Repeated unchanged percentages (10%, 10%, 10%) and non-milestone steps (12%, 24%) must not emit
    act(() => {
      emitProgress({ processedBytes: 100, totalBytes: 1000, percentage: 10 })
      emitProgress({ processedBytes: 104, totalBytes: 1000, percentage: 10 })
      emitProgress({ processedBytes: 109, totalBytes: 1000, percentage: 10 })
      emitProgress({ processedBytes: 120, totalBytes: 1000, percentage: 12 })
      emitProgress({ processedBytes: 240, totalBytes: 1000, percentage: 24 })
    })
    expect(result.current.announcementHistory).toEqual(['Hashing video: 0% complete.'])

    // Reaching 25% milestone announces once; repeated 25% chunks do not repeat
    act(() => {
      emitProgress({ processedBytes: 250, totalBytes: 1000, percentage: 25 })
      emitProgress({ processedBytes: 255, totalBytes: 1000, percentage: 25 })
      emitProgress({ processedBytes: 490, totalBytes: 1000, percentage: 49 })
      emitProgress({ processedBytes: 500, totalBytes: 1000, percentage: 50 })
      emitProgress({ processedBytes: 505, totalBytes: 1000, percentage: 50 })
      emitProgress({ processedBytes: 750, totalBytes: 1000, percentage: 75 })
      emitProgress({ processedBytes: 1000, totalBytes: 1000, percentage: 100 })
      emitProgress({ processedBytes: 1000, totalBytes: 1000, percentage: 100 })
    })

    expect(result.current.announcementHistory).toEqual([
      'Hashing video: 0% complete.',
      'Hashing video: 25% complete.',
      'Hashing video: 50% complete.',
      'Hashing video: 75% complete.',
      'Hashing video: 100% complete.',
    ])

    await act(async () => {
      finishHash('a'.repeat(64))
      await op
    })

    // Terminal success ('ready') announced exactly once
    expect(result.current.announcementHistory).toEqual([
      'Hashing video: 0% complete.',
      'Hashing video: 25% complete.',
      'Hashing video: 50% complete.',
      'Hashing video: 75% complete.',
      'Hashing video: 100% complete.',
      'Embedding portable Harpocrates metadata into the video.',
      'Embedded evidence package is ready for Stellar registration.',
    ])
  })

  it('announces terminal cancellation and failure exactly once without leaking sensitive hashes', async () => {
    let rejectHash!: (err: Error) => void
    hashFileInWorkerMock.mockImplementation(
      (_file, _onProgress, signal: AbortSignal) =>
        new Promise<string>((_resolve, reject) => {
          rejectHash = reject
          signal.addEventListener('abort', () => reject(new Error('Aborted late')), { once: true })
        }),
    )

    const { result } = renderHook(() => useEvidence())
    let cancelRun!: Promise<void>
    act(() => {
      cancelRun = result.current.handleEvidence(new File(['video'], 'clip.mp4'))
    })

    // Cancel twice in a row — terminal cancellation must only be announced once
    act(() => {
      result.current.cancelEvidence()
      result.current.cancelEvidence()
    })
    await act(async () => {
      await cancelRun
    })

    expect(result.current.stage).toBe('cancelled')
    expect(
      result.current.announcementHistory?.filter((msg) => msg === 'Upload cancelled.'),
    ).toHaveLength(1)

    // Now test terminal failure announced once with redacted hex hash
    hashFileInWorkerMock.mockImplementationOnce(
      () =>
        new Promise<string>((_resolve, reject) => {
          rejectHash = reject
        }),
    )
    let failRun!: Promise<void>
    act(() => {
      failRun = result.current.handleEvidence(new File(['video-2'], 'clip2.mp4'))
    })
    await act(async () => {
      rejectHash(new Error(`Hash worker failed on ${'f'.repeat(64)}`))
      await failRun
    })
    // Calling cancelEvidence after terminal error is a no-op and emits nothing further
    act(() => {
      result.current.cancelEvidence()
    })

    expect(result.current.stage).toBe('error')
    expect(result.current.announcementHistory).toEqual([
      'Hashing video: 0% complete.',
      'Hash worker failed on [redacted]',
    ])
  })
})

