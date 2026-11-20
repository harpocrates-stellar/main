import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useEvidence } from './useEvidence'

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

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
  getWalletNetwork: vi.fn(),
  registerProofOnStellar: vi.fn(),
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
})

describe('useEvidence pre-registration review', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  async function prepareReadyEvidence() {
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

    const hook = renderHook(() => useEvidence())
    const file = new File(['synthetic-video'], 'sample.mp4', { lastModified: 1700000000000 })
    await act(async () => {
      await hook.result.current.handleEvidence(file)
    })
    return hook
  }

  it('builds a review snapshot with identity tier, statement digest, and network', async () => {
    const { result } = await prepareReadyEvidence()

    expect(result.current.review).toBeNull()
    await act(async () => {
      await result.current.openReview()
    })

    expect(result.current.review).not.toBeNull()
    expect(result.current.review?.tier).toBe('silent')
    expect(result.current.review?.tierTitle).toBe('Silent Witness')
    expect(result.current.review?.networkName).toBe('Testnet')
    expect(result.current.review?.networkPassphrase).toBe('Test SDF Network ; September 2015')
    expect(result.current.review?.statementDigest).toMatch(/^[0-9a-f]{64}$/)
    expect(result.current.reviewInvalidatedReason).toBeNull()
  })

  it('invalidates the review when identity tier or proof parameters change', async () => {
    const { result } = await prepareReadyEvidence()

    await act(async () => {
      await result.current.openReview()
    })
    expect(result.current.review).not.toBeNull()

    // Changing credential seed invalidates the active review
    act(() => {
      result.current.setCredentialSeed('new-secret-seed')
    })
    expect(result.current.review).toBeNull()
    expect(result.current.reviewInvalidatedReason).toMatch(/proof parameters changed/i)
    // Privacy check: secret seed must never appear in the invalidation message
    expect(result.current.reviewInvalidatedReason).not.toContain('new-secret-seed')

    // Re-open review, then change nullifier seed
    await act(async () => {
      await result.current.openReview()
    })
    expect(result.current.review).not.toBeNull()
    act(() => {
      result.current.setNullifierSeed('new-nullifier-seed')
    })
    expect(result.current.review).toBeNull()
    expect(result.current.reviewInvalidatedReason).toMatch(/proof parameters changed/i)

    // Re-open review, then change identity tier
    await act(async () => {
      await result.current.openReview()
    })
    expect(result.current.review).not.toBeNull()
    act(() => {
      result.current.setSelectedTier('source')
    })
    expect(result.current.review).toBeNull()
    expect(result.current.reviewInvalidatedReason).toMatch(/identity tier changed/i)
  })

  it('invalidates the review when a new source file is selected', async () => {
    const { result } = await prepareReadyEvidence()

    await act(async () => {
      await result.current.openReview()
    })
    expect(result.current.review).not.toBeNull()

    hashFileInWorkerMock.mockResolvedValueOnce('d'.repeat(64))
    const nextFile = new File(['next-video'], 'next.mp4', { lastModified: 1700000001000 })
    await act(async () => {
      await result.current.handleEvidence(nextFile)
    })

    expect(result.current.review).toBeNull()
    expect(result.current.reviewInvalidatedReason).toMatch(/source file changed/i)
  })

  it('fails closed when registerProof is called without an active review', async () => {
    const { result } = await prepareReadyEvidence()

    await act(async () => {
      await result.current.registerProof('GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF')
    })

    expect(result.current.stage).toBe('ready')
    expect(result.current.registration).toBeNull()
    expect(result.current.message).toMatch(/review the evidence package before registering/i)
  })
})

