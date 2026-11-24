import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useEvidence } from './useEvidence'
import { ApiClientError } from '../services/apiError'

const { hashFileInWorkerMock, embedVideoMock, getWalletNetworkMock, registerProofOnStellarMock } =
  vi.hoisted(() => ({
    hashFileInWorkerMock: vi.fn(),
    embedVideoMock: vi.fn(),
    getWalletNetworkMock: vi.fn(),
    registerProofOnStellarMock: vi.fn(),
  }))

vi.mock('../config', () => ({
  appConfig: {
    harpocratesRegistryId: 'CTEST_REGISTRY_ID',
  },
}))

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
  getWalletNetwork: getWalletNetworkMock,
  registerProofOnStellar: registerProofOnStellarMock,
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

  describe('evidence notes preservation and recoverable API failure retry', () => {
    it('preserves user-entered evidence notes after a recoverable API failure', async () => {
      hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
      embedVideoMock.mockRejectedValueOnce(new Error('Steganography service 503 Service Unavailable'))

      const { result } = renderHook(() => useEvidence())
      const testFile = new File(['evidence-bytes'], 'surveillance.mp4', { lastModified: 1700000001000 })

      act(() => {
        result.current.setEvidenceNotes('Critical context: captured near east gate at 14:00')
      })
      expect(result.current.evidenceNotes).toBe('Critical context: captured near east gate at 14:00')

      await act(async () => {
        await result.current.handleEvidence(testFile)
      })

      // Recoverable API failure leaves the hook in error stage
      expect(result.current.stage).toBe('error')
      expect(result.current.message).toBe('Steganography service 503 Service Unavailable')
      // Original user-entered notes MUST be preserved
      expect(result.current.evidenceNotes).toBe('Critical context: captured near east gate at 14:00')
    })

    it('keeps the retry action tied to the reviewed file identity and preserves notes across successful recovery', async () => {
      hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
      embedVideoMock
        .mockRejectedValueOnce(new Error('Temporary network glitch'))
        .mockResolvedValueOnce({
          embeddedBlob: new Blob(['embedded-video']),
          embeddedHash: 'b'.repeat(64),
          metadataHash: 'c'.repeat(64),
        })

      const { result } = renderHook(() => useEvidence())
      const testFile = new File(['evidence-bytes'], 'surveillance.mp4', { lastModified: 1700000002000 })

      act(() => {
        result.current.setEvidenceNotes('Initial observation notes')
      })

      await act(async () => {
        await result.current.handleEvidence(testFile)
      })
      expect(result.current.stage).toBe('error')
      expect(result.current.evidenceNotes).toBe('Initial observation notes')

      // Retry the reviewed file identity
      await act(async () => {
        await result.current.retryEvidence()
      })

      expect(result.current.stage).toBe('ready')
      expect(result.current.evidenceNotes).toBe('Initial observation notes')
      expect(result.current.proof?.evidenceNotes).toBe('Initial observation notes')
      expect(result.current.proof?.sourceHash).toBe('a'.repeat(64))
    })

    it('does not overwrite local edits made after failure with stale server results on retry', async () => {
      hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
      embedVideoMock
        .mockRejectedValueOnce(new Error('Recoverable 500 error'))
        .mockResolvedValueOnce({
          embeddedBlob: new Blob(['embedded-video']),
          embeddedHash: 'b'.repeat(64),
          metadataHash: 'c'.repeat(64),
        })

      const { result } = renderHook(() => useEvidence())
      const testFile = new File(['evidence-bytes'], 'cam01.mp4', { lastModified: 1700000003000 })

      act(() => {
        result.current.setEvidenceNotes('First draft of notes')
      })

      await act(async () => {
        await result.current.handleEvidence(testFile)
      })
      expect(result.current.stage).toBe('error')

      // User modifies notes locally after the failure
      act(() => {
        result.current.setEvidenceNotes('Updated notes with corrected timestamp')
      })

      // Retrying should preserve the updated local edits, not overwrite them
      await act(async () => {
        await result.current.retryEvidence()
      })

      expect(result.current.stage).toBe('ready')
      expect(result.current.evidenceNotes).toBe('Updated notes with corrected timestamp')
      expect(result.current.proof?.evidenceNotes).toBe('Updated notes with corrected timestamp')
    })

    it('boundary case: preserves notes when retrying same file identity, but clears notes when selecting a different file', async () => {
      hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
      embedVideoMock.mockRejectedValue(new Error('Backend error'))

      const { result } = renderHook(() => useEvidence())
      const fileA = new File(['bytes-a'], 'fileA.mp4', { lastModified: 1700000004000 })
      const fileB = new File(['bytes-b'], 'fileB.mp4', { lastModified: 1700000005000 })

      act(() => {
        result.current.setEvidenceNotes('Notes specific to File A')
      })

      await act(async () => {
        await result.current.handleEvidence(fileA)
      })
      expect(result.current.stage).toBe('error')
      // Retrying same file identity preserves notes
      expect(result.current.evidenceNotes).toBe('Notes specific to File A')

      // Selecting a completely different file clears previous notes
      await act(async () => {
        await result.current.handleEvidence(fileB)
      })
      expect(result.current.evidenceNotes).toBe('')
    })

    it('no-ops safely when retryEvidence is invoked with no reviewed file identity', async () => {
      const { result } = renderHook(() => useEvidence())
      await act(async () => {
        await result.current.retryEvidence()
      })
      expect(result.current.stage).toBe('idle')
      expect(result.current.file).toBeNull()
    })
  })
})

  it('clears stale proof and download URL immediately on file replacement and sets a privacy-safe notice', async () => {
    const revokeObjectURL = vi.fn()
    let objectUrlCounter = 0
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: () => `blob:embedded-${++objectUrlCounter}`,
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: revokeObjectURL,
    })

    let finishSecondHash!: (hash: string) => void
    hashFileInWorkerMock
      .mockResolvedValueOnce('1'.repeat(64))
      .mockImplementationOnce(
        () =>
          new Promise<string>((resolve) => {
            finishSecondHash = resolve
          }),
      )
    embedVideoMock
      .mockResolvedValueOnce({
        embeddedBlob: new Blob(['first-embedded']),
        embeddedHash: '2'.repeat(64),
        metadataHash: '3'.repeat(64),
      })
      .mockResolvedValueOnce({
        embeddedBlob: new Blob(['second-embedded']),
        embeddedHash: '4'.repeat(64),
        metadataHash: '5'.repeat(64),
      })

    const { result } = renderHook(() => useEvidence())

    await act(async () => {
      await result.current.handleEvidence(new File(['first'], 'secret-first.mp4'))
    })

    expect(result.current.stage).toBe('ready')
    expect(result.current.proof?.videoHash).toBe('2'.repeat(64))
    expect(result.current.processedVideoUrl).toBe('blob:embedded-1')
    expect(result.current.evidenceChangeNotice).toBeNull()

    let secondRun!: Promise<void>
    act(() => {
      secondRun = result.current.handleEvidence(new File(['second'], 'secret-second.mp4'))
    })

    // Immediately upon replacement (while hashing is in flight), prior proof & blob URL are cleared.
    expect(result.current.proof).toBeNull()
    expect(result.current.registration).toBeNull()
    expect(result.current.processedVideoUrl).toBe('')
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:embedded-1')
    expect(result.current.evidenceChangeNotice).toBe(EVIDENCE_REPLACED_MESSAGE)
    expect(result.current.evidenceChangeNotice).not.toContain('secret-first.mp4')
    expect(result.current.evidenceChangeNotice).not.toContain('secret-second.mp4')

    await act(async () => {
      finishSecondHash('6'.repeat(64))
      await secondRun
    })

    expect(result.current.stage).toBe('ready')
    expect(result.current.proof?.videoHash).toBe('4'.repeat(64))
    expect(result.current.processedVideoUrl).toBe('blob:embedded-2')
    expect(result.current.evidenceChangeNotice).toBe(EVIDENCE_REPLACED_MESSAGE)
  })

  it('keeps prior proof cleared and preserves the replacement notice when the replacement file fails', async () => {
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: () => 'blob:first-embedded',
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: vi.fn(),
    })

    hashFileInWorkerMock
      .mockResolvedValueOnce('1'.repeat(64))
      .mockRejectedValueOnce(new Error('Replacement hashing failed.'))
    embedVideoMock.mockResolvedValueOnce({
      embeddedBlob: new Blob(['first-embedded']),
      embeddedHash: '2'.repeat(64),
      metadataHash: '3'.repeat(64),
    })

    const { result } = renderHook(() => useEvidence())

    await act(async () => {
      await result.current.handleEvidence(new File(['first'], 'first.mp4'))
    })
    expect(result.current.proof?.videoHash).toBe('2'.repeat(64))

    await act(async () => {
      await result.current.handleEvidence(new File(['broken'], 'broken.mp4'))
    })

    expect(result.current.stage).toBe('error')
    expect(result.current.message).toBe('Replacement hashing failed.')
    expect(result.current.proof).toBeNull()
    expect(result.current.registration).toBeNull()
    expect(result.current.processedVideoUrl).toBe('')
    expect(result.current.evidenceChangeNotice).toBe(EVIDENCE_REPLACED_MESSAGE)
  })

  it('preserves existing evidence state when file selection is cancelled with null', async () => {
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: () => 'blob:first-embedded',
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: vi.fn(),
    })

    hashFileInWorkerMock.mockResolvedValueOnce('1'.repeat(64))
    embedVideoMock.mockResolvedValueOnce({
      embeddedBlob: new Blob(['first-embedded']),
      embeddedHash: '2'.repeat(64),
      metadataHash: '3'.repeat(64),
    })

    const { result } = renderHook(() => useEvidence())

    await act(async () => {
      await result.current.handleEvidence(new File(['first'], 'first.mp4'))
    })

    await act(async () => {
      await result.current.handleEvidence(null)
    })

    expect(result.current.stage).toBe('ready')
    expect(result.current.proof?.videoHash).toBe('2'.repeat(64))
    expect(result.current.processedVideoUrl).toBe('blob:first-embedded')
    expect(result.current.evidenceChangeNotice).toBeNull()
  })
})

describe('useEvidence upload admission and queue state', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('maps queue_full backend rejection to actionable admission state', async () => {
    hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
    embedVideoMock.mockRejectedValue(
      new ApiClientError({
        code: 'QUEUE_FULL',
        message: 'Upload queue is currently full. Wait 5 seconds and retry.',
        detail: 'service overloaded',
        requestId: null,
        action: 'retry',
        retryable: true,
        status: 503,
        reason: 'queue_full',
        retryAfter: 5,
      }),
    )

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      await result.current.handleEvidence(new File(['bytes'], 'evidence.mp4'))
    })

    expect(result.current.stage).toBe('error')
    expect(result.current.uploadErrorKind).toBe('admission_rejected')
    expect(result.current.isRejectedUpload).toBe(true)
    expect(result.current.isInvalidEvidence).toBe(false)
    expect(result.current.admissionState).toEqual({
      status: 'rejected',
      reason: 'queue_full',
      message: 'Upload queue is currently full. Wait 5 seconds and retry.',
      retryAfter: 5,
      retryable: true,
      actionHint: 'retry',
    })
  })

  it('maps identity_limit rejection to actionable admission state', async () => {
    hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
    embedVideoMock.mockRejectedValue(
      new ApiClientError({
        code: 'IDENTITY_LIMIT',
        message: 'Identity limit reached. Try again in 10s.',
        detail: 'service overloaded',
        requestId: null,
        action: 'retry',
        retryable: true,
        status: 429,
        reason: 'identity_limit',
        retryAfter: 10,
      }),
    )

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      await result.current.handleEvidence(new File(['bytes'], 'evidence.mp4'))
    })

    expect(result.current.uploadErrorKind).toBe('admission_rejected')
    expect(result.current.isRejectedUpload).toBe(true)
    expect(result.current.admissionState?.reason).toBe('identity_limit')
    expect(result.current.admissionState?.retryAfter).toBe(10)
  })

  it('maps timeout rejection to actionable admission state', async () => {
    hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
    embedVideoMock.mockRejectedValue(
      new ApiClientError({
        code: 'TIMEOUT',
        message: 'Request timed out waiting for admission slot.',
        detail: 'service overloaded',
        requestId: null,
        action: 'retry',
        retryable: true,
        status: 503,
        reason: 'timeout',
        retryAfter: null,
      }),
    )

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      await result.current.handleEvidence(new File(['bytes'], 'evidence.mp4'))
    })

    expect(result.current.uploadErrorKind).toBe('admission_rejected')
    expect(result.current.isRejectedUpload).toBe(true)
    expect(result.current.admissionState?.reason).toBe('timeout')
  })

  it('distinguishes invalid evidence from admission rejection', async () => {
    hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
    embedVideoMock.mockRejectedValue(
      new ApiClientError({
        code: 'VALIDATION_ERROR',
        message: 'Video file corrupted or unsupported format.',
        detail: 'Invalid container format',
        requestId: null,
        action: 'fix_input',
        retryable: false,
        status: 400,
      }),
    )

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      await result.current.handleEvidence(new File(['bytes'], 'evidence.mp4'))
    })

    expect(result.current.stage).toBe('error')
    expect(result.current.uploadErrorKind).toBe('invalid_evidence')
    expect(result.current.isRejectedUpload).toBe(false)
    expect(result.current.isInvalidEvidence).toBe(true)
    expect(result.current.admissionState).toBeNull()
  })

  it('retries upload with the active file when retryUpload is called', async () => {
    hashFileInWorkerMock.mockResolvedValue('a'.repeat(64))
    embedVideoMock
      .mockRejectedValueOnce(
        new ApiClientError({
          code: 'QUEUE_FULL',
          message: 'Queue full.',
          detail: 'service overloaded',
          requestId: null,
          action: 'retry',
          retryable: true,
          status: 503,
          reason: 'queue_full',
          retryAfter: 2,
        }),
      )
      .mockResolvedValueOnce({
        embeddedBlob: new Blob(['embedded']),
        embeddedHash: 'b'.repeat(64),
        metadataHash: 'c'.repeat(64),
      })

    const { result } = renderHook(() => useEvidence())
    const testFile = new File(['bytes'], 'evidence.mp4')

    await act(async () => {
      await result.current.handleEvidence(testFile)
    })

    expect(result.current.isRejectedUpload).toBe(true)
    expect(result.current.stage).toBe('error')

    // Calling retryUpload triggers handleEvidence with testFile
    await act(async () => {
      await result.current.retryUpload()
    })

    expect(result.current.stage).toBe('ready')
    expect(result.current.uploadErrorKind).toBe('none')
    expect(result.current.isRejectedUpload).toBe(false)
    expect(result.current.admissionState?.status).toBe('admitted')
  })

  it('resets admission state when cancelEvidence is called', async () => {
    hashFileInWorkerMock.mockImplementation(() => new Promise(() => {}))

    const { result } = renderHook(() => useEvidence())
    act(() => {
      void result.current.handleEvidence(new File(['bytes'], 'evidence.mp4'))
    })

    act(() => {
      result.current.cancelEvidence()
    })

    expect(result.current.stage).toBe('cancelled')
    expect(result.current.admissionState).toBeNull()
    expect(result.current.uploadErrorKind).toBe('none')
    expect(result.current.isRejectedUpload).toBe(false)
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

