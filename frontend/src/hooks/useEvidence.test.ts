import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { EVIDENCE_REPLACED_MESSAGE, useEvidence } from './useEvidence'

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

describe('useEvidence proof preparation preview', () => {
  afterEach(() => {
    vi.clearAllMocks()
    vi.restoreAllMocks()
  })

  it('previews canonical public inputs before proving and submits nothing', async () => {
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
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    const { result } = renderHook(() => useEvidence())
    expect(result.current.proofPreparation).toMatchObject({
      ok: false,
      code: 'MISSING_EVIDENCE',
    })

    await act(async () => {
      await result.current.handleEvidence(new File(['x'], 'evidence.mp4'))
    })

    expect(result.current.stage).toBe('ready')
    const preview = result.current.proofPreparation
    expect(preview.ok).toBe(true)
    if (!preview.ok) return

    expect(preview.policyId).toBe('silent_witness/input-v1')
    expect(preview.policyVersion).toBe(1)
    expect(preview.publicInputs.map((field) => field.key)).toEqual([
      'video_hash_hi',
      'video_hash_lo',
      'verifier_scope',
      'epoch',
    ])
    expect(preview.publicInputs.find((field) => field.key === 'verifier_scope')?.value).toBe('0')
    expect(preview.publicInputs.find((field) => field.key === 'video_hash_hi')?.value).toBe(
      BigInt(`0x${'b'.repeat(32)}`).toString(10),
    )
    expect(preview.concealedInputs.every((field) => field.value === '[REDACTED]')).toBe(true)
    expect(preview.readOnly).toBe(true)
    expect(preview.transactionSubmission).toBe('none')
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})

describe('useEvidence guided network mismatch recovery', () => {
  afterEach(() => {
    vi.clearAllMocks()
    vi.restoreAllMocks()
  })

  async function prepareEvidence() {
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
    await act(async () => {
      await hook.result.current.handleEvidence(new File(['x'], 'evidence.mp4'))
    })
    return hook
  }

  it('populates required and current wallet networks on mismatch and resumes only after fresh validation', async () => {
    const { result } = await prepareEvidence()

    getWalletNetworkMock.mockResolvedValueOnce('Public Global Stellar Network ; September 2015')
    await act(async () => {
      await result.current.registerProof('GSOURCEGAUTH')
    })

    expect(registerProofOnStellarMock).not.toHaveBeenCalled()
    expect(result.current.networkMismatchRecovery).toMatchObject({
      requiredNetwork: 'Testnet',
      currentWalletNetwork: 'Mainnet',
      isValidating: false,
      validationError: null,
      intent: {
        tier: 'silent',
        videoHash: 'b'.repeat(64),
      },
    })

    // Still on wrong network — fresh validation must fail closed and keep recovery active.
    getWalletNetworkMock.mockResolvedValueOnce('Test SDF Future Network ; October 2022')
    let resumed = true
    await act(async () => {
      resumed = await result.current.revalidateNetworkMismatch('GSOURCEGAUTH')
    })
    expect(resumed).toBe(false)
    expect(result.current.networkMismatchRecovery?.currentWalletNetwork).toBe('Futurenet')
    expect(result.current.networkMismatchRecovery?.validationError).toContain('Futurenet')

    // Wallet switched to Testnet — fresh validation clears recovery so registration can resume.
    getWalletNetworkMock.mockResolvedValueOnce('Test SDF Network ; September 2015')
    await act(async () => {
      resumed = await result.current.revalidateNetworkMismatch('GSOURCEGAUTH')
    })
    expect(resumed).toBe(true)
    expect(result.current.networkMismatch).toBeNull()
    expect(result.current.networkMismatchRecovery).toBeNull()
    expect(result.current.message).toContain('Network validated on Testnet')
  })

  it('refuses to resume when the selected identity tier changed since evidence preparation', async () => {
    const { result } = await prepareEvidence()

    getWalletNetworkMock.mockResolvedValueOnce('Public Global Stellar Network ; September 2015')
    await act(async () => {
      await result.current.registerProof('GSOURCEGAUTH')
    })
    expect(result.current.networkMismatchRecovery?.requiredNetwork).toBe('Testnet')

    // Switch identity tier without re-preparing evidence.
    act(() => {
      result.current.setSelectedTier('source')
    })

    getWalletNetworkMock.mockResolvedValueOnce('Test SDF Network ; September 2015')
    let resumed = true
    await act(async () => {
      resumed = await result.current.revalidateNetworkMismatch('GSOURCEGAUTH')
    })

    expect(resumed).toBe(false)
    expect(result.current.networkMismatchRecovery).not.toBeNull()
    expect(result.current.networkMismatchRecovery?.validationError).toContain(
      'Selected identity tier changed',
    )
    expect(getWalletNetworkMock).toHaveBeenCalledTimes(1)
  })
})
