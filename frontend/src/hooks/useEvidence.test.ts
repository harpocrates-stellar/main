/**
 * Tests for the cancellable useEvidence hook.
 * Uses synthetic evidence, no real media, secrets, or network calls.
 * ~cancel upload~ and ~cancel proof generation~ are exercised along with the
 * sequence guard and the stable, privacy-safe cancellation copy.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useEvidence } from './useEvidence'

vi.mock('../services/evidenceService', () => ({
  embedVideo: vi.fn(),
  persistRegistration: vi.fn(),
  fetchRecentEvents: vi.fn(),
}))

vi.mock('../stellar', () => ({
  getWalletNetwork: vi.fn(),
  registerProofOnStellar: vi.fn(),
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
}))

vi.mock('../networkGuard', () => ({
  checkNetworkMatch: vi.fn(),
}))

// Minimal worker-client double so no real Worker is spawned.
vi.mock('../workers/proofWorkerClient', () => {
  class ProofWorkerError extends Error {
    code: string
    constructor(code: string, message = code) {
      super(message)
      this.name = 'ProofWorkerError'
      this.code = code
    }
  }
  return {
    ProofWorkerClient: vi.fn(),
    ProofWorkerError,
  }
})

vi.mock('../noirClient', () => ({
  generateSilentWitnessProof: vi.fn(),
}))

function makeVideoFile(name = 'evidence.mp4', bytes = new Uint8Array([1, 2, 3])) {
  return new File([bytes], name, { type: 'video/mp4' })
}

function makeResolvedEmbed(hashSuffix = 'e') {
  return {
    embeddedBlob: new Blob(['embedded-bytes'], { type: 'video/mp4' }),
    embeddedHash: hashSuffix.repeat(64),
    metadataHash: 'm'.repeat(64),
  }
}

async function defaultsForPositiveFlows() {
  const evid = (await import('../services/evidenceService')) as unknown as {
    embedVideo: ReturnType<typeof vi.fn>
    persistRegistration: ReturnType<typeof vi.fn>
  }
  evid.embedVideo.mockResolvedValue(makeResolvedEmbed())
  evid.persistRegistration.mockResolvedValue(undefined)

  const stel = (await import('../stellar')) as unknown as {
    getWalletNetwork: ReturnType<typeof vi.fn>
    registerProofOnStellar: ReturnType<typeof vi.fn>
  }
  stel.getWalletNetwork.mockResolvedValue('Test SDF Network ; September 2015')
  stel.registerProofOnStellar.mockResolvedValue({ hash: 'txhash', status: 'PENDING' })

  const ng = (await import('../networkGuard')) as unknown as {
    checkNetworkMatch: ReturnType<typeof vi.fn>
  }
  ng.checkNetworkMatch.mockReturnValue({ ok: true, reason: '', remediation: '' })
}

beforeEach(async () => {
  vi.clearAllMocks()
  // Only stub blob URLs when the runtime provides them (jsdom does); never rely
  // on real object URLs in tests.
  if (typeof URL.createObjectURL === 'function') {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:test')
  }
  if (typeof URL.revokeObjectURL === 'function') {
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
  }
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

// ── upload ────────────────────────────────────────────────────────────────

describe('useEvidence – upload', () => {
  it('completes an embed to the ready stage', async () => {
    await defaultsForPositiveFlows()
    const evid = (await import('../services/evidenceService')) as unknown as {
      embedVideo: ReturnType<typeof vi.fn>
    }

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      await result.current.handleEvidence(makeVideoFile('clip.mp4'))
    })

    expect(evid.embedVideo).toHaveBeenCalledTimes(1)
    const [, , , , , signalArg] = evid.embedVideo.mock.calls[0]
    expect(signalArg).toBeInstanceOf(AbortSignal)
    expect(result.current.stage).toBe('ready')
    expect(result.current.proof?.videoHash).toBe('e'.repeat(64))
    expect(result.current.proof?.fileName).toContain('harpocrates-')
    expect(result.current.isCancellable).toBe(false)
  })

  it('cancels an in-flight upload with stable copy and no leftovers', async () => {
    await defaultsForPositiveFlows()
    const evid = (await import('../services/evidenceService')) as unknown as {
      embedVideo: ReturnType<typeof vi.fn>
    }
    evid.embedVideo.mockImplementation(
      (_file: File, _tier: unknown, _sh: string, _pid: string, _ts: string, signal?: AbortSignal) =>
        new Promise((_resolve, reject) => {
          signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
        }),
    )

    const { result } = renderHook(() => useEvidence())
    let p: Promise<void>
    act(() => {
      p = result.current.handleEvidence(makeVideoFile('private-footage-997.mp4'))
    })
    await act(async () => {
      await vi.waitFor(() => expect(evid.embedVideo).toHaveBeenCalledTimes(1))
    })
    expect(result.current.stage).toBe('embedding')
    expect(result.current.isCancellable).toBe(true)

    const [, , , , , signalArg] = evid.embedVideo.mock.calls[0] as [unknown, unknown, unknown, unknown, unknown, AbortSignal]
    expect(signalArg.aborted).toBe(false)

    await act(async () => {
      result.current.cancelEvidence()
    })
    await act(async () => {
      await p!.catch(() => {})
    })

    expect(signalArg.aborted).toBe(true)
    expect(result.current.stage).toBe('cancelled')
    expect(result.current.message).toBe('Upload cancelled.')
    expect(result.current.isCancellable).toBe(false)
    expect(result.current.proof).toBeNull()
    expect(result.current.file).toBeNull()
  })

  it('ignores a stale upload that settles after cancellation', async () => {
    await defaultsForPositiveFlows()
    const evid = (await import('../services/evidenceService')) as unknown as {
      embedVideo: ReturnType<typeof vi.fn>
    }
    let firstResolve: (v: unknown) => void
    evid.embedVideo.mockImplementationOnce(
      () => new Promise((resolve) => {
        firstResolve = resolve
      }),
    )
    evid.embedVideo.mockResolvedValueOnce(makeResolvedEmbed('b'))

    const { result } = renderHook(() => useEvidence())
    let p: Promise<void>
    act(() => {
      p = result.current.handleEvidence(makeVideoFile('first.mp4'))
    })
    await act(async () => {
      await vi.waitFor(() => expect(evid.embedVideo).toHaveBeenCalledTimes(1))
    })

    act(() => {
      result.current.cancelEvidence()
    })

    // Stale first upload settles after cancellation — must be discarded.
    await act(async () => {
      firstResolve!({ embeddedBlob: new Blob(['stale']), embeddedHash: '1'.repeat(64), metadataHash: '2'.repeat(64) })
    })
    await act(async () => {
      await p!.catch(() => {})
    })

    expect(result.current.stage).toBe('cancelled')
    expect(result.current.message).toBe('Upload cancelled.')
  })

  it('does nothing when called with a null file', async () => {
    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      await result.current.handleEvidence(null)
    })
    expect(result.current.stage).toBe('idle')
  })
})

// ── proof generation (module worker path) ─────────────────────────────────

describe('useEvidence – cancel proof generation (module worker path)', () => {
  it('cancels the worker request and maps CANCELLED to stable copy', async () => {
    await defaultsForPositiveFlows()

    const pc = (await import('../workers/proofWorkerClient')) as unknown as {
      ProofWorkerClient: ReturnType<typeof vi.fn>
      ProofWorkerError: new (code: string, message?: string) => Error & { code: string }
    }
    const { ProofWorkerError } = pc

    let rejectResult: (e: unknown) => void
    const fakeClient = {
      generate: vi.fn(() => {
        const result = new Promise<void>((_resolve, reject) => {
          rejectResult = reject
        })
        return { requestId: 'req-1', result }
      }),
      cancel: vi.fn((requestId: string) => {
        rejectResult(new ProofWorkerError('CANCELLED', 'Proof generation cancelled.'))
        void requestId
      }),
      destroy: vi.fn(),
    }
    pc.ProofWorkerClient.mockImplementation(function (this: unknown) {
      void this
      return fakeClient
    })

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      result.current.setCredentialSeed('my-cred-seed')
      result.current.setNullifierSeed('my-null-seed')
    })
    await act(async () => {
      await result.current.handleEvidence(makeVideoFile('clip.mp4'))
    })

    let p: Promise<void>
    act(() => {
      p = result.current.registerProof('GSOURCEGAUTH')
    })
    await act(async () => {
      await vi.waitFor(() => expect(fakeClient.generate).toHaveBeenCalledTimes(1))
    })
    expect(result.current.stage).toBe('proving')

    await act(async () => {
      result.current.cancelEvidence()
    })
    await act(async () => {
      await p!.catch(() => {})
    })

    expect(fakeClient.cancel).toHaveBeenCalledWith('req-1')
    expect(fakeClient.destroy).toHaveBeenCalledTimes(1)
    expect(result.current.stage).toBe('cancelled')
    expect(result.current.message).toBe('Proof generation cancelled.')
  })

  it('requires credential and nullifier seeds before proving', async () => {
    await defaultsForPositiveFlows()

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      await result.current.handleEvidence(makeVideoFile('clip.mp4'))
    })

    await act(async () => {
      await result.current.registerProof('GSOURCEGAUTH').catch(() => {})
    })

    expect(result.current.stage).toBe('error')
    expect(result.current.message).toMatch(/credential and nullifier seeds/i)
  })

  it('fails closed without executing witnesses on the UI thread', async () => {
    await defaultsForPositiveFlows()
    const noir = (await import('../noirClient')) as unknown as {
      generateSilentWitnessProof: ReturnType<typeof vi.fn>
    }

    const pc = (await import('../workers/proofWorkerClient')) as unknown as {
      ProofWorkerClient: ReturnType<typeof vi.fn>
      ProofWorkerError: new (code: string, message?: string) => Error & { code: string }
    }
    pc.ProofWorkerClient.mockImplementation(function (this: unknown) {
      void this
      return {
        generate: vi.fn(() => ({ requestId: '', result: Promise.reject(new pc.ProofWorkerError('UNSUPPORTED_ENVIRONMENT')) })),
        cancel: vi.fn(),
        destroy: vi.fn(),
      }
    })

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      result.current.setCredentialSeed('my-cred-seed')
      result.current.setNullifierSeed('my-null-seed')
    })
    await act(async () => {
      await result.current.handleEvidence(makeVideoFile('clip.mp4'))
    })

    await act(async () => {
      await result.current.registerProof('GSOURCEGAUTH').catch(() => {})
    })

    // No main-thread fallback: the unsupported environment surfaces and the
    // noirClient prover is never invoked on the UI thread.
    expect(noir.generateSilentWitnessProof).not.toHaveBeenCalled()
    expect(result.current.stage).toBe('error')
  })
})

// ── registration ──────────────────────────────────────────────────────────

describe('useEvidence – registerProof', () => {
  it('registers a ready source-tier proof on Stellar', async () => {
    await defaultsForPositiveFlows()

    const { result } = renderHook(() => useEvidence())
    await act(async () => {
      result.current.setSelectedTier('source')
    })
    await act(async () => {
      await result.current.handleEvidence(makeVideoFile('clip.mp4'))
    })
    expect(result.current.stage).toBe('ready')

    await act(async () => {
      await result.current.registerProof('GSOURCEGAUTH')
    })

    expect(result.current.stage).toBe('registered')
    expect(result.current.message).toMatch(/Registration submitted/i)
    expect(result.current.registration?.status).toBe('PENDING')
  })
})

// ── lifecycle and privacy ─────────────────────────────────────────────────

describe('useEvidence – cancellation lifecycle and privacy', () => {
  it('cancelEvidence is a no-op when the flow is not cancellable', async () => {
    await defaultsForPositiveFlows()

    const { result } = renderHook(() => useEvidence())
    expect(result.current.isCancellable).toBe(false)
    act(() => {
      result.current.cancelEvidence()
    })
    expect(result.current.stage).toBe('idle')
    expect(result.current.message).toBe('Upload evidence to begin.')

    await act(async () => {
      await result.current.handleEvidence(makeVideoFile('clip.mp4'))
    })
    expect(result.current.stage).toBe('ready')
    act(() => {
      result.current.cancelEvidence()
    })
    expect(result.current.stage).toBe('ready')
  })

  it('cancellation copy is stable and never leaks file names, hashes, or secrets', async () => {
    await defaultsForPositiveFlows()
    const evid = (await import('../services/evidenceService')) as unknown as {
      embedVideo: ReturnType<typeof vi.fn>
    }
    evid.embedVideo.mockImplementation(
      (_file: File, _tier: unknown, _sh: string, _pid: string, _ts: string, signal?: AbortSignal) =>
        new Promise((_resolve, reject) => {
          signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
        }),
    )

    const { result } = renderHook(() => useEvidence())
    let p: Promise<void>
    act(() => {
      p = result.current.handleEvidence(makeVideoFile('private-footage-997.mp4'))
    })
    await act(async () => {
      await vi.waitFor(() => expect(evid.embedVideo).toHaveBeenCalledTimes(1))
    })
    await act(async () => {
      result.current.cancelEvidence()
    })
    await act(async () => {
      await p!.catch(() => {})
    })

    const copy = result.current.message
    expect(copy).toBe('Upload cancelled.')
    expect(copy).not.toMatch(/private-footage|997|e{40,}|[0-9a-f]{40,}/i)
  })
})