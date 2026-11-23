import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createVerificationRevisionGuard,
  runVerificationFlow,
  verifyUploadedVideo,
} from './verificationFlow'

const { extractMetadata, fetchProofEventsByVideo, getOnChainProof } = vi.hoisted(() => ({
  extractMetadata: vi.fn(),
  fetchProofEventsByVideo: vi.fn(),
  getOnChainProof: vi.fn(),
}))

vi.mock('./verificationService', () => ({
  extractMetadata,
  fetchProofEventsByVideo,
  getOnChainProof,
}))

const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)

describe('createVerificationRevisionGuard', () => {
  it('issues monotonically increasing revisions and invalidates previous ones', () => {
    const guard = createVerificationRevisionGuard()
    expect(guard.current()).toBe(0)
    expect(guard.isCurrent(0)).toBe(false)
    expect(guard.isCurrent(-1)).toBe(false)

    const rev1 = guard.next()
    expect(rev1).toBe(1)
    expect(guard.isCurrent(rev1)).toBe(true)

    const rev2 = guard.next()
    expect(rev2).toBe(2)
    expect(guard.isCurrent(rev1)).toBe(false)
    expect(guard.isCurrent(rev2)).toBe(true)
  })

  it('invalidates the active revision on cancel/clear', () => {
    const guard = createVerificationRevisionGuard()
    const rev1 = guard.next()
    expect(guard.isCurrent(rev1)).toBe(true)

    const invalidated = guard.invalidate()
    expect(invalidated).toBeGreaterThan(rev1)
    expect(guard.isCurrent(rev1)).toBe(false)
  })
})

describe('runVerificationFlow', () => {
  beforeEach(() => {
    extractMetadata.mockReset()
    fetchProofEventsByVideo.mockReset()
    getOnChainProof.mockReset()
  })

  it('binds the supplied request revision to the returned result', async () => {
    fetchProofEventsByVideo.mockResolvedValue([])
    getOnChainProof.mockResolvedValue(null)

    const result = await runVerificationFlow(HASH_A, { revision: 42 })

    expect(result.videoHash).toBe(HASH_A)
    expect(result.revision).toBe(42)
  })

  it('keeps revision undefined when caller does not supply one', async () => {
    fetchProofEventsByVideo.mockResolvedValue([])
    getOnChainProof.mockResolvedValue(null)

    const result = await runVerificationFlow(HASH_A)

    expect(result.revision).toBeUndefined()
  })

  it('rejects with AbortError when signal is already aborted before network calls', async () => {
    const controller = new AbortController()
    controller.abort()

    await expect(
      runVerificationFlow(HASH_A, { signal: controller.signal, revision: 1 }),
    ).rejects.toMatchObject({ name: 'AbortError' })

    expect(fetchProofEventsByVideo).not.toHaveBeenCalled()
    expect(getOnChainProof).not.toHaveBeenCalled()
  })

  it('rejects with AbortError when signal aborts while getOnChainProof is in flight', async () => {
    const controller = new AbortController()
    fetchProofEventsByVideo.mockResolvedValue([])
    getOnChainProof.mockImplementation(async () => {
      controller.abort()
      return {
        videoHash: HASH_A,
        metadataHash: HASH_B,
        tier: 1,
        status: 1,
        createdAt: '123',
        expiresAt: 0,
        source: null,
        issuer: null,
      }
    })

    await expect(
      runVerificationFlow(HASH_A, { signal: controller.signal, revision: 2 }),
    ).rejects.toMatchObject({ name: 'AbortError' })
  })
})

describe('verifyUploadedVideo', () => {
  beforeEach(() => {
    extractMetadata.mockReset()
    fetchProofEventsByVideo.mockReset()
    getOnChainProof.mockReset()
  })

  it('binds revision and aborts cleanly if cancelled after extraction', async () => {
    const controller = new AbortController()
    const file = new File(['evidence'], 'evidence.mp4', { type: 'video/mp4' })
    extractMetadata.mockImplementation(async () => {
      controller.abort()
      return { hasHarpocratesMetadata: true }
    })

    await expect(
      verifyUploadedVideo(file, HASH_A, { signal: controller.signal, revision: 7 }),
    ).rejects.toMatchObject({ name: 'AbortError' })

    expect(fetchProofEventsByVideo).not.toHaveBeenCalled()
  })
})
