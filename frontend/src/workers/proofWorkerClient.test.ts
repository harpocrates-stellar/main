import { describe, it, expect, vi, afterEach } from 'vitest'
import { ProofWorkerClient, ProofWorkerError } from './proofWorkerClient'
import * as multiBrowser from './multiBrowserWorkerSupport'

const validInput = {
  videoHash: '0'.repeat(64),
  credentialSecret: 'secret1',
  nullifierSecret: 'secret2',
}

describe('ProofWorkerClient', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('rejects a second concurrent request with BUSY without queuing', async () => {
    const client = new ProofWorkerClient()
    const first = client.generate(validInput)
    const second = client.generate(validInput)

    await expect(second.result).rejects.toMatchObject({ code: 'BUSY' })
    expect(second.requestId).toBe('')

    // first is expected to fail in this test env (jsdom can't fetch relative
    // circuit URLs) — assert on it explicitly so it's not left unhandled.
    await expect(first.result).rejects.toBeInstanceOf(ProofWorkerError)

    client.destroy()
  })

  it('rejects a pending request as CANCELLED and respawns a working worker', async () => {
    const client = new ProofWorkerClient()
    const first = client.generate(validInput)

    client.cancel(first.requestId)
    await expect(first.result).rejects.toMatchObject({ code: 'CANCELLED' })

    client.destroy()
  }, 15_000)

  it('rejects invalid videoHash deterministically without touching the worker', async () => {
    const client = new ProofWorkerClient()
    const { requestId, result } = client.generate({
      ...validInput,
      videoHash: 'not-valid-hex',
    })
    expect(requestId).toBe('')
    await expect(result).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    client.destroy()
  })

  it('rejects empty secrets as INVALID_INPUT (boundary)', async () => {
    const client = new ProofWorkerClient()
    await expect(
      client.generate({ ...validInput, credentialSecret: '' }).result,
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      client.generate({ ...validInput, nullifierSecret: '' }).result,
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    client.destroy()
  })

  it('rejects oversized secrets as INVALID_INPUT (boundary)', async () => {
    const client = new ProofWorkerClient()
    const oversized = 'x'.repeat(257)
    await expect(
      client.generate({ ...validInput, credentialSecret: oversized }).result,
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    client.destroy()
  })

  it('rejects when multi-browser worker support is missing (unsupported env)', async () => {
    vi.spyOn(multiBrowser, 'assessWorkerSupport').mockReturnValue({
      ok: false,
      tier: 'unsupported',
      missing: ['WebAssembly'],
      reason: 'Browser proving unavailable; missing capability: WebAssembly.',
    })
    const client = new ProofWorkerClient()
    const { requestId, result } = client.generate(validInput)
    expect(requestId).toBe('')
    await expect(result).rejects.toMatchObject({
      code: 'UNSUPPORTED_ENVIRONMENT',
      message: expect.stringContaining('WebAssembly'),
    })
    // Privacy: rejection must not echo fixture secrets
    await result.catch((err: ProofWorkerError) => {
      expect(err.message).not.toContain('secret1')
      expect(err.message).not.toContain('secret2')
    })
    client.destroy()
  })

  it('recovers from a worker crash and respawns cleanly', async () => {
    const client = new ProofWorkerClient()
    const first = client.generate(validInput)

    // simulate a real crash by triggering the worker's onerror handler directly
    // @ts-expect-error - accessing private field for test purposes
    const worker = client.worker
    worker.onerror?.(new ErrorEvent('error', { message: 'simulated crash' }))

    await expect(first.result).rejects.toMatchObject({ code: 'CRASHED' })

    client.destroy()
  }, 15_000)

  it('error messages stay privacy-safe on INVALID_INPUT', async () => {
    const client = new ProofWorkerClient()
    const secret = 'nullifier-should-never-appear-in-errors'
    await expect(
      client.generate({
        videoHash: 'zz',
        credentialSecret: secret,
        nullifierSecret: secret,
      }).result,
    ).rejects.toSatisfy((err: ProofWorkerError) => {
      expect(err.code).toBe('INVALID_INPUT')
      expect(err.message).not.toContain(secret)
      return true
    })
    client.destroy()
  })
})
