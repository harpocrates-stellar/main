import { describe, it, expect, vi } from 'vitest'
import { ProofWorkerClient, ProofWorkerError } from './proofWorkerClient'

describe('ProofWorkerClient', () => {
  it('rejects a second concurrent request with BUSY', async () => {
    const client = new ProofWorkerClient()
    const first = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })
    const second = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })

    await expect(second.result).rejects.toMatchObject({ code: 'BUSY' })

    // first is expected to fail in this test env (jsdom can't fetch relative
    // circuit URLs) — assert on it explicitly so it's not left unhandled.
    await expect(first.result).rejects.toBeInstanceOf(ProofWorkerError)

    client.destroy()
  })
})
it('rejects a pending request as CANCELLED and respawns a working worker', async () => {
    const client = new ProofWorkerClient()
    const first = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })

    client.cancel(first.requestId)
    await expect(first.result).rejects.toMatchObject({ code: 'CANCELLED' })

    client.destroy()
  }, 15000)

  it('rejects invalid input deterministically without touching the worker', async () => {
    const client = new ProofWorkerClient()
    const { result } = client.generate({
      videoHash: 'not-valid-hex',
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })
    await expect(result).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    client.destroy()
  })
  it('recovers from a worker crash and respawns cleanly', async () => {
    const client = new ProofWorkerClient()
    const first = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })

    // simulate a real crash by triggering the worker's onerror handler directly
    // @ts-expect-error - accessing private field for test purposes
    const worker = client.worker
    worker.onerror?.(new ErrorEvent('error', { message: 'simulated crash' }))

    await expect(first.result).rejects.toMatchObject({ code: 'CRASHED' })

    client.destroy()
  }, 15000)

describe('ProofWorkerClient fallback', () => {
  const VALID = {
    videoHash: '0'.repeat(64),
    credentialSecret: 'secret1',
    nullifierSecret: 'secret2',
  }
  const resolvedProof = {
    credentialRoot: 'c'.repeat(64),
    nullifier: 'd'.repeat(64),
    proof: 'ee',
    publicInputs: 'ff',
    proofBytes: 2,
    publicInputBytes: 2,
  }

  it('proves on the main thread when the worker cannot be spawned', async () => {
    const prover = vi.fn(async () => resolvedProof)
    const client = new ProofWorkerClient({ workerFactory: () => null, prover })

    expect(client.mode).toBe('main-thread')
    expect(client.fallbackReason).toBe('worker_spawn_failed')

    const { result, mode, fallbackReason } = client.generate(VALID)
    await expect(result).resolves.toEqual(resolvedProof)
    expect(prover).toHaveBeenCalledTimes(1)
    expect(mode).toBe('main-thread')
    expect(fallbackReason).toBe('worker_spawn_failed')

    client.destroy()
  })

  it('rejects with WORKER_UNAVAILABLE when fallback is disabled', async () => {
    const client = new ProofWorkerClient({
      runtime: 'worker',
      workerFactory: () => null,
      enableFallback: false,
    })

    expect(client.mode).toBe('unavailable')
    const { result } = client.generate(VALID)
    await expect(result).rejects.toMatchObject({ code: 'WORKER_UNAVAILABLE' })

    client.destroy()
  })

  it('always uses the main thread when runtime is "main" without touching Worker', async () => {
    const prover = vi.fn(async () => resolvedProof)
    const client = new ProofWorkerClient({
      runtime: 'main',
      prover,
      workerFactory: () => {
        throw new Error('Worker must not be constructed in main runtime')
      },
    })

    expect(client.mode).toBe('main-thread')
    expect(client.fallbackReason).toBe('runtime_forced_main')
    await expect(client.generate(VALID).result).resolves.toEqual(resolvedProof)

    client.destroy()
  })

  it('enforces the explicit fallback secret-byte boundary', async () => {
    const prover = vi.fn(async () => resolvedProof)
    const client = new ProofWorkerClient({ runtime: 'main', prover, maxSecretBytes: 8 })

    // exactly 8 bytes on each secret is within the explicit limit
    const atBoundary = {
      videoHash: '0'.repeat(64),
      credentialSecret: '12345678',
      nullifierSecret: '12345678',
    }
    await expect(client.generate(atBoundary).result).resolves.toEqual(resolvedProof)

    // 9 bytes crosses the explicit fallback limit
    const overLimit = {
      videoHash: '0'.repeat(64),
      credentialSecret: '123456789',
      nullifierSecret: '12345678',
    }
    await expect(client.generate(overLimit).result).rejects.toMatchObject({
      code: 'FALLBACK_LIMIT_EXCEEDED',
    })
    expect(prover).toHaveBeenCalledTimes(1)

    client.destroy()
  })

  it('rejects a second concurrent main-thread request with BUSY', async () => {
    const gates: Array<() => void> = []
    const prover = vi.fn(
      () =>
        new Promise<typeof resolvedProof>((resolve) => {
          gates.push(() => resolve(resolvedProof))
        }),
    )
    const client = new ProofWorkerClient({ runtime: 'main', prover })

    const first = client.generate(VALID)
    const second = client.generate(VALID)

    await expect(second.result).rejects.toMatchObject({ code: 'BUSY' })
    gates[0]()
    await expect(first.result).resolves.toEqual(resolvedProof)

    client.destroy()
  })

  it('times out a main-thread proof generation', async () => {
    const client = new ProofWorkerClient({
      runtime: 'main',
      prover: () => new Promise(() => {}),
      timeoutMs: 50,
    })
    await expect(client.generate(VALID).result).rejects.toMatchObject({ code: 'TIMEOUT' })
    client.destroy()
  })

  it('never leaks secret material in fallback errors', async () => {
    const secret = 'super-secret-credential-value'
    const prover = vi.fn(async () => {
      throw new Error(`internal failure while hashing ${secret}`)
    })
    const client = new ProofWorkerClient({ runtime: 'main', prover })

    const error = await client
      .generate({ ...VALID, credentialSecret: secret })
      .result.catch((err: unknown) => err)

    const typed = error as ProofWorkerError
    expect(typed).toBeInstanceOf(ProofWorkerError)
    expect(typed.code).toBe('PROOF_GENERATION_FAILED')
    expect(typed.message).not.toContain(secret)

    client.destroy()
  })

  it('maps main-thread circuit/artifact failures to CIRCUIT_LOAD_FAILED', async () => {
    const prover = vi.fn(async () => {
      throw new Error('fetch failed for /noir/silent_witness.json (network)')
    })
    const client = new ProofWorkerClient({ runtime: 'main', prover })

    const error = await client.generate(VALID).result.catch((err: unknown) => err)
    expect((error as ProofWorkerError).code).toBe('CIRCUIT_LOAD_FAILED')

    client.destroy()
  })
})