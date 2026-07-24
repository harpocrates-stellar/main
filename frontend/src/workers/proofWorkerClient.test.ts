import { describe, it, expect } from 'vitest'
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