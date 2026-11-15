import { describe, expect, it, vi } from 'vitest'
import {
  PROOF_WORKER_PROTOCOL_VERSION,
  RELOAD_REQUIRED_MESSAGE,
  checkWorkerProtocolCompatibility,
  guardTransferableBuffersForProtocol,
} from '../proofWorkerMemory'
import { ProofWorkerManager } from './proof-worker-manager'
import { ProofWorkerClient, ProofWorkerError } from './proofWorkerClient'
import type { WorkerResponse } from './proofWorker.types'

class MockProtocolWorker {
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null = null
  onerror: ((event: ErrorEvent) => void) | null = null
  onmessageerror: ((event: MessageEvent) => void) | null = null
  terminated = false
  posted: Array<{ message: unknown; transfer?: Transferable[] }> = []

  postMessage(message: unknown, transfer?: Transferable[]) {
    this.posted.push({ message, transfer })
  }

  terminate() {
    this.terminated = true
  }
}

describe('worker and main-thread protocol version compatibility', () => {
  it('accepts exact canonical version and rejects mismatched or coerced versions without echoing secrets', () => {
    const ok = checkWorkerProtocolCompatibility(PROOF_WORKER_PROTOCOL_VERSION)
    expect(ok).toEqual({
      compatible: true,
      expectedVersion: PROOF_WORKER_PROTOCOL_VERSION,
      actualVersion: PROOF_WORKER_PROTOCOL_VERSION,
      reloadRequired: false,
    })

    const mismatch = checkWorkerProtocolCompatibility('harpocrates.proof-worker.v0')
    expect(mismatch).toEqual({
      compatible: false,
      code: 'PROTOCOL_VERSION_MISMATCH',
      expectedVersion: PROOF_WORKER_PROTOCOL_VERSION,
      actualVersion: 'harpocrates.proof-worker.v0',
      reloadRequired: true,
      message: RELOAD_REQUIRED_MESSAGE,
    })

    // Coerced numeric or secret-bearing malformed strings must fail closed and redact actualVersion
    const secretLike = 'credentialSecret=0xdeadbeefcafebabe'
    const coerced = checkWorkerProtocolCompatibility(1)
    const malformed = checkWorkerProtocolCompatibility(secretLike)
    expect(coerced.compatible).toBe(false)
    if (!coerced.compatible) {
      expect(coerced.actualVersion).toBeNull()
      expect(coerced.reloadRequired).toBe(true)
    }
    expect(malformed.compatible).toBe(false)
    if (!malformed.compatible) {
      expect(malformed.actualVersion).toBeNull()
      expect(JSON.stringify(malformed)).not.toContain('deadbeef')
    }
  })

  it('fails before accepting or detaching transferable buffers in ProofWorkerManager', async () => {
    const manager = new ProofWorkerManager()
    await manager.init()

    const mockWorker = new MockProtocolWorker()
    ;(manager as unknown as { worker: Worker }).worker = mockWorker as unknown as Worker

    // Negotiate an older deployed worker asset version
    const handshake = manager.negotiateProtocolVersion('harpocrates.proof-worker.v0')
    expect(handshake.compatible).toBe(false)

    const secretBuffer = new Uint8Array([9, 8, 7, 6]).buffer
    const response = manager.dispatchTransferableOperation(
      { type: 'verify', id: 'req-1', payload: { evidence: 'e', proof: 'p', contract: 'c' } },
      [secretBuffer],
    )

    expect(response.type).toBe('error')
    expect(response.reloadRequired).toBe(true)
    expect(response.error?.code).toBe('PROTOCOL_VERSION_MISMATCH')
    expect(response.error?.message).toBe(RELOAD_REQUIRED_MESSAGE)
    // Buffer was NOT transferred or detached and postMessage was NEVER invoked
    expect(secretBuffer.byteLength).toBe(4)
    expect(new Uint8Array(secretBuffer)).toEqual(new Uint8Array([9, 8, 7, 6]))
    expect(mockWorker.posted).toHaveLength(0)

    manager.destroy()
  })

  it('rejects incompatible worker envelopes without fallback parsing of untrusted fields', async () => {
    const manager = new ProofWorkerManager()
    await manager.init()

    let getterTriggered = false
    const hostileEnvelope = {
      type: 'success',
      protocolVersion: 'harpocrates.proof-worker.v999',
      id: 'msg-hostile',
      get data() {
        getterTriggered = true
        return { valid: true }
      },
    }

    const result = manager.receiveWorkerEnvelope(hostileEnvelope)
    expect(getterTriggered).toBe(false)
    expect(result.type).toBe('error')
    expect(result.reloadRequired).toBe(true)
    expect(result.error?.code).toBe('PROTOCOL_VERSION_MISMATCH')

    manager.destroy()
  })

  it('guards transferable buffers directly and preserves happy-path transfer list on match', () => {
    const buf = new ArrayBuffer(16)
    const blocked = guardTransferableBuffersForProtocol('wrong.v2', [buf])
    expect(blocked.ok).toBe(false)
    if (!blocked.ok) {
      expect(blocked.reloadRequired).toBe(true)
      expect(blocked.code).toBe('PROTOCOL_VERSION_MISMATCH')
    }
    expect(buf.byteLength).toBe(16)

    const allowed = guardTransferableBuffersForProtocol(PROOF_WORKER_PROTOCOL_VERSION, [buf])
    expect(allowed.ok).toBe(true)
    if (allowed.ok) {
      expect(allowed.transferList).toEqual([buf])
      expect(allowed.reloadRequired).toBe(false)
    }
  })

  it('fails ProofWorkerClient before secret transfer or fallback proving when READY reports a mismatch', async () => {
    const mockWorker = new MockProtocolWorker()
    const fallbackProver = vi.fn()
    const client = new ProofWorkerClient({
      workerFactory: () => mockWorker as unknown as Worker,
      prover: fallbackProver,
    })

    // Worker announces stale cached bundle version on READY
    mockWorker.onmessage?.(
      new MessageEvent('message', {
        data: { type: 'READY', protocolVersion: 'harpocrates.proof-worker.v0' },
      }),
    )
    expect(mockWorker.terminated).toBe(true)

    const { requestId, result } = client.generate({
      videoHash: 'a'.repeat(64),
      credentialSecret: '12345',
      nullifierSecret: '67890',
    })

    expect(requestId).toBe('')
    await expect(result).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(ProofWorkerError)
      const pwErr = err as ProofWorkerError
      expect(pwErr.code).toBe('PROTOCOL_VERSION_MISMATCH')
      expect(pwErr.reloadRequired).toBe(true)
      expect(pwErr.message).toBe(RELOAD_REQUIRED_MESSAGE)
      expect(pwErr.message).not.toContain('12345')
      return true
    })

    // Zero transfers and zero unsafe fallback proving on main thread
    expect(mockWorker.posted).toHaveLength(0)
    expect(fallbackProver).not.toHaveBeenCalled()
    client.destroy()
  })

  it('rejects in-flight ProofWorkerClient requests if a worker response carries a mismatched version', async () => {
    const mockWorker = new MockProtocolWorker()
    const client = new ProofWorkerClient({
      workerFactory: () => mockWorker as unknown as Worker,
    })

    mockWorker.onmessage?.(
      new MessageEvent('message', {
        data: { type: 'READY', protocolVersion: PROOF_WORKER_PROTOCOL_VERSION },
      }),
    )

    const { requestId, result } = client.generate({
      videoHash: 'b'.repeat(64),
      credentialSecret: '11111',
      nullifierSecret: '22222',
    })
    expect(requestId).toBeTruthy()
    expect(mockWorker.posted).toHaveLength(1)

    mockWorker.onmessage?.(
      new MessageEvent('message', {
        data: {
          type: 'RESULT',
          protocolVersion: 'harpocrates.proof-worker.v2',
          requestId,
          proof: {
            credentialRoot: '1',
            nullifier: '2',
            proof: '00',
            publicInputs: '[]',
            proofBytes: 1,
            publicInputBytes: 2,
          },
        },
      }),
    )

    await expect(result).rejects.toMatchObject({
      code: 'PROTOCOL_VERSION_MISMATCH',
      reloadRequired: true,
      message: RELOAD_REQUIRED_MESSAGE,
    })
    expect(mockWorker.terminated).toBe(true)
    client.destroy()
  })
})
