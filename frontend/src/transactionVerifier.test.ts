import { describe, it, expect, vi } from 'vitest'
import { rpc, xdr } from '@stellar/stellar-sdk'
import { verifyTransactionStatus, pollTransactionStatus } from './transactionVerifier'

function mockEnvelopeXdr(ops: unknown[] = []) {
  return {
    toXDR: () => new Uint8Array([1, 2, 3, 4]),
    switch: () => xdr.EnvelopeType.envelopeTypeTx(),
    tx: () => ({
      operations: () => ops,
    }),
  }
}

function createMockServer(responses: Record<string, unknown>) {
  return {
    getTransaction: vi.fn().mockImplementation((hash: string) => {
      const response = responses[hash]
      if (!response) {
        return Promise.resolve({
          status: rpc.Api.GetTransactionStatus.NOT_FOUND,
          txHash: hash,
        })
      }
      return Promise.resolve(response)
    }),
  } as unknown as rpc.Server
}

describe('verifyTransactionStatus', () => {
  it('returns confirmed for a successful transaction', async () => {
    const server = createMockServer({
      abc123: {
        status: rpc.Api.GetTransactionStatus.SUCCESS,
        txHash: 'abc123',
        ledger: 100,
        createdAt: 1700000000,
        envelopeXdr: mockEnvelopeXdr(),
      },
    })

    const result = await verifyTransactionStatus('abc123', undefined, server)
    expect(result.status).toBe('confirmed')
    expect(result.txHash).toBe('abc123')
    expect(result.ledger).toBe(100)
    expect(result.createdAt).toBe(1700000000)
  })

  it('returns failed for a failed transaction', async () => {
    const server = createMockServer({
      def456: {
        status: rpc.Api.GetTransactionStatus.FAILED,
        txHash: 'def456',
        ledger: 200,
        createdAt: 1700001000,
        envelopeXdr: mockEnvelopeXdr(),
      },
    })

    const result = await verifyTransactionStatus('def456', undefined, server)
    expect(result.status).toBe('failed')
    expect(result.txHash).toBe('def456')
    expect(result.ledger).toBe(200)
  })

  it('returns missing for a not-found transaction', async () => {
    const server = createMockServer({})

    const result = await verifyTransactionStatus('ghi789', undefined, server)
    expect(result.status).toBe('missing')
    expect(result.txHash).toBe('ghi789')
  })

  it('returns operationCount for successful transactions', async () => {
    const server = createMockServer({
      'op-count': {
        status: rpc.Api.GetTransactionStatus.SUCCESS,
        txHash: 'op-count',
        ledger: 400,
        createdAt: 1700003000,
        envelopeXdr: mockEnvelopeXdr([{}, {}, {}]),
      },
    })

    const result = await verifyTransactionStatus('op-count', undefined, server)
    expect(result.operationCount).toBe(3)
  })

  it('returns undefined contractMatch when no expectedContractId', async () => {
    const server = createMockServer({
      nocontract: {
        status: rpc.Api.GetTransactionStatus.SUCCESS,
        txHash: 'nocontract',
        ledger: 500,
        createdAt: 1700004000,
        envelopeXdr: mockEnvelopeXdr(),
      },
    })

    const result = await verifyTransactionStatus('nocontract', undefined, server)
    expect(result.contractMatch).toBeUndefined()
  })
})

describe('pollTransactionStatus', () => {
  it('returns confirmed immediately if first poll succeeds', async () => {
    const server = createMockServer({
      'poll-ok': {
        status: rpc.Api.GetTransactionStatus.SUCCESS,
        txHash: 'poll-ok',
        ledger: 500,
        createdAt: 1700004000,
        envelopeXdr: mockEnvelopeXdr(),
      },
    })

    const result = await pollTransactionStatus('poll-ok', undefined, {
      maxAttempts: 3,
      intervalMs: 10,
      server,
    })
    expect(result.status).toBe('confirmed')
  })

  it('retries on NOT_FOUND then returns confirmed', async () => {
    const getTransaction = vi.fn()
      .mockResolvedValueOnce({
        status: rpc.Api.GetTransactionStatus.NOT_FOUND,
        txHash: 'poll-retry',
      })
      .mockResolvedValueOnce({
        status: rpc.Api.GetTransactionStatus.SUCCESS,
        txHash: 'poll-retry',
        ledger: 600,
        createdAt: 1700005000,
        envelopeXdr: mockEnvelopeXdr(),
      })

    const server = { getTransaction } as unknown as rpc.Server

    const result = await pollTransactionStatus('poll-retry', undefined, {
      maxAttempts: 3,
      intervalMs: 10,
      server,
    })
    expect(result.status).toBe('confirmed')
    expect(getTransaction).toHaveBeenCalledTimes(2)
  })

  it('returns pending after exhausting all attempts', async () => {
    const getTransaction = vi.fn().mockResolvedValue({
      status: rpc.Api.GetTransactionStatus.NOT_FOUND,
      txHash: 'poll-timeout',
    })

    const server = { getTransaction } as unknown as rpc.Server

    const result = await pollTransactionStatus('poll-timeout', undefined, {
      maxAttempts: 2,
      intervalMs: 10,
      server,
    })
    expect(result.status).toBe('pending')
    expect(getTransaction).toHaveBeenCalledTimes(2)
  })

  it('returns failed immediately on failure', async () => {
    const getTransaction = vi.fn().mockResolvedValue({
      status: rpc.Api.GetTransactionStatus.FAILED,
      txHash: 'poll-fail',
      ledger: 700,
      createdAt: 1700006000,
      envelopeXdr: mockEnvelopeXdr(),
    })

    const server = { getTransaction } as unknown as rpc.Server

    const result = await pollTransactionStatus('poll-fail', undefined, {
      maxAttempts: 5,
      intervalMs: 10,
      server,
    })
    expect(result.status).toBe('failed')
    expect(getTransaction).toHaveBeenCalledTimes(1)
  })

  it('stops polling after maxAttempts', async () => {
    const getTransaction = vi.fn().mockResolvedValue({
      status: rpc.Api.GetTransactionStatus.NOT_FOUND,
      txHash: 'poll-max',
    })

    const server = { getTransaction } as unknown as rpc.Server

    const result = await pollTransactionStatus('poll-max', undefined, {
      maxAttempts: 4,
      intervalMs: 10,
      server,
    })
    expect(result.status).toBe('pending')
    expect(getTransaction).toHaveBeenCalledTimes(4)
  })
})
