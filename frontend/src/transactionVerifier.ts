import { rpc, xdr } from '@stellar/stellar-sdk'

const RPC_URL = import.meta.env.VITE_STELLAR_RPC_URL ?? 'https://soroban-testnet.stellar.org'

export type TransactionStatus = 'confirmed' | 'pending' | 'failed' | 'missing'

export type TransactionVerification = {
  status: TransactionStatus
  txHash: string
  ledger?: number
  createdAt?: number
  contractMatch?: boolean
  operationCount?: number
}

export function createServer(url?: string): rpc.Server {
  return new rpc.Server(url ?? RPC_URL)
}

export async function verifyTransactionStatus(
  txHash: string,
  expectedContractId?: string,
  server?: rpc.Server,
): Promise<TransactionVerification> {
  const srv = server ?? createServer()
  const response = await srv.getTransaction(txHash)

  switch (response.status) {
    case rpc.Api.GetTransactionStatus.NOT_FOUND:
      return { status: 'missing', txHash }

    case rpc.Api.GetTransactionStatus.FAILED:
      return buildResult(response, txHash, 'failed', expectedContractId)

    case rpc.Api.GetTransactionStatus.SUCCESS:
      return buildResult(response, txHash, 'confirmed', expectedContractId)

    default:
      return { status: 'missing', txHash }
  }
}

function buildResult(
  response: rpc.Api.GetFailedTransactionResponse | rpc.Api.GetSuccessfulTransactionResponse,
  txHash: string,
  status: 'failed' | 'confirmed',
  expectedContractId?: string,
): TransactionVerification {
  const envelopeXdr = response.envelopeXdr.toXDR()
  const contractMatch = expectedContractId
    ? envelopeXdrContainsContractId(envelopeXdr, expectedContractId)
    : undefined

  const envelope = tryParseEnvelope(response.envelopeXdr)

  return {
    status,
    txHash,
    ledger: response.ledger,
    createdAt: response.createdAt,
    contractMatch,
    operationCount: envelope?.operationCount,
  }
}

function envelopeXdrContainsContractId(xdrBytes: Uint8Array, contractId: string): boolean {
  const hex = contractId.toLowerCase().replace(/^0x/, '')
  const bytesHex = Array.from(xdrBytes, (b) => Number(b).toString(16).padStart(2, '0')).join('')
  return bytesHex.includes(hex)
}

function tryParseEnvelope(envelope: xdr.TransactionEnvelope): { operationCount: number } | null {
  try {
    if (envelope.switch() !== xdr.EnvelopeType.envelopeTypeTx()) return null
    const tx = (envelope as unknown as { tx(): xdr.Transaction }).tx()
    return { operationCount: tx.operations().length }
  } catch {
    return null
  }
}

export async function pollTransactionStatus(
  txHash: string,
  expectedContractId?: string,
  options?: { maxAttempts?: number; intervalMs?: number; server?: rpc.Server },
): Promise<TransactionVerification> {
  const maxAttempts = options?.maxAttempts ?? 10
  const intervalMs = options?.intervalMs ?? 3000
  const server = options?.server

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const result = await verifyTransactionStatus(txHash, expectedContractId, server)

    if (result.status === 'confirmed' || result.status === 'failed') {
      return result
    }

    if (attempt < maxAttempts - 1) {
      await new Promise((resolve) => setTimeout(resolve, intervalMs))
    }
  }

  return { status: 'pending', txHash }
}
