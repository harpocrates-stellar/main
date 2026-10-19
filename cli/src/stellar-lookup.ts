import { BASE_FEE, Contract, Networks, StrKey, TransactionBuilder, rpc, scValToNative, nativeToScVal } from '@stellar/stellar-sdk'
import { asHex32, bytesToHex, hexToBytes } from './hashing.js'

/**
 * Chain-level proof record returned by the Harpocrates Registry contract.
 */
export type ChainProofRecord = {
  videoHash: string
  metadataHash: string
  tier: number
  status: number
  createdAt: string
  expiresAt?: string
  source: string | null
  issuer: string | null
}

export type StellarLookupOptions = {
  /** Stellar RPC URL (defaults to testnet). */
  rpcUrl?: string
  /** Network passphrase (defaults to testnet). */
  networkPassphrase?: string
  /** Source account for simulation. If omitted the simulation will likely fail. */
  sourceAddress?: string
  /** Timeout in milliseconds for each RTC call (defaults to 15000). */
  timeoutMs?: number
}

/**
 * Error thrown when an RPC call does not complete within the configured timeout.
 */
export class LookupTimeoutError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'LookupTimeoutError'
  }
}

const DEFAULT_RPC_URL = 'https://soroban-testnet.stellar.org'
const DEFAULT_TIMEOUT_MS = 15000

/**
 * Race a promise against a timer, rejecting with a typed LookupTimeoutError.
 */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new LookupTimeoutError(`${label} timed out after ${timeoutMs}ms`))
    }, timeoutMs)
    promise.then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      (err) => {
        clearTimeout(timer)
        reject(err)
      },
    )
  })
}

/**
 * Look up a proof record on-chain by its video hash.
 *
 * Uses a read-only simulation so no wallet or signing is required, but a
 * funded source address is needed to cover the simulated fee.
 */
export async function lookupByVideoHash(
  contractId: string,
  videoHash: string,
  options: StellarLookupOptions = {},
): Promise<ChainProofRecord | null> {
  const rpcUrl = options.rpcUrl ?? DEFAULT_RPC_URL
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source = options.sourceAddress
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await withTimeout(server.getAccount(source), timeoutMs, 'getAccount')
  const contract = new Contract(contractId)

  // Encode the 32-byte video hash as scBytes32 expected by Soroban.
  const videoHashScVal = nativeToScVal(hexToBytes(asHex32(videoHash, 'videoHash')))

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_by_video', videoHashScVal))
    .setTimeout(30)
    .build()

  const simulation = await withTimeout(server.simulateTransaction(transaction), timeoutMs, 'simulateTransaction')

  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }

  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return null
  }

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : null
  if (!native) return null

  return {
    videoHash: bytesToHex(native.video_hash),
    metadataHash: bytesToHex(native.metadata_hash),
    tier: Number(native.tier),
    status: Number(native.status),
    createdAt: native.created_at?.toString?.() ?? String(native.created_at),
    expiresAt: native.expires_at?.toString?.() ?? undefined,
    source: native.source ?? null,
    issuer: native.issuer ?? null,
  }
}

/**
 * Verify that a transaction on Stellar matches the expected contract ID and
 * was successfully confirmed.
 */
export async function verifyTransaction(
  txHash: string,
  expectedContractId?: string,
  options: StellarLookupOptions = {},
): Promise<TransactionVerification> {
  const rpcUrl = options.rpcUrl ?? DEFAULT_RPC_URL
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const server = new rpc.Server(rpcUrl)
  const response = await withTimeout(server.getTransaction(txHash), timeoutMs, 'getTransaction')

  switch (response.status) {
    case rpc.Api.GetTransactionStatus.NOT_FOUND:
      return { status: 'missing', txHash }

    case rpc.Api.GetTransactionStatus.FAILED:
      return {
        status: 'failed',
        txHash,
        ledger: response.ledger,
        createdAt: response.createdAt,
      }

    case rpc.Api.GetTransactionStatus.SUCCESS:
      return {
        status: 'confirmed',
        txHash,
        ledger: response.ledger,
        createdAt: response.createdAt,
        contractMatch: expectedContractId
          ? checkContractMatch(response.envelopeXdr.toXDR(), expectedContractId)
          : undefined,
      }

    default:
      return { status: 'missing', txHash }
  }
}

export type TransactionVerification = {
  status: 'confirmed' | 'pending' | 'failed' | 'missing'
  txHash: string
  ledger?: number
  createdAt?: number
  contractMatch?: boolean
}

/**
 * Check whether an envelope references the decoded contract address bytes.
 * This is a conservative preflight, not a substitute for matching chain data.
 */
export function checkContractMatch(envelopeBytes: Uint8Array, contractId: string): boolean {
  if (!StrKey.isValidContract(contractId)) return false
  const hex = bytesToHex(StrKey.decodeContract(contractId))
  const bytesHex = Array.from(envelopeBytes, (b) => Number(b).toString(16).padStart(2, '0')).join('')
  return bytesHex.includes(hex)
}
