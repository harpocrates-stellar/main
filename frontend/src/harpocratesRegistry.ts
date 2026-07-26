import { Address, BASE_FEE, Contract, Networks, TransactionBuilder, scValToNative } from '@stellar/stellar-sdk'
import { rpc } from '@stellar/stellar-sdk'
import { signTransaction } from '@stellar/freighter-api'
import { asHex32, asHexBytes, bytesToHex, scBytes, scBytes32 } from './stellarEncoding'
import type {
  ChainProofRecord,
  IdentityTier,
  NormalizedRegisterProofInput,
  RegisterProofInput,
  RegisterProofResult,
  RegistryMethod,
  TxState,
} from './stellarTypes'

const RPC_URL = import.meta.env.VITE_STELLAR_RPC_URL ?? 'https://soroban-testnet.stellar.org'

/**
 * The network passphrase the deployed contract was built against.
 * Exported so network-guard code can compare it with the wallet's
 * reported network without duplicating the constant.
 */
export const CONTRACT_NETWORK_PASSPHRASE: string = Networks.TESTNET

const NETWORK_PASSPHRASE = CONTRACT_NETWORK_PASSPHRASE
const READONLY_SOURCE = import.meta.env.VITE_STELLAR_READONLY_SOURCE ?? ''
const POLL_INTERVAL_MS = 1000
const POLL_TIMEOUT_MS = 30000

type SendTransactionResponse = Awaited<ReturnType<rpc.Server['sendTransaction']>>

function initialTxState(status: string): TxState {
  if (status === 'PENDING' || status === 'DUPLICATE') return 'awaiting_confirmation'
  return 'submitting'
}

function resolveTxState(
  pollResult: rpc.Api.GetSuccessfulTransactionResponse | null,
  timedOut: boolean,
): TxState {
  if (timedOut) return 'timeout'
  if (pollResult) return 'confirmed'
  return 'failed'
}

function resolveStatus(
  isRejected: boolean,
  pollResult: rpc.Api.GetSuccessfulTransactionResponse | null,
  timedOut: boolean,
): string {
  if (isRejected) return 'REJECTED_BY_WALLET'
  if (timedOut) return 'TIMEOUT'
  if (pollResult) return 'SUCCESS'
  return 'FAILED'
}

export async function registerProofOnStellar(
  input: RegisterProofInput,
  waitForConfirmation = true,
): Promise<RegisterProofResult> {
  const normalized = normalizeRegisterProofInput(input)
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(normalized.publicKey)
  const contract = new Contract(normalized.contractId)
  const operation = contract.call(methodForTier(normalized.tier), ...argsForTier(normalized))

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(operation)
    .setTimeout(90)
    .build()

  const prepared = await server.prepareTransaction(transaction)
  const signed = await signTransaction(prepared.toXDR(), {
    networkPassphrase: NETWORK_PASSPHRASE,
    address: normalized.publicKey,
  })

  if (signed.error) {
    return {
      hash: '',
      status: 'REJECTED_BY_WALLET',
      txState: 'failed',
    }
  }

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted: SendTransactionResponse = await server.sendTransaction(signedTransaction)

  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    return {
      hash: submitted.hash ?? '',
      status: 'REJECTED_BY_RPC',
      txState: 'failed',
    }
  }

  if (!waitForConfirmation) {
    return {
      hash: submitted.hash,
      status: submitted.status,
      txState: initialTxState(submitted.status),
    }
  }

  const pollResult = await pollForConfirmation(server, submitted.hash)
  const timedOut = pollResult === null

  return {
    hash: submitted.hash,
    status: resolveStatus(false, pollResult, timedOut),
    txState: resolveTxState(pollResult, timedOut),
  }
}

export async function pollForConfirmation(
  server: rpc.Server,
  hash: string,
  timeoutMs = POLL_TIMEOUT_MS,
): Promise<rpc.Api.GetSuccessfulTransactionResponse | null> {
  const start = Date.now()

  while (Date.now() - start < timeoutMs) {
    const response = await server.getTransaction(hash)
    if (response.status === 'SUCCESS') {
      return response as rpc.Api.GetSuccessfulTransactionResponse
    }
    if (response.status === 'FAILED') {
      return null
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS))
  }

  return null
}

export async function getProofByVideoHash(
  contractId: string,
  videoHash: string,
  sourceAddress?: string,
): Promise<ChainProofRecord | null> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_by_video' satisfies RegistryMethod, scBytes32(asHex32(videoHash, 'videoHash'))))
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)
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
    source: native.source ?? null,
    issuer: native.issuer ?? null,
  }
}

function normalizeRegisterProofInput(input: RegisterProofInput): NormalizedRegisterProofInput {
  return {
    ...input,
    videoHash: asHex32(input.videoHash, 'videoHash'),
    metadataHash: asHex32(input.metadataHash, 'metadataHash'),
    proofId: asHex32(input.proofId, 'proofId'),
    silentWitness: input.silentWitness
      ? {
          publicInputs: asHexBytes(input.silentWitness.publicInputs, 'silentWitness.publicInputs'),
          proof: asHexBytes(input.silentWitness.proof, 'silentWitness.proof'),
        }
      : undefined,
  }
}

function methodForTier(tier: IdentityTier): RegistryMethod {
  if (tier === 'silent') return 'register_anonymous_verified'
  if (tier === 'seal') return 'register_seal'
  return 'register_source'
}

function argsForTier(input: NormalizedRegisterProofInput) {
  const videoHash = scBytes32(input.videoHash)
  const metadataHash = scBytes32(input.metadataHash)
  const proofId = scBytes32(input.proofId)
  const address = new Address(input.publicKey).toScVal()

  if (input.tier === 'silent') {
    if (!input.silentWitness) {
      throw new Error('Silent Witness registration requires Noir proof artifacts.')
    }

    return [
      videoHash,
      metadataHash,
      proofId,
      scBytes(input.silentWitness.publicInputs),
      scBytes(input.silentWitness.proof),
    ]
  }

  return [address, videoHash, metadataHash, proofId]
}
