import {
  Address,
  BASE_FEE,
  Contract,
  Networks,
  TransactionBuilder,
  scValToNative,
} from '@stellar/stellar-sdk'
import { rpc } from '@stellar/stellar-sdk'
import { signTransaction } from '@stellar/freighter-api'
import {
  asHex32,
  asHexBytes,
  bytesToHex,
  scBytes,
  scBytes32,
  scU32,
} from './stellarEncoding'
import type {
  ChainProofRecord,
  IdentityTier,
  NormalizedRegisterProofInput,
  ProofHistoryEntry,
  ProofHistoryResult,
  RegisterProofInput,
  RegisterProofResult,
  RegistryMethod,
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

export async function registerProofOnStellar(input: RegisterProofInput): Promise<RegisterProofResult> {
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
    throw new Error(signed.error.message)
  }

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted = await server.sendTransaction(signedTransaction)

  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    throw new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
  }

  return {
    hash: submitted.hash,
    status: submitted.status,
  }
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

export async function getProof(
  contractId: string,
  proofId: string,
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
    .addOperation(contract.call('get_proof' satisfies RegistryMethod, scBytes32(asHex32(proofId, 'proofId'))))
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

export async function getProofHistory(
  contractId: string,
  proofId: string,
  sourceAddress?: string,
  limit = 50,
  offset = 0,
): Promise<ProofHistoryResult> {
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
    .addOperation(
      contract.call(
        'get_proof_history' satisfies RegistryMethod,
        scBytes32(asHex32(proofId, 'proofId')),
        scU32(offset),
        scU32(Math.min(limit, 256)),
      ),
    )
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)
  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }
  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return { entries: [], count: 0 }
  }

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : []
  const entries: ProofHistoryEntry[] = Array.isArray(native)
    ? native.map((entry: { action: unknown; timestamp: unknown; actor: unknown; reason_code: unknown }) => ({
        action: Number(entry.action) as ProofHistoryEntry['action'],
        timestamp: entry.timestamp?.toString?.() ?? String(entry.timestamp),
        actor: entry.actor == null ? null : String(entry.actor),
        reasonCode: Number(entry.reason_code),
      }))
    : []

  const countResponse = await getProofHistoryCount(contractId, proofId, sourceAddress)
  return { entries, count: countResponse }
}

export async function getProofHistoryCount(
  contractId: string,
  proofId: string,
  sourceAddress?: string,
): Promise<number> {
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
    .addOperation(contract.call('get_proof_history_count' satisfies RegistryMethod, scBytes32(asHex32(proofId, 'proofId'))))
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)
  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }
  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return 0
  }

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : 0
  return Number(native)
}

export async function verifyProof(
  contractId: string,
  publicKey: string,
  proofId: string,
  reasonCode: number,
): Promise<RegisterProofResult> {
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(publicKey)
  const contract = new Contract(contractId)
  const operation = contract.call(
    'verify_proof' satisfies RegistryMethod,
    new Address(publicKey).toScVal(),
    scBytes32(asHex32(proofId, 'proofId')),
    scU32(reasonCode),
  )

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
    address: publicKey,
  })

  if (signed.error) {
    throw new Error(signed.error.message)
  }

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted = await server.sendTransaction(signedTransaction)

  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    throw new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
  }

  return {
    hash: submitted.hash,
    status: submitted.status,
  }
}

export async function expireProof(
  contractId: string,
  publicKey: string,
  proofId: string,
  reasonCode: number,
): Promise<RegisterProofResult> {
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(publicKey)
  const contract = new Contract(contractId)
  const operation = contract.call(
    'expire_proof' satisfies RegistryMethod,
    new Address(publicKey).toScVal(),
    scBytes32(asHex32(proofId, 'proofId')),
    scU32(reasonCode),
  )

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
    address: publicKey,
  })

  if (signed.error) {
    throw new Error(signed.error.message)
  }

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted = await server.sendTransaction(signedTransaction)

  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    throw new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
  }

  return {
    hash: submitted.hash,
    status: submitted.status,
  }
}

export async function correctProof(
  contractId: string,
  publicKey: string,
  proofId: string,
  newMetadataHash: string,
  reasonCode: number,
): Promise<RegisterProofResult> {
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(publicKey)
  const contract = new Contract(contractId)
  const operation = contract.call(
    'correct_proof' satisfies RegistryMethod,
    new Address(publicKey).toScVal(),
    scBytes32(asHex32(proofId, 'proofId')),
    scBytes32(asHex32(newMetadataHash, 'newMetadataHash')),
    scU32(reasonCode),
  )

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
    address: publicKey,
  })

  if (signed.error) {
    throw new Error(signed.error.message)
  }

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted = await server.sendTransaction(signedTransaction)

  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    throw new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
  }

  return {
    hash: submitted.hash,
    status: submitted.status,
  }
}
