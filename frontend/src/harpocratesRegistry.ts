import { Address, BASE_FEE, Contract, Networks, TransactionBuilder, nativeToScVal, scValToNative } from '@stellar/stellar-sdk'
import { rpc } from '@stellar/stellar-sdk'
import { signTransaction } from '@stellar/freighter-api'
import { asHex32, asHexBytes, bytesToHex, scBytes, scBytes32 } from './stellarEncoding'
import type {
  ChainProofRecord,
  ChainVerifierState,
  IdentityTier,
  NormalizedRegisterProofInput,
  RegisterProofInput,
  RegisterProofResult,
  RegistryMethod,
  VerifierRotationActionInput,
  VerifierRotationInput,
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

export async function scheduleVerifierRotation(input: VerifierRotationInput): Promise<RegisterProofResult> {
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(input.publicKey)
  const contract = new Contract(input.contractId)
  const operation = contract.call(
    'schedule_verifier_rotation' satisfies RegistryMethod,
    new Address(input.publicKey).toScVal(),
    new Address(input.verifier).toScVal(),
    nativeToScVal(input.activationLedger),
    nativeToScVal(input.overlapWindow),
    nativeToScVal(input.rollbackWindow),
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
    address: input.publicKey,
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

export async function activateVerifierRotation(input: VerifierRotationActionInput): Promise<RegisterProofResult> {
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(input.publicKey)
  const contract = new Contract(input.contractId)
  const operation = contract.call('activate_verifier_rotation' satisfies RegistryMethod, new Address(input.publicKey).toScVal())

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
    address: input.publicKey,
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

export async function rollbackVerifierRotation(input: VerifierRotationActionInput): Promise<RegisterProofResult> {
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(input.publicKey)
  const contract = new Contract(input.contractId)
  const operation = contract.call('rollback_verifier_rotation' satisfies RegistryMethod, new Address(input.publicKey).toScVal())

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
    address: input.publicKey,
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

export async function getVerifierState(contractId: string, sourceAddress?: string): Promise<ChainVerifierState | null> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for verifier state inspection.')
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_verifier_state' satisfies RegistryMethod))
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
    activeVerifier: native.active_verifier ? native.active_verifier.toString() : null,
    pendingVerifier: native.pending_verifier ? native.pending_verifier.toString() : null,
    previousVerifier: native.previous_verifier ? native.previous_verifier.toString() : null,
    activationLedger: String(native.activation_ledger ?? 0),
    overlapWindow: String(native.overlap_window ?? 0),
    rollbackWindow: String(native.rollback_window ?? 0),
    rollbackWindowEnd: String(native.rollback_window_end ?? 0),
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
