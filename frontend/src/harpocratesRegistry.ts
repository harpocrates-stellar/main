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
  ChainDisputeRecord,
  DelegationRecord,
  ChainProofRecord,
  Hex32,
  IdentityTier,
  IssuerRecord,
  NormalizedRegisterProofInput,
  ProofHistoryEntry,
  ProofHistoryResult,
  RegisterProofInput,
  RegisterProofResult,
  RegistryMethod,
  TxState,
} from './stellarTypes'

const RPC_URL = import.meta.env.VITE_STELLAR_RPC_URL ?? 'https://soroban-testnet.stellar.org'

/**
 * The network passphrase the deployed contract was built against.
 * Exported so network-guard code can compare it with the wallet's deported
 * network without duplicating the constant.
 */
export const CONTRACT_NETWORK_PASSPHRASE: string = Networks.TESTNET

const NETWORK_PASSPHRASE = CONTRACT_NETWORK_PASSPHRASE
const READONLY_SOURCE = import.meta.env.VITE_STELLAR_READONLY_SOURCE ?? ''
const POLL_INTERVAL_MS = 1000
const POLL_TIMEOUT_MS = 30000

export function requireReadSource(source?: string): string {
  const resolved = source || READONLY_SOURCE
  if (!resolved) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }
  return resolved
}

type SendTransactionResponse = Awaited<ReturnType<rpc.Server['sendTransaction']>>

/**
 * Read a `u64` field out of a decoded contract value as Unix seconds.
 *
 * Soroban decodes `u64` to `bigint`, which JSON-style consumers cannot carry,
 * so the record types hold plain numbers. An absent or non-finite field stays
 * `null` rather than becoming `0`, because `0` means "never expires" on chain
 * and must not be produced by a decoding failure.
 */
function toUnixSeconds(value: unknown): number | null {
  if (value === null || value === undefined) return null
  const seconds = Number(value)
  return Number.isFinite(seconds) ? seconds : null
}

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

export function normalizeRegisterProofInput(input: RegisterProofInput): NormalizedRegisterProofInput {
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

export function methodForTier(tier: IdentityTier, isDelegated = false): RegistryMethod {
  if (tier === 'silent') return 'register_anonymous_verified'
  if (tier === 'seal') {
    return isDelegated ? 'register_seal_delegated' : 'register_seal'
  }
  return isDelegated ? 'register_source_delegated' : 'register_source'
}

export function argsForTier(input: NormalizedRegisterProofInput) {
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

  if (input.grantor) {
    const grantorAddress = new Address(input.grantor).toScVal()
    // register_source_delegated(delegate, source, video_hash, metadata_hash, proof_id)
    // register_seal_delegated(delegate, issuer, video_hash, metadata_hash, proof_id)
    return [address, grantorAddress, videoHash, metadataHash, proofId]
  }

  return [address, videoHash, metadataHash, proofId]
}

export function buildRegisterProofOperation(
  contractId: string,
  input: RegisterProofInput,
) {
  const normalized = normalizeRegisterProofInput(input)
  const isDelegated = Boolean(normalized.grantor && normalized.tier !== 'silent')
  const contract = new Contract(contractId)
  return contract.call(
    methodForTier(normalized.tier, isDelegated),
    ...argsForTier(normalized),
  )
}

export async function registerProofOnStellar(
  input: RegisterProofInput,
  waitForConfirmation = true,
): Promise<RegisterProofResult> {
  const normalized = normalizeRegisterProofInput(input)
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(normalized.publicKey)
  const operation = buildRegisterProofOperation(input.contractId, input)

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
  assertReleaseCompatibility()
  const source = requireReadSource(sourceAddress)

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
    expiresAt: toUnixSeconds(native.expires_at),
    source: native.source ?? null,
    issuer: native.issuer ?? null,
  }
}

export async function getBatchProofStatuses(
  contractId: string,
  proofIds: string[],
  sourceAddress?: string,
): Promise<number[] | null> {
  const source = requireReadSource(sourceAddress)

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  
  const scProofIds = proofIds.map(id => scBytes32(asHex32(id, 'proofId')))
  
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_proof_statuses', ...scProofIds))
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
  if (!native || !Array.isArray(native)) return null

  // returns array of status enum values mapped to numbers
  return native.map((val: unknown) => Number(val))
}

export async function getProof(
  contractId: string,
  proofId: string,
  sourceAddress?: string,
): Promise<ChainProofRecord | null> {
  const source = requireReadSource(sourceAddress)

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
    expiresAt: toUnixSeconds(native.expires_at),
    source: native.source ?? null,
    issuer: native.issuer ?? null,
  }
}

/**
 * Read an issuer's registry record.
 *
 * The two "no record" cases are deliberately kept apart:
 * - resolves to `null` when the registry holds no record for the address
 *   (`get_issuer` returns `None`) — a trust outcome, not a failure;
 * - throws when the read itself did not complete — a dependency failure.
 *
 * Callers must pre-validate the address with
 * `isLookupEligibleIssuer`; `Address` construction rejects anything that is
 * not a well-formed StrKey, and that rejection is not a registry answer.
 */
export async function getIssuerRecord(
  contractId: string,
  issuer: string,
  sourceAddress?: string,
): Promise<IssuerRecord | null> {
  const source = requireReadSource(sourceAddress)

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_issuer' satisfies RegistryMethod, new Address(issuer).toScVal()))
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
    address: native.address ?? issuer,
    tier: Number(native.tier),
    active: Boolean(native.active),
    registeredAt: toUnixSeconds(native.registered_at),
  }
}

/**
 * Read a dispute record from the registry by dispute ID.
 *
 * Simulation-only read following the pattern of `getProofHistoryCount`; no
 * signing is required. Resolves to `null` when the contract returns an
 * empty `Option` (no such dispute).
 */
export async function getDispute(
  contractId: string,
  disputeId: string,
  sourceAddress?: string,
): Promise<ChainDisputeRecord | null> {
  const source = requireReadSource(sourceAddress)

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_dispute' satisfies RegistryMethod, scBytes32(asHex32(disputeId, 'disputeId'))))
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
  if (native === null || native === undefined) return null

  return {
    disputeId: native.dispute_id?.toString?.() ?? String(native.dispute_id),
    proofId: native.proof_id?.toString?.() ?? String(native.proof_id),
    opener: native.opener ?? null,
    reason: native.reason ?? '',
    status: Number(native.status),
    createdAt: native.created_at?.toString?.() ?? String(native.created_at),
    resolvedAt: toUnixSeconds(native.resolved_at),
  }
}

/**
 * Read the number of open disputes for a proof ID.
 *
 * Simulation-only read following the pattern of `getProofHistoryCount`; no
 * signing is required. Resolves to `null` when the contract returns an
 * empty `Option`.
 */
export async function getOpenDisputeCount(
  contractId: string,
  proofId: string,
  sourceAddress?: string,
): Promise<number | null> {
  const source = requireReadSource(sourceAddress)

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_open_dispute_count' satisfies RegistryMethod, scBytes32(asHex32(proofId, 'proofId'))))
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
  if (native === null || native === undefined) return null

  return Number(native)
}

// ---------------------------------------------------------------------------
// Dispute Workflow (#contracts/DISPUTE.md)
// ---------------------------------------------------------------------------

export enum DisputeReason {
  ContentError = 1,
  MetadataError = 2,
  TierMismatch = 3,
  CredentialLapsed = 4,
  PrivacyViolation = 5,
  Other = 6,
}

export const DISPUTE_REASON_LABELS: Record<DisputeReason, string> = {
  [DisputeReason.ContentError]: 'Content error (tampered or invalid video/content)',
  [DisputeReason.MetadataError]: 'Metadata error (incorrect claims/attributes)',
  [DisputeReason.TierMismatch]: 'Tier mismatch (wrong identity tier)',
  [DisputeReason.CredentialLapsed]: 'Credential lapsed (expired or stale root)',
  [DisputeReason.PrivacyViolation]: 'Privacy violation (unauthorized disclosure)',
  [DisputeReason.Other]: 'Other',
}

export enum DisputeStatus {
  Open = 1,
  Responded = 2,
  Resolved = 3,
  Dismissed = 4,
  Superseded = 5,
}

export const DISPUTE_STATUS_LABELS: Record<DisputeStatus, string> = {
  [DisputeStatus.Open]: 'Open',
  [DisputeStatus.Responded]: 'Responded',
  [DisputeStatus.Resolved]: 'Resolved',
  [DisputeStatus.Dismissed]: 'Dismissed',
  [DisputeStatus.Superseded]: 'Superseded',
}

export type ChainDisputeRecord = {
  disputeId: string
  proofId: string
  reason: DisputeReason
  reporterHash: string
  commitmentHash: string
  status: DisputeStatus
  openedAt: number
  respondDeadline: number
  resolveDeadline: number
  responseCommitment: string | null
  resolvedAt: number
  supersededBy: string | null
}

export type OpenDisputeInput = {
  contractId: string
  publicKey: string
  proofId: string
  reason: DisputeReason | number
  evidenceHash: string
  disputeId?: string
  reporterHash?: string
}

export type RespondDisputeInput = {
  contractId: string
  publicKey: string
  disputeId: string
  responseCommitment: string
}

export function isValidDisputeReason(reason: number): reason is DisputeReason {
  return Number.isInteger(reason) && reason >= 1 && reason <= 6
}

export function isValidEvidenceHash(hash: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(hash.trim())
}

export function validateDisputeReason(reason: number): DisputeReason {
  if (!isValidDisputeReason(reason)) {
    throw new Error('Dispute reason must be an integer between 1 and 6.')
  }
  return reason
}

export function validateEvidenceHash(hash: string, label = 'evidenceHash'): Hex32 {
  const trimmed = hash.trim()
  if (!isValidEvidenceHash(trimmed)) {
    throw new Error(`${label} must be a 64-character (32-byte) hex string.`)
  }
  return asHex32(trimmed, label)
}

function generateRandomHex32(): string {
  const bytes = new Uint8Array(32)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes)
  } else {
    for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256)
  }
  return bytesToHex(bytes)
}

/**
 * Open a dispute challenging a registered proof on the Stellar registry.
 * Validates reason codes and evidence hash format client-side.
 * Uses the TransactionStateMachine to track progress if provided.
 */
export async function openDispute(
  input: OpenDisputeInput,
  machine?: TransactionStateMachine,
): Promise<RegisterProofResult> {
  const reason = validateDisputeReason(Number(input.reason))
  const evidenceHash = validateEvidenceHash(input.evidenceHash, 'evidenceHash')
  const proofId = asHex32(input.proofId, 'proofId')
  const disputeId = asHex32(input.disputeId ?? generateRandomHex32(), 'disputeId')

  const reporterHash = asHex32(
    input.reporterHash ?? (await sha256(`${input.publicKey}:${proofId}`)),
    'reporterHash',
  )

  machine?.send({ type: 'SUBMIT' })

  try {
    const server = new rpc.Server(RPC_URL)
    const account = await server.getAccount(input.publicKey)
    const contract = new Contract(input.contractId)
    const operation = contract.call(
      'open_dispute' satisfies RegistryMethod,
      new Address(input.publicKey).toScVal(),
      scBytes32(reporterHash),
      scBytes32(disputeId),
      scBytes32(proofId),
      scU32(reason),
      scBytes32(evidenceHash),
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
      const err = new Error(signed.error.message || 'Transaction rejected by wallet.')
      machine?.send({ type: 'FAILED', error: err.message })
      throw err
    }

    const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
    const submitted: SendTransactionResponse = await server.sendTransaction(signedTransaction)

    if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
      const err = new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
      machine?.send({ type: 'FAILED', error: err.message })
      throw err
    }

    const hash = submitted.hash ?? ''
    machine?.send({ type: 'TX_HASH_RECEIVED', hash })

    const txState = initialTxState(submitted.status)
    if (submitted.status === 'SUCCESS') {
      machine?.send({ type: 'CONFIRMED' })
    }

    return {
      hash,
      status: submitted.status,
      txState,
    }
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error)
    machine?.send({ type: 'FAILED', error: msg })
    throw error
  }
}

/**
 * Respond to an open dispute as the issuer (Tier 3) or source (Tier 2).
 * Validates response commitment format client-side.
 * Uses the TransactionStateMachine to track progress if provided.
 */
export async function respondDispute(
  input: RespondDisputeInput,
  machine?: TransactionStateMachine,
): Promise<RegisterProofResult> {
  const disputeId = asHex32(input.disputeId, 'disputeId')
  const responseCommitment = validateEvidenceHash(input.responseCommitment, 'responseCommitment')

  machine?.send({ type: 'SUBMIT' })

  try {
    const server = new rpc.Server(RPC_URL)
    const account = await server.getAccount(input.publicKey)
    const contract = new Contract(input.contractId)
    const operation = contract.call(
      'respond_dispute' satisfies RegistryMethod,
      new Address(input.publicKey).toScVal(),
      scBytes32(disputeId),
      scBytes32(responseCommitment),
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
      const err = new Error(signed.error.message || 'Transaction rejected by wallet.')
      machine?.send({ type: 'FAILED', error: err.message })
      throw err
    }

    const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
    const submitted: SendTransactionResponse = await server.sendTransaction(signedTransaction)

    if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
      const err = new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
      machine?.send({ type: 'FAILED', error: err.message })
      throw err
    }

    const hash = submitted.hash ?? ''
    machine?.send({ type: 'TX_HASH_RECEIVED', hash })

    const txState = initialTxState(submitted.status)
    if (submitted.status === 'SUCCESS') {
      machine?.send({ type: 'CONFIRMED' })
    }

    return {
      hash,
      status: submitted.status,
      txState,
    }
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error)
    machine?.send({ type: 'FAILED', error: msg })
    throw error
  }
}





export async function getProofHistory(
  contractId: string,
  proofId: string,
  sourceAddress?: string,
  limit = 256,
): Promise<ProofHistoryResult> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }

  const count = await getProofHistoryCount(contractId, proofId, sourceAddress)
  const cappedLimit = Math.min(limit, count)
  const entries: ProofHistoryEntry[] = []

  for (let seq = 1; seq <= cappedLimit; seq += 1) {
    const entry = await getProofHistoryAt(contractId, proofId, sourceAddress, seq)
    if (entry) {
      entries.push(entry)
    }
  }

  return { entries, count }
}

export async function getProofHistoryAt(
  contractId: string,
  proofId: string,
  sourceAddress?: string,
  seq = 1,
): Promise<ProofHistoryEntry | null> {
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
        'get_proof_history_at' satisfies RegistryMethod,
        scBytes32(asHex32(proofId, 'proofId')),
        scU32(seq),
      ),
    )
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
    action: Number(native.action) as ProofHistoryEntry['action'],
    timestamp: native.timestamp?.toString?.() ?? String(native.timestamp),
    actor: native.actor == null ? null : String(native.actor),
    reasonCode: Number(native.reason_code),
  }
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
    txState: initialTxState(submitted.status),
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
    txState: initialTxState(submitted.status),
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
    txState: initialTxState(submitted.status),
  }
}

export async function getVerifierState(
  contractId: string,
  sourceAddress?: string,
): Promise<ChainVerifierState | null> {
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
    activeVerifier: native.active_verifier ? String(native.active_verifier) : null,
    pendingVerifier: native.pending_verifier ? String(native.pending_verifier) : null,
    previousVerifier: native.previous_verifier ? String(native.previous_verifier) : null,
    activationLedger: String(native.activation_ledger),
    overlapWindow: String(native.overlap_window),
    rollbackWindow: String(native.rollback_window),
    rollbackWindowEnd: String(native.rollback_window_end),
  }
}

/**
 * Check whether a delegation from `grantor` to `delegate` is currently active
 * for the requested `scope` bitmask.
 *
 * Calls `is_delegation_active(grantor, delegate, scope)` on the contract.
 * Returns `false` rather than throwing on missing/expired/wrong-scope delegations.
 */
export async function isDelegationActive(
  contractId: string,
  grantor: string,
  delegate: string,
  scope: number,
  sourceAddress?: string,
): Promise<boolean> {
  const source = sourceAddress || delegate || READONLY_SOURCE
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
        'is_delegation_active' satisfies RegistryMethod,
        new Address(grantor).toScVal(),
        new Address(delegate).toScVal(),
        scU32(scope),
      ),
    )
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)
  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }
  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return false
  }

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : null
  return Boolean(native)
}

/**
 * Read the stored `DelegationRecord` from `grantor` to `delegate`, if any.
 * Returns `null` if no delegation is recorded.
 */
export async function getDelegation(
  contractId: string,
  grantor: string,
  delegate: string,
  sourceAddress?: string,
): Promise<DelegationRecord | null> {
  const source = sourceAddress || delegate || READONLY_SOURCE
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
        'get_delegation' satisfies RegistryMethod,
        new Address(grantor).toScVal(),
        new Address(delegate).toScVal(),
      ),
    )
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
    grantor: String(native.grantor),
    delegate: String(native.delegate),
    scope: Number(native.scope),
    grantedAt: Number(native.granted_at),
    expiresAt: Number(native.expires_at),
  }
}
