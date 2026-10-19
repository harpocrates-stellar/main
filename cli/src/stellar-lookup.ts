import { BASE_FEE, Contract, Networks, StrKey, TransactionBuilder, rpc, nativeToScVal, scValToNative } from '@stellar/stellar-sdk'
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

/**
 * Chain-level dispute record returned by the Harpocrates Registry contract.
 */
export type ChainDisputeRecord = {
  disputeId: string
  proofId: string
  opener: string
  reason: string
  status: number
  createdAt: string
  resolvedAt?: string
}

export type StellarLookupOptions = {
  /** Stellar RPC URL (defaults to testnet). */
  rpcUrl?: string
  /** Network passphrase (defaults to testnet). */
  networkPassphrase?: string
  /** Source account for simulation. If omitted the simulation will likely fail. */
  sourceAddress?: string
}

const DEFAULT_RPC_URL = 'https://soroban-testnet.stellar.org'

/**
 * Resolve the RPC URL from an explicit option, the HARPOCRATES_RPC_URL env
 * variable, or the built-in testnet default, in that order of precedence.
 */
export function resolveRpcUrl(explicit?: string): string {
  if (explicit !== undefined && explicit !== '') return explicit
  const fromEnv = process.env.HARPOCRATES_RPC_URL
  if (fromEnv !== undefined && fromEnv !== '') return fromEnv
  return DEFAULT_RPC_URL
}

/**
 * Resolve the contract ID from an explicit option or the
 * HARPOCRATES_CONTRACT_ID env variable. Returns undefined when neither is set.
 */
export function resolveContractId(explicit?: string): string | undefined {
  if (explicit !== undefined && explicit !== '') return explicit
  const fromEnv = process.env.HARPOCRATES_CONTRACT_ID
  if (fromEnv !== undefined && fromEnv !== '') return fromEnv
  return undefined
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
  const rpcUrl = resolveRpcUrl(options.rpcUrl)
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source = options.sourceAddress

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await server.getAccount(source)
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
    expiresAt: native.expires_at?.toString?.() ?? undefined,
    source: native.source ?? null,
    issuer: native.issuer ?? null,
  }
}

/**
 * Read a dispute record from the registry by its dispute ID.
 *
 * Uses a simulation-only read so no signing is required. Returns `null`
 * if the contract returns an empty `Option` (no such dispute).
 */
export async function getDispute(
  contractId: string,
  disputeId: string,
  options: StellarLookupOptions = {},
): Promise<ChainDisputeRecord | null> {
  const args: unknown[] = [nativeToScVal(disputeId)]
  const native = await simulateRead(contractId, 'get_dispute', args, options)

  if (native === null || native === undefined) return null

  return {
    disputeId,
    proofId: native.proof_id ?? '',
    opener: native.opener ?? '',
    reason: native.reason ?? '',
    status: Number(native.status),
    createdAt: native.created_at?.toString?.() ?? String(native.created_at),
    resolvedAt: native.resolved_at?.toString?.() ?? undefined,
  }
}

/**
 * Read the number of open disputes for a proof ID.
 *
 * Uses a simulation-only read so no signing is required. Returns `null` if
 * the contract returns an empty `Option`.
 */
export async function getOpenDisputeCount(
  contractId: string,
  proofId: string,
  options: StellarLookupOptions = {},
): Promise<number | null> {
  const args: unknown[] = [nativeToScVal(proofId)]
  const native = await simulateRead(contractId, 'get_open_dispute_count', args, options)

  if (native === null || native === undefined) return null

  return Number(native)
}

/**
 * Run a simulation-only contract read and return the decoded native value.
 * Throws on simulation errors and returns `null` for empty `Option` results.
 */
async function simulateRead(
  contractId: string,
  method: string,
  args: unknown[],
  options: StellarLookupOptions,
): Promise<any> {
  const rpcUrl = options.rpcUrl ?? DEFAULT_RPC_URL
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source = options.sourceAddress

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)

  const methodArgs: unknown[] = args ?? []
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call(method, ...methodArgs))
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)

  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }

  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return null
  }

  const retval = simulation.result?.retval
  if (!retval) return null

  const native = scValToNative(retval)
  if (native === null || native === undefined) return null

  return native
}
