import process from 'node:process'
import { StrKey } from '@stellar/stellar-sdk'
import { asHex32 } from './hashing.js'
import {
  lookupLineage,
  resolveContractId,
  resolveRpcUrl,
  MalformedLineageError,
  type LineageLookupResult,
} from './stellar-lookup.js'

/**
 * Exit codes for the `lineage` command. A missing record uses the shared
 * `not_found` code so scripts can tell it apart from success and errors.
 */
export const LINEAGE_EXIT_CODES = {
  found: 0,
  usage: 2,
  not_found: 3,
  error: 8,
} as const

function exit(code: number, message?: string): never {
  if (message) {
    process.stderr.write(`harpocrates: ${message}\n`)
  }
  process.exit(code)
}

/**
 * Format a lineage record for humans. Only public lineage fields are shown.
 */
export function formatLineage(info: LineageLookupResult & { contractId: string; network: string }): string {
  const lines = [
    `Output digest:  ${info.outputDigest}`,
    `Contract:       ${info.contractId}`,
    `Network:        ${info.network}`,
    `Transformation: ${info.transformationKind}`,
    `Depth:          ${info.depth}`,
    `Parents (${info.parentProofIds.length}):`,
    ...info.parentProofIds.map((id) => `  - ${id}`),
  ]
  return lines.join('\n')
}

/**
 * Handle `harpocrates lineage --output-digest <hex>`: print the parents,
 * transformation kind and depth of a registered derivative.
 */
export async function handleLineage(
  flags: Record<string, string>,
  debugLog: (event: Record<string, unknown>) => void = () => {},
): Promise<void> {
  const rawDigest = flags['output-digest'] || flags.outputDigest
  const contractId = resolveContractId(flags['contract-id'] || flags.contractId)
  const rpcUrl = resolveRpcUrl(flags['rpc-url'] || flags.rpcUrl)
  const sourceAddress =
    flags['source-address'] || flags.sourceAddress || process.env.HARPOCRATES_SOURCE_ADDRESS
  const network = flags.network || 'Test SDF Network ; September 2015'
  const outputFormat = flags.output || flags.o || 'text'

  if (!rawDigest) {
    exit(LINEAGE_EXIT_CODES.usage, '--output-digest is required for lineage lookup')
  }

  let outputDigest: string
  try {
    outputDigest = asHex32(rawDigest, 'outputDigest')
  } catch {
    exit(LINEAGE_EXIT_CODES.usage, 'invalid --output-digest: must be a 32-byte hex string')
  }

  if (outputFormat !== 'text' && outputFormat !== 'json') {
    exit(LINEAGE_EXIT_CODES.usage, 'invalid --output: expected "text" or "json"')
  }

  if (!contractId || !StrKey.isValidContract(contractId)) {
    exit(LINEAGE_EXIT_CODES.error, 'a valid --contract-id is required for lineage lookup')
  }

  debugLog({ event: 'lineage.lookup', outputDigest, contractId, network })

  let record: LineageLookupResult | null
  try {
    record = await lookupLineage(contractId, outputDigest, {
      rpcUrl,
      sourceAddress,
      networkPassphrase: network,
    })
  } catch (err) {
    if (err instanceof MalformedLineageError) {
      exit(LINEAGE_EXIT_CODES.error, 'malformed lineage record returned by the registry')
    }
    exit(LINEAGE_EXIT_CODES.error, 'lineage lookup dependency failed')
  }

  if (!record) {
    exit(LINEAGE_EXIT_CODES.not_found, `no lineage record found for output digest ${outputDigest}`)
  }

  const payload = {
    outputDigest: record.outputDigest,
    contractId,
    network,
    transformationKind: record.transformationKind,
    depth: record.depth,
    parentProofIds: record.parentProofIds,
  }

  if (outputFormat === 'json') {
    process.stdout.write(JSON.stringify(payload, null, 2) + '\n')
  } else {
    process.stdout.write(formatLineage(payload) + '\n')
  }

  exit(LINEAGE_EXIT_CODES.found)
}
