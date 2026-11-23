import { StrKey } from '@stellar/stellar-sdk'
import { parseManifest, type ProofManifest } from './manifest.js'
import { DEFAULT_NETWORK_PASSPHRASE, resolveNetwork } from './network.js'
import { redactSensitive } from './logging.js'
import { resolveContractId } from './stellar-lookup.js'

export type CompatStatus =
  | 'compatible'
  | 'network_mismatch'
  | 'contract_mismatch'
  | 'incompatible'

export interface CompatConfig {
  contractId: string
  network: string
}

export interface CompatCheckItem {
  match: boolean
  bundle: string
  selected: string
}

export interface CompatReport {
  compatible: boolean
  status: CompatStatus
  network: CompatCheckItem
  contractId: CompatCheckItem
  manifestVersion: number
  protocol: string
  tier: string
  proofId: string
}

export const COMPAT_EXIT_CODES: Record<CompatStatus, number> = {
  compatible: 0,
  network_mismatch: 4,
  contract_mismatch: 5,
  incompatible: 5,
}

/**
 * Compare proof bundle (manifest) metadata against an explicit selected
 * network and contract configuration.
 *
 * Pure local inspection: performs no signing, no chain writes, and no RPC calls.
 */
export function checkCompatibility(
  manifest: ProofManifest,
  config: CompatConfig,
): CompatReport {
  const selectedNetwork = resolveNetwork(config.network)
  const bundleNetwork = resolveNetwork(manifest.network)

  const networkMatch = bundleNetwork === selectedNetwork
  const contractMatch = manifest.contractId === config.contractId

  let status: CompatStatus
  if (networkMatch && contractMatch) {
    status = 'compatible'
  } else if (!networkMatch && !contractMatch) {
    status = 'incompatible'
  } else if (!contractMatch) {
    status = 'contract_mismatch'
  } else {
    status = 'network_mismatch'
  }

  return {
    compatible: status === 'compatible',
    status,
    network: {
      match: networkMatch,
      bundle: manifest.network,
      selected: selectedNetwork,
    },
    contractId: {
      match: contractMatch,
      bundle: manifest.contractId,
      selected: config.contractId,
    },
    manifestVersion: manifest.version,
    protocol: manifest.protocol,
    tier: manifest.tier,
    proofId: manifest.proofId,
  }
}

export function formatCompatReport(report: CompatReport): string {
  const networkLine = report.network.match
    ? `Network:       MATCH (${report.network.selected})`
    : `Network:       MISMATCH (bundle: ${report.network.bundle}, selected: ${report.network.selected})`

  const contractLine = report.contractId.match
    ? `Contract:      MATCH (${report.contractId.selected})`
    : `Contract:      MISMATCH (bundle: ${report.contractId.bundle}, selected: ${report.contractId.selected})`

  return [
    `Compatibility: ${report.status}`,
    networkLine,
    contractLine,
    `Manifest:      v${report.manifestVersion} (${report.protocol}, tier: ${report.tier})`,
    `Proof ID:      ${report.proofId}`,
  ].join('\n')
}

export interface RunCheckCompatIo {
  readText: (path: string) => Promise<string>
  writeStdout: (text: string) => void
  writeStderr: (text: string) => void
  debugLog?: (event: Record<string, unknown>) => void
}

/**
 * Execute the `check-compat` command logic with injectable I/O and return the
 * process exit code. Performs no signing, no chain writes, and no RPC calls.
 */
export async function runCheckCompat(
  flags: Record<string, string>,
  io: RunCheckCompatIo,
): Promise<number> {
  const manifestPath = flags.manifest || flags.m
  const contractId = resolveContractId(flags['contract-id'] || flags.contractId)
  const network = resolveNetwork(flags.network || DEFAULT_NETWORK_PASSPHRASE)
  const outputFormat = flags.output || flags.o || 'text'

  if (!manifestPath) {
    io.writeStderr('harpocrates: --manifest is required for compatibility check\n')
    return 2
  }

  if (!contractId) {
    io.writeStderr('harpocrates: --contract-id is required for compatibility check\n')
    return 2
  }

  if (outputFormat !== 'text' && outputFormat !== 'json') {
    io.writeStderr('harpocrates: invalid --output: expected "text" or "json"\n')
    return 2
  }

  if (!StrKey.isValidContract(contractId)) {
    io.writeStderr('harpocrates: invalid --contract-id: expected a valid Stellar contract ID\n')
    return 8
  }

  let manifest: ProofManifest
  try {
    manifest = parseManifest(await io.readText(manifestPath))
  } catch {
    io.writeStderr('harpocrates: invalid or unreadable manifest\n')
    return 8
  }

  io.debugLog?.({
    event: 'check-compat.inspect',
    manifest: redactSensitive(manifest),
    contractId,
    network,
  })

  const report = checkCompatibility(manifest, { contractId, network })

  if (outputFormat === 'json') {
    io.writeStdout(JSON.stringify(report, null, 2) + '\n')
  } else {
    io.writeStdout(formatCompatReport(report) + '\n')
  }

  return COMPAT_EXIT_CODES[report.status] ?? 8
}
