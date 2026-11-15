import { StrKey } from '@stellar/stellar-sdk'
import { ALLOWED_TIERS, type IdentityTier } from './metadata.js'
import { parseManifest, type ProofManifest } from './manifest.js'
import { resolveNetwork } from './network.js'
import { networkName } from './normalize.js'

export const COMPATIBILITY_REPORT_PROTOCOL = 'harpocrates-compatibility-report' as const
export const COMPATIBILITY_REPORT_VERSION = 1 as const
export const MAX_COMPATIBILITY_BUNDLE_BYTES = 1024 * 1024

export type BundleInputKind =
  | 'bundle'
  | 'manifest'
  | 'verification-receipt'
  | 'signed-receipt'

export type CompatibilityCheckName =
  | 'bundle_integrity'
  | 'network'
  | 'contract_id'
  | 'manifest_version'
  | 'identity_tier'
  | 'verifier_scope'
  | 'circuit_version'

export type CompatibilityCheckEntry = {
  check: CompatibilityCheckName
  compatible: boolean
  expected: string | number | null
  actual: string | number | null
  reason?: string
}

export type SelectedCompatibilityConfig = {
  network: string
  contractId: string
  tier?: IdentityTier
  verifierScope?: string
  circuitVersion?: string
}

export type CompatibilityInspectionReport = {
  protocol: typeof COMPATIBILITY_REPORT_PROTOCOL
  version: typeof COMPATIBILITY_REPORT_VERSION
  compatible: boolean
  readOnly: true
  bundleKind: BundleInputKind
  selected: {
    network: string
    networkName: string
    contractId: string
    tier: IdentityTier | null
    verifierScope: string | null
    circuitVersion: string | null
  }
  observed: {
    proofId: string
    network: string
    networkName: string
    contractId: string
    manifestVersion: number | null
    tier: IdentityTier
    verifierScope: string | null
    circuitVersion: string | null
  }
  checks: CompatibilityCheckEntry[]
  mismatches: CompatibilityCheckName[]
}

interface ParsedBundleMetadata {
  bundleKind: BundleInputKind
  proofId: string
  network: string
  contractId: string
  manifestVersion: number | null
  tier: IdentityTier
  verifierScope: string | null
  circuitVersion: string | null
  integrityIssues: string[]
}

const HEX32_RE = /^[0-9a-fA-F]{64}$/
const SCOPE_RE = /^(0|[1-9][0-9]*)$/
const FORBIDDEN_PRIVATE_KEYS = new Set([
  'secret',
  'signerSecret',
  'privateKey',
  'seed',
  'witness',
  'witnessData',
  'proofBytes',
])

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function containsForbiddenPrivateField(value: unknown, depth = 0): boolean {
  if (depth > 8 || !isPlainObject(value)) {
    if (Array.isArray(value) && depth <= 8) {
      return value.some((item) => containsForbiddenPrivateField(item, depth + 1))
    }
    return false
  }
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_PRIVATE_KEYS.has(key)) return true
    if (containsForbiddenPrivateField(child, depth + 1)) return true
  }
  return false
}

function extractManifestCircuitVersion(manifest: ProofManifest): string | null {
  if (manifest.selectiveDisclosure !== undefined) {
    return String(manifest.selectiveDisclosure.circuitVersion)
  }
  return null
}

function parseSignedReceiptObject(obj: Record<string, unknown>): {
  proofId: string
  videoHash: string
  metadataHash: string
  tier: IdentityTier
  network: string
  contractId: string
  circuitVersion: string
} {
  if (obj.protocol !== 'harpocrates-verification-receipt' || obj.version !== 1) {
    throw new Error('unsupported signed receipt version')
  }
  if (typeof obj.proofId !== 'string' || !HEX32_RE.test(obj.proofId)) {
    throw new Error('signed receipt proofId is invalid')
  }
  if (typeof obj.videoHash !== 'string' || !HEX32_RE.test(obj.videoHash)) {
    throw new Error('signed receipt videoHash is invalid')
  }
  if (typeof obj.metadataHash !== 'string' || !HEX32_RE.test(obj.metadataHash)) {
    throw new Error('signed receipt metadataHash is invalid')
  }
  if (typeof obj.tier !== 'string' || !ALLOWED_TIERS.has(obj.tier)) {
    throw new Error('signed receipt tier is invalid')
  }
  if (typeof obj.networkPassphrase !== 'string' || obj.networkPassphrase.trim() === '') {
    throw new Error('signed receipt networkPassphrase is invalid')
  }
  if (typeof obj.contractId !== 'string' || obj.contractId.trim() === '') {
    throw new Error('signed receipt contractId is invalid')
  }
  if (typeof obj.circuitVersion !== 'string' || obj.circuitVersion.trim() === '') {
    throw new Error('signed receipt circuitVersion is invalid')
  }
  return {
    proofId: obj.proofId,
    videoHash: obj.videoHash,
    metadataHash: obj.metadataHash,
    tier: obj.tier as IdentityTier,
    network: obj.networkPassphrase,
    contractId: obj.contractId,
    circuitVersion: obj.circuitVersion,
  }
}

function parseBundleMetadata(rawJson: string): ParsedBundleMetadata {
  if (Buffer.byteLength(rawJson, 'utf-8') > MAX_COMPATIBILITY_BUNDLE_BYTES) {
    throw new Error('bundle exceeds 1 MiB limit')
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(rawJson)
  } catch {
    throw new Error('bundle is not valid JSON')
  }

  if (!isPlainObject(parsed)) {
    throw new Error('bundle must be a JSON object')
  }

  if (containsForbiddenPrivateField(parsed)) {
    throw new Error('bundle contains forbidden private or secret fields')
  }

  // Case 1: Standalone signed verification receipt
  if (parsed.protocol === 'harpocrates-verification-receipt') {
    const sr = parseSignedReceiptObject(parsed)
    return {
      bundleKind: 'signed-receipt',
      proofId: sr.proofId,
      network: sr.network,
      contractId: sr.contractId,
      manifestVersion: null,
      tier: sr.tier,
      verifierScope: null,
      circuitVersion: sr.circuitVersion,
      integrityIssues: [],
    }
  }

  // Case 2: Standalone ProofManifest
  if (parsed.protocol === 'harpocrates' && (parsed.version === 1 || parsed.version === 2)) {
    const manifest = parseManifest(JSON.stringify(parsed))
    return {
      bundleKind: 'manifest',
      proofId: manifest.proofId,
      network: manifest.network,
      contractId: manifest.contractId,
      manifestVersion: manifest.version,
      tier: manifest.tier,
      verifierScope: manifest.verifierScope ?? null,
      circuitVersion: extractManifestCircuitVersion(manifest),
      integrityIssues: [],
    }
  }

  // Case 3: VerificationReceipt ({ version: 1, verifiedAt, manifest, transaction, chainRecord, result })
  if (
    parsed.version === 1 &&
    isPlainObject(parsed.manifest) &&
    isPlainObject(parsed.transaction) &&
    typeof parsed.result === 'string' &&
    !('trustSnapshot' in parsed) &&
    !('receipt' in parsed) &&
    parsed.protocol === undefined
  ) {
    const manifest = parseManifest(JSON.stringify(parsed.manifest))
    const integrityIssues: string[] = []
    if (
      typeof parsed.transaction.txHash === 'string' &&
      parsed.transaction.txHash.toLowerCase() !== manifest.transactionRef.toLowerCase()
    ) {
      integrityIssues.push('receipt transaction txHash does not match manifest transactionRef')
    }
    if (parsed.transaction.contractMatch === false) {
      integrityIssues.push('receipt transaction indicates contract mismatch')
    }
    if (isPlainObject(parsed.chainRecord)) {
      if (
        typeof parsed.chainRecord.videoHash === 'string' &&
        parsed.chainRecord.videoHash.toLowerCase() !== manifest.videoHash.toLowerCase()
      ) {
        integrityIssues.push('receipt chainRecord videoHash does not match manifest videoHash')
      }
      if (
        typeof parsed.chainRecord.metadataHash === 'string' &&
        parsed.chainRecord.metadataHash.toLowerCase() !== manifest.metadataHash.toLowerCase()
      ) {
        integrityIssues.push('receipt chainRecord metadataHash does not match manifest metadataHash')
      }
    }
    return {
      bundleKind: 'verification-receipt',
      proofId: manifest.proofId,
      network: manifest.network,
      contractId: manifest.contractId,
      manifestVersion: manifest.version,
      tier: manifest.tier,
      verifierScope: manifest.verifierScope ?? null,
      circuitVersion: extractManifestCircuitVersion(manifest),
      integrityIssues,
    }
  }

  // Case 4: Verification bundle envelope ({ manifest?, receipt?, signedReceipt?, trustSnapshot?, network?, contractId?, ... })
  const allowedEnvelopeKeys = new Set([
    'protocol',
    'version',
    'createdAt',
    'network',
    'networkPassphrase',
    'contractId',
    'verifierScope',
    'circuitVersion',
    'manifest',
    'receipt',
    'signedReceipt',
    'trustSnapshot',
  ])
  for (const key of Object.keys(parsed)) {
    if (!allowedEnvelopeKeys.has(key)) {
      throw new Error(`unsupported bundle field: ${key}`)
    }
  }
  if (
    parsed.protocol !== undefined &&
    parsed.protocol !== 'harpocrates-verification-bundle' &&
    parsed.protocol !== 'harpocrates-bundle'
  ) {
    throw new Error('unsupported bundle protocol')
  }
  if (parsed.version !== undefined && parsed.version !== 1) {
    throw new Error('unsupported bundle version')
  }

  let manifest: ProofManifest | null = null
  if (parsed.manifest !== undefined) {
    if (!isPlainObject(parsed.manifest)) {
      throw new Error('bundle.manifest must be a JSON object')
    }
    manifest = parseManifest(JSON.stringify(parsed.manifest))
  }

  let receiptManifest: ProofManifest | null = null
  let signedReceiptMeta: ReturnType<typeof parseSignedReceiptObject> | null = null

  if (parsed.receipt !== undefined) {
    if (!isPlainObject(parsed.receipt)) {
      throw new Error('bundle.receipt must be a JSON object')
    }
    if (parsed.receipt.protocol === 'harpocrates-verification-receipt') {
      signedReceiptMeta = parseSignedReceiptObject(parsed.receipt)
    } else if (isPlainObject(parsed.receipt.manifest)) {
      receiptManifest = parseManifest(JSON.stringify(parsed.receipt.manifest))
    } else {
      throw new Error('bundle.receipt is invalid')
    }
  }

  if (parsed.signedReceipt !== undefined) {
    if (!isPlainObject(parsed.signedReceipt)) {
      throw new Error('bundle.signedReceipt must be a JSON object')
    }
    signedReceiptMeta = parseSignedReceiptObject(parsed.signedReceipt)
  }

  const primaryManifest = manifest ?? receiptManifest
  if (!primaryManifest && !signedReceiptMeta) {
    throw new Error('bundle must contain at least a manifest or receipt')
  }

  const integrityIssues: string[] = []
  const observedProofId = primaryManifest ? primaryManifest.proofId : signedReceiptMeta!.proofId
  const observedNetwork = primaryManifest ? primaryManifest.network : signedReceiptMeta!.network
  const observedContractId = primaryManifest ? primaryManifest.contractId : signedReceiptMeta!.contractId
  const observedTier = primaryManifest ? primaryManifest.tier : signedReceiptMeta!.tier
  let observedVerifierScope = primaryManifest ? (primaryManifest.verifierScope ?? null) : null
  let observedCircuitVersion = primaryManifest
    ? extractManifestCircuitVersion(primaryManifest)
    : signedReceiptMeta!.circuitVersion

  if (manifest && receiptManifest) {
    if (manifest.proofId.toLowerCase() !== receiptManifest.proofId.toLowerCase()) {
      integrityIssues.push('bundle manifest and receipt disagree on proofId')
    }
    if (manifest.network !== receiptManifest.network) {
      integrityIssues.push('bundle manifest and receipt disagree on network')
    }
    if (manifest.contractId !== receiptManifest.contractId) {
      integrityIssues.push('bundle manifest and receipt disagree on contractId')
    }
    if (manifest.tier !== receiptManifest.tier) {
      integrityIssues.push('bundle manifest and receipt disagree on tier')
    }
  }

  if (primaryManifest && signedReceiptMeta) {
    if (primaryManifest.proofId.toLowerCase() !== signedReceiptMeta.proofId.toLowerCase()) {
      integrityIssues.push('bundle manifest and signedReceipt disagree on proofId')
    }
    if (primaryManifest.videoHash.toLowerCase() !== signedReceiptMeta.videoHash.toLowerCase()) {
      integrityIssues.push('bundle manifest and signedReceipt disagree on videoHash')
    }
    if (primaryManifest.metadataHash.toLowerCase() !== signedReceiptMeta.metadataHash.toLowerCase()) {
      integrityIssues.push('bundle manifest and signedReceipt disagree on metadataHash')
    }
    if (primaryManifest.network !== signedReceiptMeta.network) {
      integrityIssues.push('bundle manifest and signedReceipt disagree on network')
    }
    if (primaryManifest.contractId !== signedReceiptMeta.contractId) {
      integrityIssues.push('bundle manifest and signedReceipt disagree on contractId')
    }
    if (primaryManifest.tier !== signedReceiptMeta.tier) {
      integrityIssues.push('bundle manifest and signedReceipt disagree on tier')
    }
    if (observedCircuitVersion === null) {
      observedCircuitVersion = signedReceiptMeta.circuitVersion
    } else if (observedCircuitVersion !== signedReceiptMeta.circuitVersion) {
      integrityIssues.push('bundle manifest and signedReceipt disagree on circuitVersion')
    }
  }

  const envelopeNetwork =
    typeof parsed.network === 'string'
      ? parsed.network
      : typeof parsed.networkPassphrase === 'string'
        ? parsed.networkPassphrase
        : undefined
  if (envelopeNetwork !== undefined && envelopeNetwork !== observedNetwork) {
    integrityIssues.push('bundle envelope network disagrees with inner statement')
  }
  if (typeof parsed.contractId === 'string' && parsed.contractId !== observedContractId) {
    integrityIssues.push('bundle envelope contractId disagrees with inner statement')
  }
  if (typeof parsed.verifierScope === 'string') {
    if (observedVerifierScope !== null && observedVerifierScope !== parsed.verifierScope) {
      integrityIssues.push('bundle envelope verifierScope disagrees with manifest')
    }
    observedVerifierScope = observedVerifierScope ?? parsed.verifierScope
  }
  if (typeof parsed.circuitVersion === 'string' || typeof parsed.circuitVersion === 'number') {
    const envCircuit = String(parsed.circuitVersion)
    if (observedCircuitVersion !== null && observedCircuitVersion !== envCircuit) {
      integrityIssues.push('bundle envelope circuitVersion disagrees with statement')
    }
    observedCircuitVersion = observedCircuitVersion ?? envCircuit
  }

  if (parsed.trustSnapshot !== undefined) {
    if (!isPlainObject(parsed.trustSnapshot)) {
      throw new Error('bundle.trustSnapshot must be a JSON object')
    }
    const ts = parsed.trustSnapshot
    const snapNetwork =
      typeof ts.network === 'string'
        ? ts.network
        : typeof ts.networkPassphrase === 'string'
          ? ts.networkPassphrase
          : undefined
    if (snapNetwork !== undefined && snapNetwork !== observedNetwork) {
      integrityIssues.push('bundle trustSnapshot network disagrees with statement')
    }
    if (typeof ts.contractId === 'string' && ts.contractId !== observedContractId) {
      integrityIssues.push('bundle trustSnapshot contractId disagrees with statement')
    }
    if (typeof ts.verifierScope === 'string') {
      if (observedVerifierScope !== null && observedVerifierScope !== ts.verifierScope) {
        integrityIssues.push('bundle trustSnapshot verifierScope disagrees with statement')
      }
      observedVerifierScope = observedVerifierScope ?? ts.verifierScope
    }
    if (typeof ts.circuitVersion === 'string' || typeof ts.circuitVersion === 'number') {
      const snapCircuit = String(ts.circuitVersion)
      if (observedCircuitVersion !== null && observedCircuitVersion !== snapCircuit) {
        integrityIssues.push('bundle trustSnapshot circuitVersion disagrees with statement')
      }
      observedCircuitVersion = observedCircuitVersion ?? snapCircuit
    }
  }

  return {
    bundleKind: 'bundle',
    proofId: observedProofId,
    network: observedNetwork,
    contractId: observedContractId,
    manifestVersion: primaryManifest ? primaryManifest.version : null,
    tier: observedTier,
    verifierScope: observedVerifierScope,
    circuitVersion: observedCircuitVersion,
    integrityIssues,
  }
}

export function validateSelectedConfig(config: SelectedCompatibilityConfig): {
  network: string
  contractId: string
  tier: IdentityTier | null
  verifierScope: string | null
  circuitVersion: string | null
} {
  if (typeof config.network !== 'string' || config.network.trim() === '') {
    throw new Error('selected network must be a non-empty string')
  }
  if (typeof config.contractId !== 'string' || !StrKey.isValidContract(config.contractId)) {
    throw new Error('selected contractId must be a valid Stellar contract address')
  }
  if (config.tier !== undefined && !ALLOWED_TIERS.has(config.tier)) {
    throw new Error(`selected tier must be one of: ${[...ALLOWED_TIERS].join(', ')}`)
  }
  if (config.verifierScope !== undefined && !SCOPE_RE.test(config.verifierScope)) {
    throw new Error('selected verifierScope must be a non-negative integer string')
  }
  if (config.circuitVersion !== undefined && config.circuitVersion.trim() === '') {
    throw new Error('selected circuitVersion must be a non-empty string')
  }

  return {
    network: resolveNetwork(config.network),
    contractId: config.contractId,
    tier: config.tier ?? null,
    verifierScope: config.verifierScope ?? null,
    circuitVersion: config.circuitVersion !== undefined ? config.circuitVersion.trim() : null,
  }
}

/**
 * Compare bundle, manifest, or receipt metadata against an explicit selected
 * deployment configuration without signing or performing chain/RPC writes.
 */
export function inspectBundleCompatibility(
  rawBundleJson: string,
  selectedConfig: SelectedCompatibilityConfig,
): CompatibilityInspectionReport {
  const normalizedSelected = validateSelectedConfig(selectedConfig)
  const observed = parseBundleMetadata(rawBundleJson)

  const checks: CompatibilityCheckEntry[] = []

  // 1. Internal bundle integrity check
  const bundleIntegrityOk = observed.integrityIssues.length === 0
  checks.push({
    check: 'bundle_integrity',
    compatible: bundleIntegrityOk,
    expected: 'consistent',
    actual: bundleIntegrityOk ? 'consistent' : 'inconsistent',
    ...(bundleIntegrityOk ? {} : { reason: observed.integrityIssues.join('; ') }),
  })

  // 2. Contract ID compatibility check
  const contractIdOk =
    StrKey.isValidContract(observed.contractId) &&
    observed.contractId === normalizedSelected.contractId
  checks.push({
    check: 'contract_id',
    compatible: contractIdOk,
    expected: normalizedSelected.contractId,
    actual: observed.contractId,
    ...(contractIdOk
      ? {}
      : {
          reason: StrKey.isValidContract(observed.contractId)
            ? 'bundle contractId does not match selected --contract-id'
            : 'bundle contractId is not a valid Stellar contract address',
        }),
  })

  // 3. Network passphrase compatibility check
  const networkOk = observed.network === normalizedSelected.network
  checks.push({
    check: 'network',
    compatible: networkOk,
    expected: normalizedSelected.network,
    actual: observed.network,
    ...(networkOk
      ? {}
      : { reason: 'bundle network passphrase does not match selected --network' }),
  })

  // 4. Manifest version check (when manifest is present)
  if (observed.manifestVersion !== null) {
    const versionOk = observed.manifestVersion === 1 || observed.manifestVersion === 2
    checks.push({
      check: 'manifest_version',
      compatible: versionOk,
      expected: '1|2',
      actual: observed.manifestVersion,
      ...(versionOk ? {} : { reason: 'unsupported manifest version' }),
    })
  }

  // 5. Identity tier check (preserve separation of identity tiers when explicitly selected)
  if (normalizedSelected.tier !== null) {
    const tierOk = observed.tier === normalizedSelected.tier
    checks.push({
      check: 'identity_tier',
      compatible: tierOk,
      expected: normalizedSelected.tier,
      actual: observed.tier,
      ...(tierOk ? {} : { reason: 'bundle identity tier does not match selected --tier' }),
    })
  }

  // 6. Verifier scope check (when explicitly selected)
  if (normalizedSelected.verifierScope !== null) {
    const scopeOk = observed.verifierScope !== null && observed.verifierScope === normalizedSelected.verifierScope
    checks.push({
      check: 'verifier_scope',
      compatible: scopeOk,
      expected: normalizedSelected.verifierScope,
      actual: observed.verifierScope,
      ...(scopeOk
        ? {}
        : {
            reason:
              observed.verifierScope === null
                ? 'bundle does not declare a verifierScope (v1 or receipt-only bundle)'
                : 'bundle verifierScope does not match selected --verifier-scope',
          }),
    })
  }

  // 7. Circuit version check (when explicitly selected)
  if (normalizedSelected.circuitVersion !== null) {
    const circuitOk =
      observed.circuitVersion !== null && observed.circuitVersion === normalizedSelected.circuitVersion
    checks.push({
      check: 'circuit_version',
      compatible: circuitOk,
      expected: normalizedSelected.circuitVersion,
      actual: observed.circuitVersion,
      ...(circuitOk
        ? {}
        : {
            reason:
              observed.circuitVersion === null
                ? 'bundle does not declare a circuitVersion'
                : 'bundle circuitVersion does not match selected --circuit-version',
          }),
    })
  }

  const mismatches = checks.filter((c) => !c.compatible).map((c) => c.check)

  return {
    protocol: COMPATIBILITY_REPORT_PROTOCOL,
    version: COMPATIBILITY_REPORT_VERSION,
    compatible: mismatches.length === 0,
    readOnly: true,
    bundleKind: observed.bundleKind,
    selected: {
      network: normalizedSelected.network,
      networkName: networkName(normalizedSelected.network),
      contractId: normalizedSelected.contractId,
      tier: normalizedSelected.tier,
      verifierScope: normalizedSelected.verifierScope,
      circuitVersion: normalizedSelected.circuitVersion,
    },
    observed: {
      proofId: observed.proofId,
      network: observed.network,
      networkName: networkName(observed.network),
      contractId: observed.contractId,
      manifestVersion: observed.manifestVersion,
      tier: observed.tier,
      verifierScope: observed.verifierScope,
      circuitVersion: observed.circuitVersion,
    },
    checks,
    mismatches,
  }
}

/**
 * Map a compatibility inspection report to a deterministic CLI exit code.
 *
 * - `0`: compatible
 * - `5`: contract_mismatch
 * - `4`: network_mismatch
 * - `8`: bundle integrity failure or other constraint mismatch
 */
export function compatibilityExitCode(report: CompatibilityInspectionReport): number {
  if (report.compatible) return 0
  if (report.mismatches.includes('bundle_integrity')) return 8
  if (report.mismatches.includes('contract_id')) return 5
  if (report.mismatches.includes('network')) return 4
  return 8
}

/**
 * Render a human-readable summary of a compatibility inspection report.
 */
export function formatCompatibilityReport(report: CompatibilityInspectionReport): string {
  const lines = [
    `Compatibility: ${report.compatible ? 'COMPATIBLE' : 'INCOMPATIBLE'}`,
    `Mode:          read-only (no signing, no chain writes)`,
    `Bundle kind:   ${report.bundleKind}`,
    `Proof ID:      ${report.observed.proofId}`,
    `Selected:      network=${report.selected.network} (${report.selected.networkName}) contract=${report.selected.contractId}`,
    `Observed:      network=${report.observed.network} (${report.observed.networkName}) contract=${report.observed.contractId}`,
    'Checks:',
  ]
  for (const check of report.checks) {
    const status = check.compatible ? 'PASS' : 'FAIL'
    const detail = check.reason ? ` (${check.reason})` : ''
    lines.push(
      `  [${status}] ${check.check}: expected=${String(check.expected)} actual=${String(check.actual)}${detail}`,
    )
  }
  return lines.join('\n')
}
