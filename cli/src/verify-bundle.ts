import { StrKey } from '@stellar/stellar-sdk'
import { asHex32, sha256 } from './hashing.js'
import { parseManifest, serializeManifest, type ProofManifest } from './manifest.js'
import { ALLOWED_TIERS, type IdentityTier } from './metadata.js'
import { resolveNetwork } from './network.js'
import { classifyVerification } from './normalize.js'
import type { VerificationReceipt } from './receipt.js'
import {
  decodeReceiptFromQr,
  verifyVerificationReceipt,
  type SignedVerificationReceipt,
} from './signed-receipt.js'
import type { ChainProofRecord, LineageRecord, ProofStatus, TransactionVerification } from './stellar-lookup.js'
import { verifyLineageTree, type LineageTreeResult } from './verify-lineage.js'

export const VERIFICATION_BUNDLE_PROTOCOL = 'harpocrates-verification-bundle' as const
export const VERIFICATION_BUNDLE_VERSION = 1 as const
export const BUNDLE_REPORT_PROTOCOL = 'harpocrates-bundle-verification-report' as const
export const BUNDLE_REPORT_VERSION = 1 as const
export const MAX_VERIFICATION_BUNDLE_BYTES = 1024 * 1024

export type KeyValidityWindow = {
  notBefore?: string
  notAfter?: string
}

export type OfflineLineageSnapshot = {
  records: Record<string, LineageRecord | null>
  proofStatuses: Record<string, ProofStatus>
}

export type BundleTrustSnapshot = {
  capturedAt: string
  network: string
  contractId: string
  trustedKeys?: Record<string, JsonWebKey>
  keyValidity?: Record<string, KeyValidityWindow>
  manifestDigest?: string
  expectedTier?: IdentityTier
  verifierScope?: string
  lineageSnapshot?: OfflineLineageSnapshot
}

export type OfflineVerificationBundle = {
  protocol: typeof VERIFICATION_BUNDLE_PROTOCOL
  version: typeof VERIFICATION_BUNDLE_VERSION
  manifest: ProofManifest
  trustSnapshot: BundleTrustSnapshot
  signedReceipt?: SignedVerificationReceipt | string
  receipt?: VerificationReceipt
}

export type BundleCheckScope = 'offline' | 'online_only'
export type BundleCheckStatus = 'passed' | 'failed' | 'unavailable'

export type BundleCheckId =
  | 'bundle_integrity'
  | 'manifest_validation'
  | 'trust_snapshot_validation'
  | 'receipt_validation'
  | 'signed_receipt_signature'
  | 'statement_consistency'
  | 'lineage_snapshot'
  | 'live_rpc_transaction_lookup'
  | 'live_contract_state_simulation'
  | 'live_revocation_and_dispute_check'

export type BundleCheckEntry = {
  id: BundleCheckId
  scope: BundleCheckScope
  status: BundleCheckStatus
  detail: string
}

export type BundleOverallStatus =
  | 'offline_verified'
  | 'invalid'
  | 'network_mismatch'
  | 'contract_mismatch'

export type BundleVerificationReport = {
  protocol: typeof BUNDLE_REPORT_PROTOCOL
  version: typeof BUNDLE_REPORT_VERSION
  mode: 'offline'
  bundleValid: boolean
  overallStatus: BundleOverallStatus
  exitCode: 0 | 4 | 5 | 8
  onlineChecksStatus: 'unavailable'
  proofId: string | null
  tier: IdentityTier | null
  network: string | null
  contractId: string | null
  manifestDigest: string | null
  trustSnapshotCapturedAt: string | null
  checks: BundleCheckEntry[]
  onlineChecks: {
    liveRpcTransactionLookup: 'unavailable'
    liveContractStateSimulation: 'unavailable'
    liveRevocationAndDisputeCheck: 'unavailable'
  }
  lineage?: LineageTreeResult
  failureReasons: string[]
}

export type VerifyOfflineBundleOptions = {
  expectedNetwork?: string
  expectedContractId?: string
  expectedProofId?: string
  now?: Date
}

export type CreateOfflineVerificationBundleInput = {
  manifest: ProofManifest
  trustSnapshot: BundleTrustSnapshot
  signedReceipt?: SignedVerificationReceipt | string
  receipt?: VerificationReceipt
}

const PROHIBITED_PRIVATE_KEYS = new Set([
  'credentialsecret',
  'media',
  'mediabytes',
  'mnemonic',
  'nullifiersecret',
  'password',
  'privatekey',
  'proofbytes',
  'rawbytes',
  'secret',
  'secretkey',
  'seed',
  'signersecret',
  'token',
  'witness',
])

const PRIVATE_JWK_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const

const ALLOWED_BUNDLE_FIELDS = new Set([
  'protocol',
  'version',
  'manifest',
  'trustSnapshot',
  'signedReceipt',
  'receipt',
])

const ALLOWED_SNAPSHOT_FIELDS = new Set([
  'capturedAt',
  'network',
  'networkPassphrase',
  'contractId',
  'trustedKeys',
  'keyValidity',
  'manifestDigest',
  'expectedTier',
  'verifierScope',
  'lineageSnapshot',
])

const ALLOWED_PROOF_STATUSES = new Set<ProofStatus>([
  'valid',
  'revoked',
  'expired',
  'disputed',
  'missing',
])

function canonicalizeDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalizeDeep)
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(record).sort()) {
      if (record[key] !== undefined) {
        out[key] = canonicalizeDeep(record[key])
      }
    }
    return out
  }
  return value
}

export function computeManifestDigest(manifest: ProofManifest): string {
  return sha256(new TextEncoder().encode(serializeManifest(manifest)))
}

export function createOfflineVerificationBundle(
  input: CreateOfflineVerificationBundleInput,
): OfflineVerificationBundle {
  if (!input.signedReceipt && !input.receipt) {
    throw new Error('verification bundle requires at least one of signedReceipt or receipt')
  }
  const normalizedManifest = parseManifest(serializeManifest(input.manifest))
  const resolvedNetwork = resolveNetwork(input.trustSnapshot.network)
  if (!StrKey.isValidContract(input.trustSnapshot.contractId)) {
    throw new Error('trustSnapshot.contractId must be a valid Stellar contract ID')
  }

  const bundle: OfflineVerificationBundle = {
    protocol: VERIFICATION_BUNDLE_PROTOCOL,
    version: VERIFICATION_BUNDLE_VERSION,
    manifest: normalizedManifest,
    trustSnapshot: {
      ...input.trustSnapshot,
      network: resolvedNetwork,
      manifestDigest: input.trustSnapshot.manifestDigest ?? computeManifestDigest(normalizedManifest),
    },
  }
  if (input.signedReceipt !== undefined) bundle.signedReceipt = input.signedReceipt
  if (input.receipt !== undefined) bundle.receipt = input.receipt
  return bundle
}

export function serializeVerificationBundle(bundle: OfflineVerificationBundle): string {
  const serialized = JSON.stringify(canonicalizeDeep(bundle), null, 2)
  if (Buffer.byteLength(serialized, 'utf-8') > MAX_VERIFICATION_BUNDLE_BYTES) {
    throw new Error('verification bundle exceeds 1 MiB limit')
  }
  return serialized
}

function findProhibitedMaterial(value: unknown, seen = new WeakSet<object>()): string | null {
  if (value === null || typeof value !== 'object') return null
  if (seen.has(value)) return 'circular reference in bundle'
  seen.add(value)

  if (Array.isArray(value)) {
    for (const item of value) {
      const hit = findProhibitedMaterial(item, seen)
      if (hit) return hit
    }
    return null
  }

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase()
    if (PROHIBITED_PRIVATE_KEYS.has(normalized) || normalized.includes('witness')) {
      return `bundle contains prohibited private or witness field "${key}"`
    }
    const hit = findProhibitedMaterial(child, seen)
    if (hit) return hit
  }
  return null
}

function buildOnlineOnlyChecks(): BundleCheckEntry[] {
  return [
    {
      id: 'live_rpc_transaction_lookup',
      scope: 'online_only',
      status: 'unavailable',
      detail:
        'offline bundle verification runs without network access; live Stellar RPC transaction finality was not queried',
    },
    {
      id: 'live_contract_state_simulation',
      scope: 'online_only',
      status: 'unavailable',
      detail:
        'offline bundle verification runs without network access; live Soroban registry state was not simulated',
    },
    {
      id: 'live_revocation_and_dispute_check',
      scope: 'online_only',
      status: 'unavailable',
      detail:
        'offline bundle verification runs without network access; live on-chain revocation or dispute updates after trustSnapshot.capturedAt are unavailable',
    },
  ]
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function validatePublicJwkMap(rawKeys: unknown): {
  keys?: Record<string, JsonWebKey>
  error?: string
} {
  if (!isPlainObject(rawKeys)) {
    return { error: 'trustSnapshot.trustedKeys must be a JSON object mapping key IDs to public JWKs' }
  }
  const keys: Record<string, JsonWebKey> = {}
  for (const [keyId, rawJwk] of Object.entries(rawKeys)) {
    if (!keyId.trim()) {
      return { error: 'trustSnapshot.trustedKeys contains an empty key ID' }
    }
    if (!isPlainObject(rawJwk)) {
      return { error: `trustSnapshot.trustedKeys["${keyId}"] must be a JWK object` }
    }
    for (const privField of PRIVATE_JWK_FIELDS) {
      if (privField in rawJwk && rawJwk[privField] !== undefined) {
        return { error: `trustSnapshot.trustedKeys["${keyId}"] contains private key material` }
      }
    }
    if (
      Array.isArray(rawJwk.key_ops) &&
      rawJwk.key_ops.some((op) => typeof op !== 'string' || op !== 'verify')
    ) {
      return {
        error: `trustSnapshot.trustedKeys["${keyId}"] must only permit public verification`,
      }
    }
    keys[keyId] = rawJwk as JsonWebKey
  }
  return { keys }
}

function validateKeyValidityMap(rawValidity: unknown): {
  validity?: Record<string, KeyValidityWindow>
  error?: string
} {
  if (!isPlainObject(rawValidity)) {
    return { error: 'trustSnapshot.keyValidity must be a JSON object' }
  }
  const out: Record<string, KeyValidityWindow> = {}
  for (const [keyId, rawWindow] of Object.entries(rawValidity)) {
    if (!isPlainObject(rawWindow)) {
      return { error: `trustSnapshot.keyValidity["${keyId}"] must be an object` }
    }
    const keys = Object.keys(rawWindow)
    if (keys.some((k) => k !== 'notBefore' && k !== 'notAfter')) {
      return { error: `trustSnapshot.keyValidity["${keyId}"] contains unsupported fields` }
    }
    const win: KeyValidityWindow = {}
    if (rawWindow.notBefore !== undefined) {
      if (typeof rawWindow.notBefore !== 'string' || Number.isNaN(Date.parse(rawWindow.notBefore))) {
        return { error: `trustSnapshot.keyValidity["${keyId}"].notBefore must be an ISO timestamp` }
      }
      win.notBefore = rawWindow.notBefore
    }
    if (rawWindow.notAfter !== undefined) {
      if (typeof rawWindow.notAfter !== 'string' || Number.isNaN(Date.parse(rawWindow.notAfter))) {
        return { error: `trustSnapshot.keyValidity["${keyId}"].notAfter must be an ISO timestamp` }
      }
      win.notAfter = rawWindow.notAfter
    }
    out[keyId] = win
  }
  return { validity: out }
}

function validateUnsignedReceiptObject(
  rawReceipt: unknown,
  evaluationDate: Date,
): { receipt?: VerificationReceipt; error?: string } {
  if (!isPlainObject(rawReceipt)) {
    return { error: 'bundle.receipt must be a JSON object' }
  }
  if (rawReceipt.version !== 1) {
    return { error: 'bundle.receipt version must be 1' }
  }
  if (typeof rawReceipt.verifiedAt !== 'string' || Number.isNaN(Date.parse(rawReceipt.verifiedAt))) {
    return { error: 'bundle.receipt verifiedAt must be a valid ISO timestamp' }
  }
  if (!isPlainObject(rawReceipt.manifest)) {
    return { error: 'bundle.receipt.manifest must be a JSON object' }
  }
  let receiptManifest: ProofManifest
  try {
    receiptManifest = parseManifest(JSON.stringify(rawReceipt.manifest))
  } catch {
    return { error: 'bundle.receipt.manifest is invalid' }
  }
  if (!isPlainObject(rawReceipt.transaction)) {
    return { error: 'bundle.receipt.transaction must be a JSON object' }
  }
  const tx = rawReceipt.transaction
  if (
    typeof tx.txHash !== 'string' ||
    !/^[0-9a-fA-F]{64}$/.test(tx.txHash) ||
    typeof tx.status !== 'string' ||
    !['confirmed', 'failed', 'missing', 'pending'].includes(tx.status)
  ) {
    return { error: 'bundle.receipt.transaction is malformed' }
  }

  let chainRecord: ChainProofRecord | null = null
  if (rawReceipt.chainRecord !== null) {
    if (!isPlainObject(rawReceipt.chainRecord)) {
      return { error: 'bundle.receipt.chainRecord must be an object or null' }
    }
    const cr = rawReceipt.chainRecord
    if (
      typeof cr.videoHash !== 'string' ||
      !/^[0-9a-fA-F]{64}$/.test(cr.videoHash) ||
      typeof cr.metadataHash !== 'string' ||
      !/^[0-9a-fA-F]{64}$/.test(cr.metadataHash) ||
      typeof cr.tier !== 'number' ||
      typeof cr.status !== 'number' ||
      typeof cr.createdAt !== 'string'
    ) {
      return { error: 'bundle.receipt.chainRecord fields are invalid' }
    }
    chainRecord = {
      videoHash: cr.videoHash,
      metadataHash: cr.metadataHash,
      tier: cr.tier,
      status: cr.status,
      createdAt: cr.createdAt,
      expiresAt: typeof cr.expiresAt === 'string' ? cr.expiresAt : undefined,
      source: typeof cr.source === 'string' || cr.source === null ? cr.source : null,
      issuer: typeof cr.issuer === 'string' || cr.issuer === null ? cr.issuer : null,
    }
  }

  const txVerification: TransactionVerification = {
    txHash: tx.txHash,
    status: tx.status as TransactionVerification['status'],
    contractMatch: typeof tx.contractMatch === 'boolean' ? tx.contractMatch : undefined,
    ledger: typeof tx.ledger === 'number' ? tx.ledger : undefined,
    createdAt: typeof tx.createdAt === 'number' ? tx.createdAt : undefined,
  }

  const recomputed = classifyVerification(
    receiptManifest,
    txVerification,
    chainRecord,
    Math.floor(evaluationDate.getTime() / 1000),
  )
  if (rawReceipt.result !== 'valid' || recomputed !== 'valid') {
    return {
      error: `bundle.receipt does not establish valid evidence (recorded=${String(rawReceipt.result)}, evaluated=${recomputed})`,
    }
  }

  return {
    receipt: {
      version: 1,
      verifiedAt: rawReceipt.verifiedAt,
      manifest: receiptManifest,
      transaction: txVerification,
      chainRecord,
      result: 'valid',
    },
  }
}

async function evaluateOfflineLineageSnapshot(
  outputDigest: string,
  rawSnapshot: unknown,
): Promise<{ result?: LineageTreeResult; error?: string }> {
  if (!isPlainObject(rawSnapshot)) {
    return { error: 'trustSnapshot.lineageSnapshot must be an object' }
  }
  if (!isPlainObject(rawSnapshot.records) || !isPlainObject(rawSnapshot.proofStatuses)) {
    return { error: 'trustSnapshot.lineageSnapshot requires records and proofStatuses maps' }
  }

  const recordsMap = new Map<string, LineageRecord | null>()
  for (const [rawDigest, rawRec] of Object.entries(rawSnapshot.records)) {
    let normDigest: string
    try {
      normDigest = asHex32(rawDigest, 'lineage digest').toLowerCase()
    } catch {
      return { error: 'trustSnapshot.lineageSnapshot contains a non-hex32 record key' }
    }
    if (rawRec === null) {
      recordsMap.set(normDigest, null)
    } else if (isPlainObject(rawRec)) {
      if (
        !Array.isArray(rawRec.parentProofIds) ||
        rawRec.parentProofIds.some((id) => typeof id !== 'string' || !/^[0-9a-fA-F]{64}$/.test(id)) ||
        typeof rawRec.operationType !== 'string'
      ) {
        return { error: 'trustSnapshot.lineageSnapshot record entry is malformed' }
      }
      recordsMap.set(normDigest, {
        outputDigest: normDigest,
        parentProofIds: (rawRec.parentProofIds as string[]).map((p) => p.toLowerCase()),
        parentCommitments: Array.isArray(rawRec.parentCommitments)
          ? (rawRec.parentCommitments as unknown[]).map((c) => String(c))
          : [],
        manifestDigest: typeof rawRec.manifestDigest === 'string' ? rawRec.manifestDigest : '',
        actor: typeof rawRec.actor === 'string' ? rawRec.actor : '',
        operationType: rawRec.operationType,
        depth: typeof rawRec.depth === 'number' ? rawRec.depth : 1,
      })
    } else {
      return { error: 'trustSnapshot.lineageSnapshot record entry must be an object or null' }
    }
  }

  const statusMap = new Map<string, ProofStatus>()
  for (const [rawId, rawStatus] of Object.entries(rawSnapshot.proofStatuses)) {
    let normId: string
    try {
      normId = asHex32(rawId, 'proofId').toLowerCase()
    } catch {
      return { error: 'trustSnapshot.lineageSnapshot contains a non-hex32 proofStatuses key' }
    }
    if (typeof rawStatus !== 'string' || !ALLOWED_PROOF_STATUSES.has(rawStatus as ProofStatus)) {
      return { error: 'trustSnapshot.lineageSnapshot contains an invalid proof status' }
    }
    statusMap.set(normId, rawStatus as ProofStatus)
  }

  const result = await verifyLineageTree(outputDigest, {
    getLineage: async (digest: string) => recordsMap.get(digest.toLowerCase()) ?? null,
    getProofStatus: async (proofId: string) => statusMap.get(proofId.toLowerCase()) ?? 'missing',
  })
  if (!result.success) {
    return {
      result,
      error: result.failureReason ?? 'lineage snapshot verification failed',
    }
  }
  return { result }
}

/**
 * Validate a self-contained verification bundle (manifest, receipt / signed
 * receipt, and trust snapshot) completely offline while reporting online-only
 * checks explicitly as `unavailable`.
 */
export async function verifyOfflineBundle(
  rawBundle: unknown,
  options: VerifyOfflineBundleOptions = {},
): Promise<BundleVerificationReport> {
  const evaluationDate = options.now ?? new Date()
  const checks: BundleCheckEntry[] = []
  const failureReasons: string[] = []

  const finalize = (params: {
    manifest?: ProofManifest | null
    manifestDigest?: string | null
    trustSnapshotCapturedAt?: string | null
    lineage?: LineageTreeResult
    overrideStatus?: BundleOverallStatus
  }): BundleVerificationReport => {
    const offlineFailed = checks.some((c) => c.scope === 'offline' && c.status === 'failed')
    const allChecks = [...checks, ...buildOnlineOnlyChecks()]

    let overallStatus: BundleOverallStatus = params.overrideStatus ?? (offlineFailed ? 'invalid' : 'offline_verified')
    if (offlineFailed && overallStatus === 'offline_verified') {
      overallStatus = 'invalid'
    }

    const exitCode: 0 | 4 | 5 | 8 =
      overallStatus === 'offline_verified'
        ? 0
        : overallStatus === 'network_mismatch'
          ? 4
          : overallStatus === 'contract_mismatch'
            ? 5
            : 8

    return {
      protocol: BUNDLE_REPORT_PROTOCOL,
      version: BUNDLE_REPORT_VERSION,
      mode: 'offline',
      bundleValid: overallStatus === 'offline_verified',
      overallStatus,
      exitCode,
      onlineChecksStatus: 'unavailable',
      proofId: params.manifest?.proofId ?? null,
      tier: params.manifest?.tier ?? null,
      network: params.manifest?.network ?? null,
      contractId: params.manifest?.contractId ?? null,
      manifestDigest: params.manifestDigest ?? null,
      trustSnapshotCapturedAt: params.trustSnapshotCapturedAt ?? null,
      checks: allChecks,
      onlineChecks: {
        liveRpcTransactionLookup: 'unavailable',
        liveContractStateSimulation: 'unavailable',
        liveRevocationAndDisputeCheck: 'unavailable',
      },
      ...(params.lineage ? { lineage: params.lineage } : {}),
      failureReasons,
    }
  }

  // 1. Bundle integrity & privacy check
  if (!isPlainObject(rawBundle)) {
    const reason = 'verification bundle must be a JSON object'
    checks.push({ id: 'bundle_integrity', scope: 'offline', status: 'failed', detail: reason })
    failureReasons.push(reason)
    return finalize({})
  }

  const prohibited = findProhibitedMaterial(rawBundle)
  if (prohibited) {
    checks.push({ id: 'bundle_integrity', scope: 'offline', status: 'failed', detail: prohibited })
    failureReasons.push(prohibited)
    return finalize({})
  }

  if (Object.keys(rawBundle).some((key) => !ALLOWED_BUNDLE_FIELDS.has(key))) {
    const reason = 'verification bundle contains unsupported top-level fields'
    checks.push({ id: 'bundle_integrity', scope: 'offline', status: 'failed', detail: reason })
    failureReasons.push(reason)
    return finalize({})
  }

  if (
    rawBundle.protocol !== VERIFICATION_BUNDLE_PROTOCOL ||
    rawBundle.version !== VERIFICATION_BUNDLE_VERSION
  ) {
    const reason = 'unsupported verification bundle protocol or version'
    checks.push({ id: 'bundle_integrity', scope: 'offline', status: 'failed', detail: reason })
    failureReasons.push(reason)
    return finalize({})
  }

  if (rawBundle.signedReceipt === undefined && rawBundle.receipt === undefined) {
    const reason = 'verification bundle must contain signedReceipt or receipt'
    checks.push({ id: 'bundle_integrity', scope: 'offline', status: 'failed', detail: reason })
    failureReasons.push(reason)
    return finalize({})
  }

  checks.push({
    id: 'bundle_integrity',
    scope: 'offline',
    status: 'passed',
    detail: 'bundle schema, version, and privacy boundaries validated',
  })

  // 2. Manifest validation
  let manifest: ProofManifest
  let manifestDigest: string
  try {
    if (!isPlainObject(rawBundle.manifest)) {
      throw new Error('bundle.manifest must be a JSON object')
    }
    manifest = parseManifest(JSON.stringify(rawBundle.manifest))
    manifestDigest = computeManifestDigest(manifest)
    checks.push({
      id: 'manifest_validation',
      scope: 'offline',
      status: 'passed',
      detail: `canonical manifest v${manifest.version} validated (${manifestDigest.slice(0, 16)}...)`,
    })
  } catch (err) {
    const reason = err instanceof Error ? err.message : 'invalid manifest in bundle'
    checks.push({ id: 'manifest_validation', scope: 'offline', status: 'failed', detail: reason })
    failureReasons.push(reason)
    return finalize({})
  }

  // Check explicit caller deployment overrides (--contract-id / --network / --proof-id)
  if (options.expectedContractId !== undefined) {
    if (manifest.contractId !== options.expectedContractId) {
      const reason = 'bundle contractId does not match expected --contract-id'
      checks.push({
        id: 'statement_consistency',
        scope: 'offline',
        status: 'failed',
        detail: reason,
      })
      failureReasons.push(reason)
      return finalize({
        manifest,
        manifestDigest,
        overrideStatus: 'contract_mismatch',
      })
    }
  }

  if (options.expectedNetwork !== undefined) {
    const expectedNet = resolveNetwork(options.expectedNetwork)
    if (manifest.network !== expectedNet) {
      const reason = 'bundle network does not match expected --network'
      checks.push({
        id: 'statement_consistency',
        scope: 'offline',
        status: 'failed',
        detail: reason,
      })
      failureReasons.push(reason)
      return finalize({
        manifest,
        manifestDigest,
        overrideStatus: 'network_mismatch',
      })
    }
  }

  if (
    options.expectedProofId !== undefined &&
    manifest.proofId.toLowerCase() !== options.expectedProofId.toLowerCase()
  ) {
    const reason = 'bundle proofId does not match expected --proof-id'
    checks.push({ id: 'statement_consistency', scope: 'offline', status: 'failed', detail: reason })
    failureReasons.push(reason)
    return finalize({ manifest, manifestDigest })
  }

  // 3. Trust snapshot validation
  if (!isPlainObject(rawBundle.trustSnapshot)) {
    const reason = 'bundle.trustSnapshot must be a JSON object'
    checks.push({
      id: 'trust_snapshot_validation',
      scope: 'offline',
      status: 'failed',
      detail: reason,
    })
    failureReasons.push(reason)
    return finalize({ manifest, manifestDigest })
  }

  const rawSnapshot = rawBundle.trustSnapshot
  if (Object.keys(rawSnapshot).some((k) => !ALLOWED_SNAPSHOT_FIELDS.has(k))) {
    const reason = 'bundle.trustSnapshot contains unsupported fields'
    checks.push({
      id: 'trust_snapshot_validation',
      scope: 'offline',
      status: 'failed',
      detail: reason,
    })
    failureReasons.push(reason)
    return finalize({ manifest, manifestDigest })
  }

  const capturedAt = rawSnapshot.capturedAt
  if (typeof capturedAt !== 'string' || Number.isNaN(Date.parse(capturedAt))) {
    const reason = 'trustSnapshot.capturedAt must be a valid ISO timestamp'
    checks.push({
      id: 'trust_snapshot_validation',
      scope: 'offline',
      status: 'failed',
      detail: reason,
    })
    failureReasons.push(reason)
    return finalize({ manifest, manifestDigest })
  }

  const rawSnapshotNetwork = rawSnapshot.network ?? rawSnapshot.networkPassphrase
  if (typeof rawSnapshotNetwork !== 'string' || !rawSnapshotNetwork.trim()) {
    const reason = 'trustSnapshot.network must be a non-empty string'
    checks.push({
      id: 'trust_snapshot_validation',
      scope: 'offline',
      status: 'failed',
      detail: reason,
    })
    failureReasons.push(reason)
    return finalize({ manifest, manifestDigest, trustSnapshotCapturedAt: capturedAt })
  }
  const snapshotNetwork = resolveNetwork(rawSnapshotNetwork)

  if (typeof rawSnapshot.contractId !== 'string' || !StrKey.isValidContract(rawSnapshot.contractId)) {
    const reason = 'trustSnapshot.contractId must be a valid Stellar contract ID'
    checks.push({
      id: 'trust_snapshot_validation',
      scope: 'offline',
      status: 'failed',
      detail: reason,
    })
    failureReasons.push(reason)
    return finalize({ manifest, manifestDigest, trustSnapshotCapturedAt: capturedAt })
  }

  if (!StrKey.isValidContract(manifest.contractId)) {
    const reason = 'manifest.contractId must be a valid Stellar contract ID'
    checks.push({
      id: 'trust_snapshot_validation',
      scope: 'offline',
      status: 'failed',
      detail: reason,
    })
    failureReasons.push(reason)
    return finalize({ manifest, manifestDigest, trustSnapshotCapturedAt: capturedAt })
  }

  if (snapshotNetwork !== manifest.network || rawSnapshot.contractId !== manifest.contractId) {
    const reason = 'trustSnapshot deployment binding disagrees with manifest network or contractId'
    checks.push({
      id: 'trust_snapshot_validation',
      scope: 'offline',
      status: 'failed',
      detail: reason,
    })
    failureReasons.push(reason)
    return finalize({ manifest, manifestDigest, trustSnapshotCapturedAt: capturedAt })
  }

  if (rawSnapshot.manifestDigest !== undefined) {
    if (
      typeof rawSnapshot.manifestDigest !== 'string' ||
      !/^[0-9a-fA-F]{64}$/.test(rawSnapshot.manifestDigest) ||
      rawSnapshot.manifestDigest.toLowerCase() !== manifestDigest.toLowerCase()
    ) {
      const reason = 'trustSnapshot.manifestDigest does not match canonical manifest digest'
      checks.push({
        id: 'trust_snapshot_validation',
        scope: 'offline',
        status: 'failed',
        detail: reason,
      })
      failureReasons.push(reason)
      return finalize({ manifest, manifestDigest, trustSnapshotCapturedAt: capturedAt })
    }
  }

  if (rawSnapshot.expectedTier !== undefined) {
    if (
      typeof rawSnapshot.expectedTier !== 'string' ||
      !ALLOWED_TIERS.has(rawSnapshot.expectedTier) ||
      rawSnapshot.expectedTier !== manifest.tier
    ) {
      const reason = 'trustSnapshot.expectedTier does not match manifest identity tier'
      checks.push({
        id: 'trust_snapshot_validation',
        scope: 'offline',
        status: 'failed',
        detail: reason,
      })
      failureReasons.push(reason)
      return finalize({ manifest, manifestDigest, trustSnapshotCapturedAt: capturedAt })
    }
  }

  if (rawSnapshot.verifierScope !== undefined) {
    if (typeof rawSnapshot.verifierScope !== 'string' || rawSnapshot.verifierScope !== (manifest.verifierScope ?? '0')) {
      const reason = 'trustSnapshot.verifierScope does not match manifest verifierScope'
      checks.push({
        id: 'trust_snapshot_validation',
        scope: 'offline',
        status: 'failed',
        detail: reason,
      })
      failureReasons.push(reason)
      return finalize({ manifest, manifestDigest, trustSnapshotCapturedAt: capturedAt })
    }
  }

  let trustedKeys: Record<string, JsonWebKey> = {}
  if (rawSnapshot.trustedKeys !== undefined) {
    const keyValidation = validatePublicJwkMap(rawSnapshot.trustedKeys)
    if (keyValidation.error || !keyValidation.keys) {
      const reason = keyValidation.error ?? 'invalid trustSnapshot.trustedKeys'
      checks.push({
        id: 'trust_snapshot_validation',
        scope: 'offline',
        status: 'failed',
        detail: reason,
      })
      failureReasons.push(reason)
      return finalize({ manifest, manifestDigest, trustSnapshotCapturedAt: capturedAt })
    }
    trustedKeys = keyValidation.keys
  }

  let keyValidity: Record<string, KeyValidityWindow> | undefined
  if (rawSnapshot.keyValidity !== undefined) {
    const validityCheck = validateKeyValidityMap(rawSnapshot.keyValidity)
    if (validityCheck.error) {
      checks.push({
        id: 'trust_snapshot_validation',
        scope: 'offline',
        status: 'failed',
        detail: validityCheck.error,
      })
      failureReasons.push(validityCheck.error)
      return finalize({ manifest, manifestDigest, trustSnapshotCapturedAt: capturedAt })
    }
    keyValidity = validityCheck.validity
  }

  checks.push({
    id: 'trust_snapshot_validation',
    scope: 'offline',
    status: 'passed',
    detail: `trust snapshot captured at ${capturedAt} matches deployment and policy bindings`,
  })

  // 4. Signed receipt and/or local receipt validation + statement consistency
  let validatedSignedReceipt: SignedVerificationReceipt | undefined
  if (rawBundle.signedReceipt !== undefined) {
    try {
      const decoded: SignedVerificationReceipt =
        typeof rawBundle.signedReceipt === 'string'
          ? decodeReceiptFromQr(rawBundle.signedReceipt.trim())
          : (rawBundle.signedReceipt as SignedVerificationReceipt)

      const sigResult = await verifyVerificationReceipt(decoded, {
        keys: trustedKeys,
        expectedNetworkPassphrase: manifest.network,
        expectedProofId: manifest.proofId,
        keyValidity,
        now: evaluationDate,
      })

      if (!sigResult.valid) {
        checks.push({
          id: 'signed_receipt_signature',
          scope: 'offline',
          status: 'failed',
          detail: sigResult.reason,
        })
        failureReasons.push(sigResult.reason)
      } else if (sigResult.receipt.result !== 'verified') {
        const reason = 'signedReceipt result is "unverified"'
        checks.push({
          id: 'signed_receipt_signature',
          scope: 'offline',
          status: 'failed',
          detail: reason,
        })
        failureReasons.push(reason)
      } else {
        validatedSignedReceipt = sigResult.receipt
        checks.push({
          id: 'signed_receipt_signature',
          scope: 'offline',
          status: 'passed',
          detail: `ECDSA P-256 signature verified with trusted key "${sigResult.receipt.signer.keyId}"`,
        })
      }
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'invalid signedReceipt'
      checks.push({
        id: 'signed_receipt_signature',
        scope: 'offline',
        status: 'failed',
        detail: reason,
      })
      failureReasons.push(reason)
    }
  }

  let validatedReceipt: VerificationReceipt | undefined
  if (rawBundle.receipt !== undefined) {
    const receiptCheck = validateUnsignedReceiptObject(rawBundle.receipt, evaluationDate)
    if (receiptCheck.error || !receiptCheck.receipt) {
      const reason = receiptCheck.error ?? 'invalid bundle.receipt'
      checks.push({
        id: 'receipt_validation',
        scope: 'offline',
        status: 'failed',
        detail: reason,
      })
      failureReasons.push(reason)
    } else {
      validatedReceipt = receiptCheck.receipt
      checks.push({
        id: 'receipt_validation',
        scope: 'offline',
        status: 'passed',
        detail: `captured receipt verifiedAt ${validatedReceipt.verifiedAt} classified as valid`,
      })
    }
  }

  // 5. Cross-artifact statement consistency check
  const consistencyErrors: string[] = []
  if (validatedSignedReceipt) {
    if (validatedSignedReceipt.proofId.toLowerCase() !== manifest.proofId.toLowerCase()) {
      consistencyErrors.push('signedReceipt.proofId does not match manifest.proofId')
    }
    if (validatedSignedReceipt.videoHash.toLowerCase() !== manifest.videoHash.toLowerCase()) {
      consistencyErrors.push('signedReceipt.videoHash does not match manifest.videoHash')
    }
    if (validatedSignedReceipt.metadataHash.toLowerCase() !== manifest.metadataHash.toLowerCase()) {
      consistencyErrors.push('signedReceipt.metadataHash does not match manifest.metadataHash')
    }
    if (validatedSignedReceipt.tier !== manifest.tier) {
      consistencyErrors.push('signedReceipt.tier does not match manifest.tier')
    }
    if (validatedSignedReceipt.networkPassphrase !== manifest.network) {
      consistencyErrors.push('signedReceipt.networkPassphrase does not match manifest.network')
    }
    if (validatedSignedReceipt.contractId !== manifest.contractId) {
      consistencyErrors.push('signedReceipt.contractId does not match manifest.contractId')
    }
    if (
      validatedSignedReceipt.transactionHash !== null &&
      validatedSignedReceipt.transactionHash.toLowerCase() !== manifest.transactionRef.toLowerCase()
    ) {
      consistencyErrors.push('signedReceipt.transactionHash does not match manifest.transactionRef')
    }
  }

  if (validatedReceipt) {
    if (serializeManifest(validatedReceipt.manifest) !== serializeManifest(manifest)) {
      consistencyErrors.push('bundle.receipt.manifest does not match canonical bundle.manifest')
    }
    if (
      validatedReceipt.transaction.txHash.toLowerCase() !== manifest.transactionRef.toLowerCase()
    ) {
      consistencyErrors.push('bundle.receipt.transaction.txHash does not match manifest.transactionRef')
    }
  }

  if (consistencyErrors.length > 0) {
    const joined = consistencyErrors.join('; ')
    checks.push({
      id: 'statement_consistency',
      scope: 'offline',
      status: 'failed',
      detail: joined,
    })
    failureReasons.push(...consistencyErrors)
  } else if (validatedSignedReceipt || validatedReceipt) {
    checks.push({
      id: 'statement_consistency',
      scope: 'offline',
      status: 'passed',
      detail: 'manifest, receipt, and trust snapshot statement fields and identity tier match',
    })
  }

  // 6. Optional offline lineage snapshot traversal
  let lineageResult: LineageTreeResult | undefined
  if (rawSnapshot.lineageSnapshot !== undefined) {
    const lineageEval = await evaluateOfflineLineageSnapshot(
      manifest.videoHash,
      rawSnapshot.lineageSnapshot,
    )
    lineageResult = lineageEval.result
    if (lineageEval.error) {
      checks.push({
        id: 'lineage_snapshot',
        scope: 'offline',
        status: 'failed',
        detail: lineageEval.error,
      })
      failureReasons.push(lineageEval.error)
    } else {
      checks.push({
        id: 'lineage_snapshot',
        scope: 'offline',
        status: 'passed',
        detail: 'offline lineage snapshot verified back to registered originals',
      })
    }
  }

  return finalize({
    manifest,
    manifestDigest,
    trustSnapshotCapturedAt: capturedAt,
    lineage: lineageResult,
  })
}

export function formatBundleVerificationReport(report: BundleVerificationReport): string {
  const statusHeadline =
    report.overallStatus === 'offline_verified'
      ? 'VALID (offline bundle checks passed)'
      : report.overallStatus === 'network_mismatch'
        ? 'NETWORK MISMATCH'
        : report.overallStatus === 'contract_mismatch'
          ? 'CONTRACT MISMATCH'
          : 'INVALID'

  const lines: string[] = [
    'Harpocrates Offline Verification Bundle Report',
    `  Mode:                offline (self-contained local bundle)`,
    `  Bundle Status:       ${statusHeadline}`,
    `  Online-Only Checks:  UNAVAILABLE (no live Stellar RPC queries performed)`,
  ]

  if (report.proofId) lines.push(`  Proof ID:            ${report.proofId}`)
  if (report.tier) lines.push(`  Tier:                ${report.tier}`)
  if (report.network) lines.push(`  Network:             ${report.network}`)
  if (report.contractId) lines.push(`  Contract:            ${report.contractId}`)
  if (report.manifestDigest) lines.push(`  Manifest Digest:     ${report.manifestDigest}`)
  if (report.trustSnapshotCapturedAt) {
    lines.push(`  Trust Snapshot At:   ${report.trustSnapshotCapturedAt}`)
  }

  const offlineChecks = report.checks.filter((c) => c.scope === 'offline')
  const onlineChecks = report.checks.filter((c) => c.scope === 'online_only')

  lines.push('', 'Offline checks:')
  for (const check of offlineChecks) {
    lines.push(`  [${check.status.toUpperCase()}] ${check.id}: ${check.detail}`)
  }

  lines.push('', 'Online-only checks (explicitly unavailable offline):')
  for (const check of onlineChecks) {
    lines.push(`  [${check.status.toUpperCase()}] ${check.id}: ${check.detail}`)
  }

  if (report.failureReasons.length > 0) {
    lines.push('', `Failure reasons: ${report.failureReasons.join('; ')}`)
  }

  return lines.join('\n')
}
