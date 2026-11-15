import { StrKey } from '@stellar/stellar-sdk'
import { assertC2paInputWithinLimit, parseC2paReceiptInput } from './c2pa.js'
import { canonicalHash } from './hashing.js'
import { parseManifest, type ProofManifest } from './manifest.js'
import { ALLOWED_TIERS, type IdentityTier } from './metadata.js'
import { resolveNetwork } from './network.js'
import type { VerificationReceipt } from './receipt.js'
import {
  verifyVerificationReceipt,
  type SignedVerificationReceipt,
} from './signed-receipt.js'

export const POLICY_COMPARISON_PROTOCOL = 'harpocrates-policy-comparison' as const
export const POLICY_COMPARISON_VERSION = 1 as const

export type TrustPolicy = {
  protocol?: 'harpocrates-trust-policy'
  version: 1
  name?: string
  allowedNetworks?: string[]
  allowedContractIds?: string[]
  allowedTiers?: IdentityTier[]
  minimumTier?: IdentityTier
  allowedVerifierScopes?: string[]
  requireOnChainConfirmation?: boolean
  requireSignedReceipt?: boolean
  trustedKeys?: Record<string, JsonWebKey>
  keyValidity?: Record<string, { notBefore?: string; notAfter?: string }>
  maxReceiptAgeSeconds?: number
  requireLineageVerified?: boolean
}

export type PolicyDecisionOutcome = 'trusted' | 'rejected' | 'incomplete'

export type PolicyEvaluationDecision = {
  trusted: boolean
  outcome: PolicyDecisionOutcome
  failedRules: string[]
}

export type EvidencePolicyComparisonItem = {
  index: number
  proofId: string
  tier: IdentityTier
  network: string
  contractId: string
  policyA: PolicyEvaluationDecision
  policyB: PolicyEvaluationDecision
  decisionChanged: boolean
  reasonsChanged: boolean
  transition: 'unchanged' | 'newly_trusted' | 'newly_rejected' | 'outcome_changed'
}

export type PolicyComparisonReport = {
  protocol: typeof POLICY_COMPARISON_PROTOCOL
  version: typeof POLICY_COMPARISON_VERSION
  identicalDecisions: boolean
  decisionChangedCount: number
  totalItems: number
  evidenceDigest: string
  policyADigest: string
  policyBDigest: string
  policyAName: string | null
  policyBName: string | null
  items: EvidencePolicyComparisonItem[]
  changedDecisions: EvidencePolicyComparisonItem[]
}

export type ComparePoliciesOptions = {
  now?: Date
}

type NormalizedEvidenceItem = {
  proofId: string
  videoHash: string
  metadataHash: string
  tier: IdentityTier
  network: string
  contractId: string
  verifierScope: string | null
  manifest: ProofManifest | null
  receipt: VerificationReceipt | null
  signedReceipt: SignedVerificationReceipt | null
  lineageSuccess: boolean | null
}

const TIER_RANK: Record<IdentityTier, number> = {
  silent: 1,
  source: 2,
  seal: 3,
}

const SCOPE_RE = /^(0|[1-9][0-9]*)$/
const HEX32_RE = /^[0-9a-fA-F]{64}$/
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

function containsPrivateFields(value: unknown, depth = 0): boolean {
  if (depth > 8) return false
  if (Array.isArray(value)) {
    return value.some((item) => containsPrivateFields(item, depth + 1))
  }
  if (!isPlainObject(value)) return false
  for (const [k, v] of Object.entries(value)) {
    if (FORBIDDEN_PRIVATE_KEYS.has(k)) return true
    if (containsPrivateFields(v, depth + 1)) return true
  }
  return false
}

export function parseTrustPolicy(rawJson: string): TrustPolicy {
  assertC2paInputWithinLimit(rawJson, 'policy')
  let parsed: unknown
  try {
    parsed = JSON.parse(rawJson)
  } catch {
    throw new Error('policy is not valid JSON')
  }
  return validateTrustPolicyObject(parsed)
}

export function validateTrustPolicyObject(input: unknown): TrustPolicy {
  if (!isPlainObject(input)) {
    throw new Error('policy must be a JSON object')
  }
  if (containsPrivateFields(input)) {
    throw new Error('policy contains forbidden private or secret fields')
  }

  const allowedKeys = new Set([
    'protocol',
    'version',
    'name',
    'allowedNetworks',
    'allowedContractIds',
    'allowedTiers',
    'minimumTier',
    'allowedVerifierScopes',
    'requireOnChainConfirmation',
    'requireSignedReceipt',
    'trustedKeys',
    'keyValidity',
    'maxReceiptAgeSeconds',
    'requireLineageVerified',
  ])
  for (const key of Object.keys(input)) {
    if (!allowedKeys.has(key)) {
      throw new Error(`unsupported policy field: ${key}`)
    }
  }

  if (input.protocol !== undefined && input.protocol !== 'harpocrates-trust-policy') {
    throw new Error('unsupported policy protocol')
  }
  if (input.version !== 1) {
    throw new Error('unsupported policy version')
  }
  if (input.name !== undefined && (typeof input.name !== 'string' || input.name.length > 128)) {
    throw new Error('policy.name must be a string up to 128 characters')
  }
  if (input.allowedNetworks !== undefined) {
    if (
      !Array.isArray(input.allowedNetworks) ||
      input.allowedNetworks.some((n) => typeof n !== 'string' || n.trim() === '')
    ) {
      throw new Error('policy.allowedNetworks must be an array of non-empty strings')
    }
  }
  if (input.allowedContractIds !== undefined) {
    if (
      !Array.isArray(input.allowedContractIds) ||
      input.allowedContractIds.some((c) => typeof c !== 'string' || !StrKey.isValidContract(c))
    ) {
      throw new Error('policy.allowedContractIds must contain valid Stellar contract IDs')
    }
  }
  if (input.allowedTiers !== undefined) {
    if (
      !Array.isArray(input.allowedTiers) ||
      input.allowedTiers.some((t) => typeof t !== 'string' || !ALLOWED_TIERS.has(t))
    ) {
      throw new Error('policy.allowedTiers contains an invalid identity tier')
    }
  }
  if (
    input.minimumTier !== undefined &&
    (typeof input.minimumTier !== 'string' || !ALLOWED_TIERS.has(input.minimumTier))
  ) {
    throw new Error('policy.minimumTier is invalid')
  }
  if (input.allowedVerifierScopes !== undefined) {
    if (
      !Array.isArray(input.allowedVerifierScopes) ||
      input.allowedVerifierScopes.some((s) => typeof s !== 'string' || !SCOPE_RE.test(s))
    ) {
      throw new Error('policy.allowedVerifierScopes must contain non-negative integer strings')
    }
  }
  for (const boolKey of [
    'requireOnChainConfirmation',
    'requireSignedReceipt',
    'requireLineageVerified',
  ] as const) {
    if (input[boolKey] !== undefined && typeof input[boolKey] !== 'boolean') {
      throw new Error(`policy.${boolKey} must be a boolean`)
    }
  }
  if (input.maxReceiptAgeSeconds !== undefined) {
    if (
      !Number.isSafeInteger(input.maxReceiptAgeSeconds) ||
      (input.maxReceiptAgeSeconds as number) <= 0
    ) {
      throw new Error('policy.maxReceiptAgeSeconds must be a positive integer')
    }
  }
  if (input.trustedKeys !== undefined) {
    if (!isPlainObject(input.trustedKeys)) {
      throw new Error('policy.trustedKeys must be a JSON object')
    }
    for (const [kid, jwk] of Object.entries(input.trustedKeys)) {
      if (kid.trim() === '' || !isPlainObject(jwk)) {
        throw new Error('policy.trustedKeys entries must be JWK objects')
      }
      if ('d' in jwk) {
        throw new Error('policy.trustedKeys must not contain private key material')
      }
    }
  }
  if (input.keyValidity !== undefined) {
    if (!isPlainObject(input.keyValidity)) {
      throw new Error('policy.keyValidity must be a JSON object')
    }
    for (const validity of Object.values(input.keyValidity)) {
      if (!isPlainObject(validity)) {
        throw new Error('policy.keyValidity entry must be an object')
      }
      if (validity.notBefore !== undefined && (typeof validity.notBefore !== 'string' || Number.isNaN(Date.parse(validity.notBefore)))) {
        throw new Error('policy.keyValidity.notBefore must be a valid ISO timestamp')
      }
      if (validity.notAfter !== undefined && (typeof validity.notAfter !== 'string' || Number.isNaN(Date.parse(validity.notAfter)))) {
        throw new Error('policy.keyValidity.notAfter must be a valid ISO timestamp')
      }
    }
  }

  // Deep-clone so caller-supplied policy objects can never be mutated.
  return structuredClone(input) as unknown as TrustPolicy
}

function parseSingleEvidenceObject(obj: Record<string, unknown>): NormalizedEvidenceItem {
  if (containsPrivateFields(obj)) {
    throw new Error('bundle contains forbidden private or secret fields')
  }

  // Standalone SignedVerificationReceipt
  if (obj.protocol === 'harpocrates-verification-receipt') {
    if (
      typeof obj.proofId !== 'string' ||
      !HEX32_RE.test(obj.proofId) ||
      typeof obj.videoHash !== 'string' ||
      !HEX32_RE.test(obj.videoHash) ||
      typeof obj.metadataHash !== 'string' ||
      !HEX32_RE.test(obj.metadataHash) ||
      typeof obj.tier !== 'string' ||
      !ALLOWED_TIERS.has(obj.tier) ||
      typeof obj.networkPassphrase !== 'string' ||
      typeof obj.contractId !== 'string'
    ) {
      throw new Error('signed receipt in bundle is malformed')
    }
    return {
      proofId: obj.proofId.toLowerCase(),
      videoHash: obj.videoHash.toLowerCase(),
      metadataHash: obj.metadataHash.toLowerCase(),
      tier: obj.tier as IdentityTier,
      network: obj.networkPassphrase,
      contractId: obj.contractId,
      verifierScope: null,
      manifest: null,
      receipt: null,
      signedReceipt: structuredClone(obj) as unknown as SignedVerificationReceipt,
      lineageSuccess: null,
    }
  }

  // Standalone VerificationReceipt
  if (
    obj.version === 1 &&
    isPlainObject(obj.manifest) &&
    isPlainObject(obj.transaction) &&
    typeof obj.result === 'string' &&
    !('receipt' in obj) &&
    !('signedReceipt' in obj) &&
    obj.protocol === undefined
  ) {
    const receipt = parseC2paReceiptInput(obj)
    return {
      proofId: receipt.manifest.proofId.toLowerCase(),
      videoHash: receipt.manifest.videoHash.toLowerCase(),
      metadataHash: receipt.manifest.metadataHash.toLowerCase(),
      tier: receipt.manifest.tier,
      network: receipt.manifest.network,
      contractId: receipt.manifest.contractId,
      verifierScope: receipt.manifest.verifierScope ?? null,
      manifest: receipt.manifest,
      receipt,
      signedReceipt: null,
      lineageSuccess: null,
    }
  }

  // Saved verification bundle item ({ manifest?, receipt?, signedReceipt?, lineage? })
  let manifest: ProofManifest | null = null
  if (obj.manifest !== undefined) {
    if (!isPlainObject(obj.manifest)) throw new Error('bundle manifest must be an object')
    manifest = parseManifest(JSON.stringify(obj.manifest))
  }

  let receipt: VerificationReceipt | null = null
  let signedReceipt: SignedVerificationReceipt | null = null

  if (obj.receipt !== undefined) {
    if (!isPlainObject(obj.receipt)) throw new Error('bundle receipt must be an object')
    if (obj.receipt.protocol === 'harpocrates-verification-receipt') {
      signedReceipt = parseSingleEvidenceObject(obj.receipt).signedReceipt
    } else {
      receipt = parseC2paReceiptInput(obj.receipt)
    }
  }

  if (obj.signedReceipt !== undefined) {
    if (!isPlainObject(obj.signedReceipt)) throw new Error('bundle signedReceipt must be an object')
    signedReceipt = parseSingleEvidenceObject(obj.signedReceipt).signedReceipt
  }

  const primaryManifest = manifest ?? receipt?.manifest ?? null
  if (!primaryManifest && !signedReceipt) {
    throw new Error('bundle item must include a manifest, receipt, or signedReceipt')
  }

  // Fail closed if inner components disagree on canonical statement or deployment binding.
  if (manifest && receipt) {
    if (
      manifest.proofId.toLowerCase() !== receipt.manifest.proofId.toLowerCase() ||
      manifest.videoHash.toLowerCase() !== receipt.manifest.videoHash.toLowerCase() ||
      manifest.metadataHash.toLowerCase() !== receipt.manifest.metadataHash.toLowerCase() ||
      manifest.tier !== receipt.manifest.tier ||
      manifest.network !== receipt.manifest.network ||
      manifest.contractId !== receipt.manifest.contractId
    ) {
      throw new Error('bundle manifest and receipt disagree on statement or deployment binding')
    }
  }
  if (primaryManifest && signedReceipt) {
    if (
      primaryManifest.proofId.toLowerCase() !== signedReceipt.proofId.toLowerCase() ||
      primaryManifest.videoHash.toLowerCase() !== signedReceipt.videoHash.toLowerCase() ||
      primaryManifest.metadataHash.toLowerCase() !== signedReceipt.metadataHash.toLowerCase() ||
      primaryManifest.tier !== signedReceipt.tier ||
      primaryManifest.network !== signedReceipt.networkPassphrase ||
      primaryManifest.contractId !== signedReceipt.contractId
    ) {
      throw new Error('bundle manifest and signedReceipt disagree on statement or deployment binding')
    }
  }

  let lineageSuccess: boolean | null = null
  if (obj.lineage !== undefined) {
    if (!isPlainObject(obj.lineage) || typeof obj.lineage.success !== 'boolean') {
      throw new Error('bundle.lineage must be an object with boolean success')
    }
    lineageSuccess = obj.lineage.success
  }

  return {
    proofId: primaryManifest ? primaryManifest.proofId.toLowerCase() : signedReceipt!.proofId.toLowerCase(),
    videoHash: primaryManifest ? primaryManifest.videoHash.toLowerCase() : signedReceipt!.videoHash.toLowerCase(),
    metadataHash: primaryManifest
      ? primaryManifest.metadataHash.toLowerCase()
      : signedReceipt!.metadataHash.toLowerCase(),
    tier: primaryManifest ? primaryManifest.tier : signedReceipt!.tier,
    network: primaryManifest ? primaryManifest.network : signedReceipt!.networkPassphrase,
    contractId: primaryManifest ? primaryManifest.contractId : signedReceipt!.contractId,
    verifierScope: primaryManifest ? (primaryManifest.verifierScope ?? null) : null,
    manifest: primaryManifest,
    receipt,
    signedReceipt,
    lineageSuccess,
  }
}

function parseSavedBundleEvidence(rawBundleJson: string): NormalizedEvidenceItem[] {
  assertC2paInputWithinLimit(rawBundleJson, 'bundle')
  let parsed: unknown
  try {
    parsed = JSON.parse(rawBundleJson)
  } catch {
    throw new Error('bundle is not valid JSON')
  }
  if (!isPlainObject(parsed)) {
    throw new Error('bundle must be a JSON object')
  }
  if (containsPrivateFields(parsed)) {
    throw new Error('bundle contains forbidden private or secret fields')
  }

  if (Array.isArray(parsed.items)) {
    if (parsed.items.length === 0 || parsed.items.length > 64) {
      throw new Error('bundle.items must contain between 1 and 64 items')
    }
    return parsed.items.map((item) => {
      if (!isPlainObject(item)) throw new Error('bundle item must be an object')
      return parseSingleEvidenceObject(item)
    })
  }

  return [parseSingleEvidenceObject(parsed)]
}

async function evaluatePolicyForItem(
  item: NormalizedEvidenceItem,
  policy: TrustPolicy,
  now: Date,
): Promise<PolicyEvaluationDecision> {
  const failedRules: string[] = []
  let hasIncomplete = false

  // 1. Network check
  if (policy.allowedNetworks !== undefined) {
    const normalizedAllowed = new Set(policy.allowedNetworks.map((n) => resolveNetwork(n)))
    if (!normalizedAllowed.has(item.network)) {
      failedRules.push('network_not_allowed')
    }
  }

  // 2. Contract ID check
  if (policy.allowedContractIds !== undefined) {
    if (!policy.allowedContractIds.includes(item.contractId)) {
      failedRules.push('contract_not_allowed')
    }
  }

  // 3. Identity tier checks (allowedTiers & minimumTier)
  if (policy.allowedTiers !== undefined && !policy.allowedTiers.includes(item.tier)) {
    failedRules.push('tier_not_allowed')
  }
  if (
    policy.minimumTier !== undefined &&
    TIER_RANK[item.tier] < TIER_RANK[policy.minimumTier]
  ) {
    failedRules.push('below_minimum_tier')
  }

  // 4. Verifier scope check
  if (policy.allowedVerifierScopes !== undefined) {
    if (item.verifierScope === null || !policy.allowedVerifierScopes.includes(item.verifierScope)) {
      failedRules.push('verifier_scope_not_allowed')
    }
  }

  // 5. On-chain confirmation check (default true unless requireSignedReceipt is used without an unsigned receipt)
  const requireOnChain =
    policy.requireOnChainConfirmation ?? (item.signedReceipt === null || item.receipt !== null)
  if (requireOnChain) {
    if (!item.receipt) {
      hasIncomplete = true
      failedRules.push('missing_on_chain_receipt')
    } else if (item.receipt.result === 'pending' || item.receipt.transaction.status === 'pending') {
      hasIncomplete = true
      failedRules.push('on_chain_confirmation_pending')
    } else if (
      item.receipt.result !== 'valid' ||
      item.receipt.transaction.status !== 'confirmed' ||
      item.receipt.chainRecord?.status !== 1
    ) {
      failedRules.push(`on_chain_result_${item.receipt.result}`)
    }
  }

  // 6. Signed receipt & trusted signer key check
  const mustVerifySigned =
    policy.requireSignedReceipt === true ||
    (item.signedReceipt !== null && policy.trustedKeys !== undefined)
  if (policy.requireSignedReceipt === true && item.signedReceipt === null) {
    hasIncomplete = true
    failedRules.push('missing_signed_receipt')
  } else if (mustVerifySigned && item.signedReceipt !== null) {
    if (!policy.trustedKeys || Object.keys(policy.trustedKeys).length === 0) {
      failedRules.push('no_trusted_keys_configured')
    } else {
      const verifyRes = await verifyVerificationReceipt(item.signedReceipt, {
        keys: policy.trustedKeys,
        keyValidity: policy.keyValidity,
        now,
      })
      if (!verifyRes.valid) {
        failedRules.push('signed_receipt_untrusted')
      } else if (item.signedReceipt.result !== 'verified') {
        failedRules.push('signed_receipt_unverified_result')
      }
    }
  } else if (item.signedReceipt !== null && !item.receipt) {
    // Signed receipt present with no trustedKeys in policy -> cannot establish signer trust fail-closed!
    hasIncomplete = true
    failedRules.push('signed_receipt_key_unchecked')
  }

  // 7. Receipt freshness / maxReceiptAgeSeconds check
  if (policy.maxReceiptAgeSeconds !== undefined) {
    const verifiedAtIso = item.signedReceipt?.verifiedAt ?? item.receipt?.verifiedAt ?? null
    if (!verifiedAtIso) {
      hasIncomplete = true
      failedRules.push('missing_receipt_timestamp')
    } else {
      const ageSeconds = (now.getTime() - Date.parse(verifiedAtIso)) / 1000
      if (!Number.isFinite(ageSeconds) || ageSeconds < 0 || ageSeconds > policy.maxReceiptAgeSeconds) {
        failedRules.push('receipt_age_exceeded')
      }
    }
  }

  // 8. Lineage check
  if (policy.requireLineageVerified === true) {
    if (item.lineageSuccess === null) {
      hasIncomplete = true
      failedRules.push('missing_lineage_evidence')
    } else if (!item.lineageSuccess) {
      failedRules.push('lineage_verification_failed')
    }
  }

  const sortedRules = [...failedRules].sort()
  if (sortedRules.length === 0) {
    return {
      trusted: true,
      outcome: 'trusted',
      failedRules: [],
    }
  }

  const onlyIncompleteRules =
    hasIncomplete &&
    sortedRules.every((r) =>
      [
        'missing_on_chain_receipt',
        'on_chain_confirmation_pending',
        'missing_signed_receipt',
        'signed_receipt_key_unchecked',
        'missing_receipt_timestamp',
        'missing_lineage_evidence',
      ].includes(r),
    )

  return {
    trusted: false,
    outcome: onlyIncompleteRules ? 'incomplete' : 'rejected',
    failedRules: sortedRules,
  }
}

/**
 * Evaluate two trust-policy configurations against identical saved verification
 * bundle evidence without mutating either policy or making live network calls.
 */
export async function compareTrustPolicies(
  rawBundleJson: string,
  rawPolicyAJson: string,
  rawPolicyBJson: string,
  options: ComparePoliciesOptions = {},
): Promise<PolicyComparisonReport> {
  const evidenceItems = parseSavedBundleEvidence(rawBundleJson)
  const policyA = parseTrustPolicy(rawPolicyAJson)
  const policyB = parseTrustPolicy(rawPolicyBJson)
  const now = options.now ?? new Date()

  const evidenceDigest = canonicalHash({
    items: evidenceItems.map((e) => ({
      proofId: e.proofId,
      videoHash: e.videoHash,
      metadataHash: e.metadataHash,
      tier: e.tier,
      network: e.network,
      contractId: e.contractId,
      verifierScope: e.verifierScope,
      receiptResult: e.receipt?.result ?? null,
      signedReceiptSignature: e.signedReceipt?.signature ?? null,
      lineageSuccess: e.lineageSuccess,
    })),
  })
  const policyADigest = canonicalHash(policyA as unknown as Record<string, unknown>)
  const policyBDigest = canonicalHash(policyB as unknown as Record<string, unknown>)

  const items: EvidencePolicyComparisonItem[] = []
  for (let i = 0; i < evidenceItems.length; i++) {
    const item = evidenceItems[i]
    const decA = await evaluatePolicyForItem(item, policyA, now)
    const decB = await evaluatePolicyForItem(item, policyB, now)

    const decisionChanged = decA.trusted !== decB.trusted || decA.outcome !== decB.outcome
    const reasonsChanged =
      JSON.stringify(decA.failedRules) !== JSON.stringify(decB.failedRules)

    let transition: EvidencePolicyComparisonItem['transition'] = 'unchanged'
    if (decisionChanged) {
      if (!decA.trusted && decB.trusted) transition = 'newly_trusted'
      else if (decA.trusted && !decB.trusted) transition = 'newly_rejected'
      else transition = 'outcome_changed'
    }

    items.push({
      index: i,
      proofId: item.proofId,
      tier: item.tier,
      network: item.network,
      contractId: item.contractId,
      policyA: decA,
      policyB: decB,
      decisionChanged,
      reasonsChanged,
      transition,
    })
  }

  const changedDecisions = items.filter((item) => item.decisionChanged)

  return {
    protocol: POLICY_COMPARISON_PROTOCOL,
    version: POLICY_COMPARISON_VERSION,
    identicalDecisions: changedDecisions.length === 0,
    decisionChangedCount: changedDecisions.length,
    totalItems: items.length,
    evidenceDigest,
    policyADigest,
    policyBDigest,
    policyAName: policyA.name ?? null,
    policyBName: policyB.name ?? null,
    items,
    changedDecisions,
  }
}

export function formatPolicyComparisonReport(report: PolicyComparisonReport): string {
  const labelA = report.policyAName ?? 'policy-a'
  const labelB = report.policyBName ?? 'policy-b'
  const lines = [
    `Trust Policy Comparison: ${report.identicalDecisions ? 'NO DECISION CHANGES' : `${report.decisionChangedCount} CHANGED DECISION(S)`}`,
    `Policies:         ${labelA} (${report.policyADigest.slice(0, 12)}...) -> ${labelB} (${report.policyBDigest.slice(0, 12)}...)`,
    `Evidence digest:  ${report.evidenceDigest}`,
    `Evaluated items:  ${report.totalItems}`,
  ]
  for (const item of report.items) {
    const rulesA = item.policyA.failedRules.length > 0 ? ` [${item.policyA.failedRules.join(',')}]` : ''
    const rulesB = item.policyB.failedRules.length > 0 ? ` [${item.policyB.failedRules.join(',')}]` : ''
    lines.push(
      `  [${item.transition}] proof=${item.proofId} tier=${item.tier}: ${item.policyA.outcome}${rulesA} -> ${item.policyB.outcome}${rulesB}`,
    )
  }
  return lines.join('\n')
}
