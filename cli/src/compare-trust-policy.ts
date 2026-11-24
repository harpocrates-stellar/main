import { verifyVerificationReceipt, type SignedVerificationReceipt } from './signed-receipt.js'
import { parseManifest, type ProofManifest } from './manifest.js'
import type { TrustSnapshot, OfflineBundle } from './verify-bundle.js'
import { parseOfflineBundle } from './verify-bundle.js'

/**
 * A trust-policy file is a JSON object with the same shape as TrustSnapshot.
 * The same bundle evidence is verified against both policies and the results
 * are compared, without changing either policy.
 */
export type TrustPolicy = TrustSnapshot

/**
 * The trust decision for a single receipt under one policy.
 * `skipped` means the receipt index was out of range for the evidence.
 */
export type ReceiptDecision =
  | { valid: true; keyId: string }
  | { valid: false; reason: string }
  | { valid: null; reason: 'skipped' }

/**
 * Per-receipt comparison: what changed between policyA and policyB for the
 * same evidence.
 */
export type ReceiptDiff =
  | { index: number; changed: false; decision: ReceiptDecision }
  | { index: number; changed: true; before: ReceiptDecision; after: ReceiptDecision }

export type ManifestDecision =
  | { valid: true; proofId: string | null }
  | { valid: false; reason: string }

/**
 * Per-manifest comparison.
 */
export type ManifestDiff =
  | { index: number; changed: false; decision: ManifestDecision }
  | { index: number; changed: true; before: ManifestDecision; after: ManifestDecision }

export type TrustPolicyComparisonReport = {
  /** Did any trust decision change between the two policies? */
  changed: boolean
  receipts: ReceiptDiff[]
  manifests: ManifestDiff[]
  summary: {
    receiptsChanged: number
    receiptsTotal: number
    manifestsChanged: number
    manifestsTotal: number
  }
}

export class PolicyParseError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PolicyParseError'
  }
}

/** Parse and lightly validate a trust-policy JSON string. */
export function parseTrustPolicy(json: string): TrustPolicy {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new PolicyParseError('policy is not valid JSON')
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new PolicyParseError('policy must be a JSON object')
  }
  const p = parsed as Record<string, unknown>
  if (!p.keys || typeof p.keys !== 'object' || Array.isArray(p.keys)) {
    throw new PolicyParseError('policy.keys must be an object mapping key IDs to JWKs')
  }
  return p as TrustPolicy
}

function evaluateManifest(raw: unknown): ManifestDecision {
  try {
    const str = typeof raw === 'string' ? raw : JSON.stringify(raw)
    const m: ProofManifest = parseManifest(str)
    return { valid: true, proofId: m.proofId ?? null }
  } catch (err) {
    return { valid: false, reason: err instanceof Error ? err.message : 'invalid manifest' }
  }
}

async function evaluateReceipt(
  receipt: SignedVerificationReceipt,
  policy: TrustPolicy,
  now?: Date,
): Promise<ReceiptDecision> {
  const result = await verifyVerificationReceipt(receipt, {
    keys: policy.keys,
    expectedNetworkPassphrase: policy.networkPassphrase,
    keyValidity: policy.keyValidity,
    now,
  })
  if (result.valid) return { valid: true, keyId: result.receipt.signer.keyId }
  return { valid: false, reason: result.reason }
}

/**
 * Evaluate both policies against identical bundle evidence and return a
 * diff of every trust decision that changed.
 *
 * Neither policy is mutated. The bundle is parsed from `bundleJson` once and
 * the same evidence is used for both evaluations.
 */
export async function compareTrustPolicies(
  policyA: TrustPolicy,
  policyB: TrustPolicy,
  bundle: OfflineBundle,
  now?: Date,
): Promise<TrustPolicyComparisonReport> {
  // Manifests: policy has no effect on manifest parsing (it is purely structural
  // validation), so both policies always see the same manifest decisions.
  const manifestDiffs: ManifestDiff[] = bundle.manifests.map((m, index) => {
    const decision = evaluateManifest(m)
    return { index, changed: false, decision }
  })

  // Receipts: each policy may trust different keys / impose different validity
  // windows, so decisions can diverge.
  const receiptDiffs: ReceiptDiff[] = []
  for (let index = 0; index < bundle.receipts.length; index++) {
    const receipt = bundle.receipts[index]
    const [a, b] = await Promise.all([
      evaluateReceipt(receipt, policyA, now),
      evaluateReceipt(receipt, policyB, now),
    ])

    const aValid = a.valid
    const bValid = b.valid
    if (aValid === bValid) {
      receiptDiffs.push({ index, changed: false, decision: a })
    } else {
      receiptDiffs.push({ index, changed: true, before: a, after: b })
    }
  }

  const receiptsChanged = receiptDiffs.filter((r) => r.changed).length
  const manifestsChanged = manifestDiffs.filter((m) => m.changed).length

  return {
    changed: receiptsChanged > 0 || manifestsChanged > 0,
    receipts: receiptDiffs,
    manifests: manifestDiffs,
    summary: {
      receiptsChanged,
      receiptsTotal: bundle.receipts.length,
      manifestsChanged,
      manifestsTotal: bundle.manifests.length,
    },
  }
}

function renderDecision(d: ReceiptDecision): string {
  if (d.valid === true) return `✅ valid (key: ${d.keyId})`
  if (d.valid === false) return `❌ invalid (${d.reason})`
  return `⏭  skipped`
}

/** Render a human-readable diff of the two policy evaluations. */
export function formatTrustPolicyComparison(report: TrustPolicyComparisonReport): string {
  const lines: string[] = []
  lines.push(report.changed ? '⚠️  Trust decisions changed between policies.' : '✅ No trust decisions changed between policies.')

  if (report.receipts.length > 0) {
    lines.push(`\nReceipts (${report.summary.receiptsTotal}):`)
    for (const r of report.receipts) {
      if (r.changed) {
        lines.push(`  receipt[${r.index}] CHANGED`)
        lines.push(`    policy A: ${renderDecision(r.before)}`)
        lines.push(`    policy B: ${renderDecision(r.after)}`)
      } else {
        lines.push(`  receipt[${r.index}] unchanged — ${renderDecision(r.decision)}`)
      }
    }
  }

  if (report.manifests.length > 0) {
    lines.push(`\nManifests (${report.summary.manifestsTotal}):`)
    for (const m of report.manifests) {
      if (m.changed) {
        lines.push(`  manifest[${m.index}] CHANGED`)
      } else {
        const d = m.decision
        lines.push(
          `  manifest[${m.index}] unchanged — ` +
            (d.valid ? `✅ valid (proofId: ${d.proofId ?? 'none'})` : `❌ invalid (${d.reason})`),
        )
      }
    }
  }

  return lines.join('\n')
}

export interface RunCompareTrustPolicyIo {
  readText: (path: string) => Promise<string>
  writeStdout: (text: string) => void
  writeStderr: (text: string) => void
  debugLog?: (event: Record<string, unknown>) => void
}

/**
 * Execute the `compare-trust-policy` command logic with injectable I/O.
 * Returns the process exit code.
 * Exit 0 → no decisions changed; exit 1 → at least one decision changed;
 * exit 2 → usage error; exit 8 → input error.
 */
export async function runCompareTrustPolicy(
  flags: Record<string, string>,
  io: RunCompareTrustPolicyIo,
): Promise<number> {
  const policyAPath = flags['policy-a'] || flags.policyA
  const policyBPath = flags['policy-b'] || flags.policyB
  const bundlePath = flags.bundle || flags.b
  const outputFormat = flags.output || flags.o || 'text'

  if (!policyAPath) {
    io.writeStderr('harpocrates: --policy-a is required\n')
    return 2
  }
  if (!policyBPath) {
    io.writeStderr('harpocrates: --policy-b is required\n')
    return 2
  }
  if (!bundlePath) {
    io.writeStderr('harpocrates: --bundle is required\n')
    return 2
  }
  if (outputFormat !== 'text' && outputFormat !== 'json') {
    io.writeStderr('harpocrates: invalid --output: expected "text" or "json"\n')
    return 2
  }

  let policyA: TrustPolicy
  try {
    policyA = parseTrustPolicy(await io.readText(policyAPath))
  } catch (err) {
    io.writeStderr(`harpocrates: invalid or unreadable policy-a: ${err instanceof Error ? err.message : String(err)}\n`)
    return 8
  }

  let policyB: TrustPolicy
  try {
    policyB = parseTrustPolicy(await io.readText(policyBPath))
  } catch (err) {
    io.writeStderr(`harpocrates: invalid or unreadable policy-b: ${err instanceof Error ? err.message : String(err)}\n`)
    return 8
  }

  let bundle: OfflineBundle
  try {
    bundle = parseOfflineBundle(await io.readText(bundlePath))
  } catch (err) {
    io.writeStderr(`harpocrates: invalid or unreadable bundle: ${err instanceof Error ? err.message : String(err)}\n`)
    return 8
  }

  io.debugLog?.({
    event: 'compare-trust-policy.input',
    policyAKeys: Object.keys(policyA.keys),
    policyBKeys: Object.keys(policyB.keys),
    bundleManifests: bundle.manifests.length,
    bundleReceipts: bundle.receipts.length,
  })

  const report = await compareTrustPolicies(policyA, policyB, bundle)

  if (outputFormat === 'json') {
    io.writeStdout(JSON.stringify(report, null, 2) + '\n')
  } else {
    io.writeStdout(formatTrustPolicyComparison(report) + '\n')
  }

  return report.changed ? 1 : 0
}
