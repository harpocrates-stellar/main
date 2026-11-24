import { parseManifest, type ProofManifest } from './manifest.js'
import { verifyVerificationReceipt, type SignedVerificationReceipt } from './signed-receipt.js'

/**
 * Point-in-time capture of the trust material needed to verify receipts
 * offline: the public verifier keys (by key id) plus the expected network and
 * optional per-key validity windows. Captured so a bundle can be checked with
 * no network access.
 */
export type TrustSnapshot = {
  keys: Record<string, JsonWebKey>
  networkPassphrase?: string
  capturedAt?: string
  keyValidity?: Record<string, { notBefore?: string; notAfter?: string }>
}

/** A self-contained set of artifacts that can be verified without a network. */
export type OfflineBundle = {
  version: string
  trustSnapshot: TrustSnapshot
  manifests: unknown[]
  receipts: SignedVerificationReceipt[]
}

export type ManifestCheck =
  | { index: number; valid: true; proofId: string | null }
  | { index: number; valid: false; reason: string }

export type ReceiptCheck =
  | { index: number; valid: true; keyId: string }
  | { index: number; valid: false; reason: string }

/**
 * An online-only check that a local bundle cannot perform. Reported explicitly
 * so a caller can tell "skipped because offline" apart from "passed".
 */
export type OnlineCheck = { name: string; status: 'unavailable'; reason: string }

export type OfflineBundleReport = {
  offline: true
  trustSnapshot: { keyCount: number; capturedAt: string | null; networkPassphrase: string | null }
  manifests: ManifestCheck[]
  receipts: ReceiptCheck[]
  onlineChecks: OnlineCheck[]
  summary: {
    manifestsValid: number
    manifestsTotal: number
    receiptsValid: number
    receiptsTotal: number
    allValid: boolean
  }
}

export const BUNDLE_FORMAT_VERSION = '1.0.0'

/** Checks that depend on live chain/RPC state and are never run offline. */
const ONLINE_ONLY_CHECKS: readonly string[] = [
  'on-chain-proof-status',
  'transaction-confirmation',
  'on-chain-lineage',
]

const ONLINE_UNAVAILABLE_REASON = 'offline bundle: requires a network RPC connection'

export class BundleFormatError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BundleFormatError'
  }
}

/** Parse and structurally validate a local offline-verification bundle. */
export function parseOfflineBundle(json: string): OfflineBundle {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new BundleFormatError('bundle is not valid JSON')
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new BundleFormatError('bundle must be a JSON object')
  }
  const b = parsed as Record<string, unknown>

  const snapshot = b.trustSnapshot
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
    throw new BundleFormatError('bundle.trustSnapshot must be an object')
  }
  const keys = (snapshot as Record<string, unknown>).keys
  if (!keys || typeof keys !== 'object' || Array.isArray(keys)) {
    throw new BundleFormatError('bundle.trustSnapshot.keys must be an object of key id to JWK')
  }

  const manifests = b.manifests ?? []
  if (!Array.isArray(manifests)) {
    throw new BundleFormatError('bundle.manifests must be an array')
  }
  const receipts = b.receipts ?? []
  if (!Array.isArray(receipts)) {
    throw new BundleFormatError('bundle.receipts must be an array')
  }

  return {
    version: typeof b.version === 'string' ? b.version : BUNDLE_FORMAT_VERSION,
    trustSnapshot: snapshot as TrustSnapshot,
    manifests: manifests as unknown[],
    receipts: receipts as SignedVerificationReceipt[],
  }
}

/**
 * Verify every manifest and receipt in a bundle against its trust snapshot,
 * entirely offline. Online-only checks are reported as `unavailable` rather
 * than passed or failed.
 */
export async function verifyOfflineBundle(bundle: OfflineBundle, now?: Date): Promise<OfflineBundleReport> {
  const snapshot = bundle.trustSnapshot

  const manifests: ManifestCheck[] = bundle.manifests.map((m, index) => {
    try {
      const raw = typeof m === 'string' ? m : JSON.stringify(m)
      const parsed: ProofManifest = parseManifest(raw)
      return { index, valid: true as const, proofId: parsed.proofId ?? null }
    } catch (err) {
      return { index, valid: false as const, reason: err instanceof Error ? err.message : 'invalid manifest' }
    }
  })

  const receipts: ReceiptCheck[] = []
  for (let index = 0; index < bundle.receipts.length; index++) {
    const result = await verifyVerificationReceipt(bundle.receipts[index], {
      keys: snapshot.keys,
      expectedNetworkPassphrase: snapshot.networkPassphrase,
      keyValidity: snapshot.keyValidity,
      now,
    })
    if (result.valid) {
      receipts.push({ index, valid: true, keyId: result.receipt.signer.keyId })
    } else {
      receipts.push({ index, valid: false, reason: result.reason })
    }
  }

  const onlineChecks: OnlineCheck[] = ONLINE_ONLY_CHECKS.map((name) => ({
    name,
    status: 'unavailable',
    reason: ONLINE_UNAVAILABLE_REASON,
  }))

  const manifestsValid = manifests.filter((m) => m.valid).length
  const receiptsValid = receipts.filter((r) => r.valid).length
  const allValid = manifestsValid === manifests.length && receiptsValid === receipts.length

  return {
    offline: true,
    trustSnapshot: {
      keyCount: Object.keys(snapshot.keys).length,
      capturedAt: snapshot.capturedAt ?? null,
      networkPassphrase: snapshot.networkPassphrase ?? null,
    },
    manifests,
    receipts,
    onlineChecks,
    summary: {
      manifestsValid,
      manifestsTotal: manifests.length,
      receiptsValid,
      receiptsTotal: receipts.length,
      allValid,
    },
  }
}

/** Render a human-readable summary of an offline bundle report. */
export function formatOfflineBundleReport(report: OfflineBundleReport): string {
  const lines: string[] = []
  const s = report.summary
  lines.push(s.allValid ? '✅ Offline bundle verified.' : '❌ Offline bundle has failures.')
  lines.push(`Trust snapshot: ${report.trustSnapshot.keyCount} key(s)` +
    (report.trustSnapshot.networkPassphrase ? `, network "${report.trustSnapshot.networkPassphrase}"` : ''))
  lines.push(`Manifests: ${s.manifestsValid}/${s.manifestsTotal} valid`)
  for (const m of report.manifests) {
    if (!m.valid) lines.push(`  - manifest[${m.index}] invalid: ${m.reason}`)
  }
  lines.push(`Receipts: ${s.receiptsValid}/${s.receiptsTotal} valid`)
  for (const r of report.receipts) {
    if (!r.valid) lines.push(`  - receipt[${r.index}] invalid: ${r.reason}`)
  }
  lines.push('Online-only checks (unavailable offline):')
  for (const c of report.onlineChecks) {
    lines.push(`  - ${c.name}: ${c.status}`)
  }
  return lines.join('\n')
}
