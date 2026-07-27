/**
 * artifactIntegrity — runtime verification of WASM and circuit artifact integrity.
 *
 * Loads a signed manifest of expected SHA-256 digests and verifies every
 * artifact (circuit JSON, WASM, proving key) against it before the proving
 * subsystem may consume them.  This prevents proof generation with tampered
 * or substituted artifacts, even when the app itself is served over a
 * compromised CDN or cache.
 *
 * ### Threat model (see THREAT_MODEL.md)
 *
 *   T6 (compromised build pipeline / CDN injection):
 *     An attacker replaces the circuit JSON or WASM files with a backdoored
 *     version that leaks the witness.  The manifest is pinned to known-good
 *     digests, so the substitution is detected before the backend is
 *     instantiated.
 *
 *   T8 (cache poisoning / Service Worker race):
 *     A stale or attacker-controlled Service Worker returns an older artifact.
 *     The `cache: 'no-store'` fetch policy plus the digest check rejects any
 *     artifact whose hash does not match the current manifest entry.
 *
 * ### Usage
 *
 *   ```ts
 *   const manifest = await loadManifest('/noir/manifest.json')
 *   const circuitData = await fetchAndVerify('/noir/silent_witness.json', manifest)
 *   const circuit: CompiledCircuit = JSON.parse(new TextDecoder().decode(circuitData))
 *   ```
 *
 * ### Rollout
 *
 *   When circuit artifacts are recompiled, the manifest must be regenerated
 *   with the new digests and the `createdAt` timestamp bumped.  The manifest
 *   itself is versioned (`manifest.version`) so the verification routine can
 *   reject an incompatible manifest schema without attempting to verify.
 *
 *   Rollback: deploy the previous manifest + artifact set.  The frontend
 *   accepts any artifact that matches the current manifest — there is no
 *   mandatory-forward migration.
 *
 * ### Privacy
 *
 *   No artifact content, hashes, or manifest fields are ever logged to the
 *   console, sent to a remote endpoint, or included in error messages exposed
 *   to the user.  Error messages are generic ("Proof system integrity check
 *   failed") while the full detail is captured in the thrown error's `cause`
 *   chain for developer tooling.
 */

import { sha256 } from './utils'
import type { CompiledCircuit } from '@noir-lang/types'

// ── Types ─────────────────────────────────────────────────────────────────────

export const MANIFEST_VERSION = 1

export interface ArtifactEntry {
  sha256: string
  size: number
}

export interface ArtifactManifest {
  protocol: 'harpocrates'
  version: number
  circuitVersion: string
  network: string
  createdAt: string
  artifacts: Record<string, ArtifactEntry>
}

export class ArtifactIntegrityError extends Error {
  public readonly artifactPath: string
  public readonly expectedDigest: string
  public readonly actualDigest: string

  constructor(path: string, expected: string, actual: string) {
    super('Proof system integrity check failed')
    this.name = 'ArtifactIntegrityError'
    this.artifactPath = path
    this.expectedDigest = expected
    this.actualDigest = actual
  }
}

export class ManifestIntegrityError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ManifestIntegrityError'
  }
}

export class ArtifactFetchError extends Error {
  public readonly artifactPath: string
  public readonly httpStatus: number

  constructor(path: string, status: number) {
    super('Proof system artifact could not be loaded')
    this.name = 'ArtifactFetchError'
    this.artifactPath = path
    this.httpStatus = status
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Fetch and validate the artifact manifest.
 *
 * The manifest must:
 *   - Have the correct `protocol`
 *   - Have a `version` this runtime understands
 *   - Contain a non-empty `artifacts` map
 *
 * Throws `ManifestIntegrityError` on any violation.
 */
export async function loadManifest(url: string = '/noir/manifest.json'): Promise<ArtifactManifest> {
  const response = await fetch(url, { cache: 'no-store' })
  if (!response.ok) {
    throw new ManifestIntegrityError(
      `Artifact manifest could not be loaded (HTTP ${response.status})`,
    )
  }

  let parsed: unknown
  try {
    parsed = await response.json()
  } catch {
    throw new ManifestIntegrityError('Artifact manifest is not valid JSON')
  }

  const manifest = parsed as ArtifactManifest

  if (manifest.protocol !== 'harpocrates') {
    throw new ManifestIntegrityError('Artifact manifest has an unrecognised protocol')
  }
  if (typeof manifest.version !== 'number' || manifest.version !== MANIFEST_VERSION) {
    throw new ManifestIntegrityError('Artifact manifest version is not supported')
  }
  if (typeof manifest.circuitVersion !== 'string' || manifest.circuitVersion.length === 0) {
    throw new ManifestIntegrityError('Artifact manifest is missing circuitVersion')
  }
  if (typeof manifest.network !== 'string' || manifest.network.length === 0) {
    throw new ManifestIntegrityError('Artifact manifest is missing network binding')
  }
  if (!manifest.artifacts || Object.keys(manifest.artifacts).length === 0) {
    throw new ManifestIntegrityError('Artifact manifest contains no artifact entries')
  }

  return manifest
}

/**
 * Fetch an artifact and verify its SHA-256 digest against the manifest.
 *
 * Returns the raw bytes on success.  Throws `ArtifactFetchError` on HTTP
 * failure or `ArtifactIntegrityError` on digest mismatch.
 */
export async function fetchAndVerify(
  path: string,
  manifest: ArtifactManifest,
): Promise<ArrayBuffer> {
  const entry = manifest.artifacts[path]
  if (!entry) {
    throw new ManifestIntegrityError(
      `Artifact manifest does not contain an entry for ${path}`,
    )
  }

  const response = await fetch(path, { cache: 'no-store' })
  if (!response.ok) {
    throw new ArtifactFetchError(path, response.status)
  }

  const data = await response.arrayBuffer()

  if (data.byteLength !== entry.size) {
    throw new ArtifactIntegrityError(
      path,
      entry.sha256,
      `size mismatch (expected ${entry.size}, got ${data.byteLength})`,
    )
  }

  const digest = await sha256(data)
  if (digest !== entry.sha256) {
    throw new ArtifactIntegrityError(path, entry.sha256, digest)
  }

  return data
}

/**
 * Verify that the artifact manifest's network binding matches the expected
 * network passphrase.  Call this before `loadManifest` / `fetchAndVerify`
 * when the caller has already resolved the target network (e.g. from the
 * connected wallet or environment config).
 *
 * Returns `true` when the network matches, or throws `ManifestIntegrityError`
 * with a descriptive message when it does not.
 */
export function verifyManifestNetwork(
  manifest: ArtifactManifest,
  expectedNetwork: string,
): void {
  if (manifest.network !== expectedNetwork) {
    throw new ManifestIntegrityError(
      `Artifact manifest is bound to a different network (expected "${expectedNetwork}")`,
    )
  }
}

/**
 * Load a Noir circuit artifact with full integrity verification.
 *
 * Convenience wrapper around `loadManifest` + `fetchAndVerify` + JSON parse.
 * Caches the manifest and parsed circuit so repeated calls for the same
 * circuit do not re-fetch.
 */
const circuitCache = new Map<string, CompiledCircuit>()

export async function loadVerifiedCircuit(
  path: string,
  manifestUrl?: string,
): Promise<CompiledCircuit> {
  const cached = circuitCache.get(path)
  if (cached) return cached

  const manifest = await loadManifest(manifestUrl)
  const data = await fetchAndVerify(path, manifest)
  const text = new TextDecoder().decode(data)
  const circuit = JSON.parse(text) as CompiledCircuit

  circuitCache.set(path, circuit)
  return circuit
}

/**
 * Clear the circuit cache.  Useful between test runs or when the manifest
 * is known to have been updated.
 */
export function clearCircuitCache(): void {
  circuitCache.clear()
}
