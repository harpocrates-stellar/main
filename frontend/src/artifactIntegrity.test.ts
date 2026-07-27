/**
 * Unit tests for artifact integrity verification.
 *
 * Covers:
 *   - loadManifest: valid manifest, missing manifest, wrong protocol,
 *     wrong version, empty artifacts, malformed JSON
 *   - fetchAndVerify: matching digest, size mismatch, digest mismatch,
 *     missing manifest entry, HTTP error
 *   - verifyManifestNetwork: matching network, mismatched network
 *   - loadVerifiedCircuit: loads and caches, clears cache
 *   - ArtifactIntegrityError: exposes path / expected / actual for diagnostics
 *   - Privacy: no artifact content or hashes in user-facing error messages
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  loadManifest,
  fetchAndVerify,
  verifyManifestNetwork,
  loadVerifiedCircuit,
  clearCircuitCache,
  ArtifactIntegrityError,
  ManifestIntegrityError,
  ArtifactFetchError,
  MANIFEST_VERSION,
  type ArtifactManifest,
} from './artifactIntegrity'
import { sha256 } from './utils'
import type { CompiledCircuit } from '@noir-lang/types'

// ── Manifest fixtures ─────────────────────────────────────────────────────────

const VALID_MANIFEST: ArtifactManifest = {
  protocol: 'harpocrates',
  version: MANIFEST_VERSION,
  circuitVersion: '1.0.0-beta.9',
  network: 'Test SDF Network ; September 2015',
  createdAt: '2026-07-27T00:00:00.000Z',
  artifacts: {
    '/noir/silent_witness.json': {
      sha256: '26c306df107269cce78e21bdedafe0444a54691131e825d44ce350dcf8b97e79',
      size: 24329,
    },
    '/noir/silent_witness_helper.json': {
      sha256: '95a629e7a094d8ddfe6bc92d2455f500eb9ce1f4dec37d51b9c5ed3b4a55ddb4',
      size: 24149,
    },
  },
}

// Helpers to build mock responses
function mockJsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockBinaryResponse(bytes: Uint8Array, status = 200): Response {
  return new Response(bytes, {
    status,
    headers: { 'Content-Type': 'application/octet-stream' },
  })
}

// ── loadManifest ──────────────────────────────────────────────────────────────

describe('loadManifest', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('returns a parsed manifest when fetch succeeds with valid JSON', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockJsonResponse(VALID_MANIFEST))

    const manifest = await loadManifest('/test/manifest.json')
    expect(manifest.protocol).toBe('harpocrates')
    expect(manifest.version).toBe(MANIFEST_VERSION)
    expect(manifest.circuitVersion).toBe('1.0.0-beta.9')
    expect(Object.keys(manifest.artifacts)).toHaveLength(2)
  })

  it('uses the default manifest URL when none is provided', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockJsonResponse(VALID_MANIFEST))

    const manifest = await loadManifest()
    expect(manifest.protocol).toBe('harpocrates')
  })

  it('throws ManifestIntegrityError when fetch fails with HTTP error', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockJsonResponse(null, 404))

    await expect(loadManifest('/test/manifest.json')).rejects.toThrow(ManifestIntegrityError)
  })

  it('throws ManifestIntegrityError when response is not valid JSON', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('not json', { status: 200 }))

    await expect(loadManifest('/test/manifest.json')).rejects.toThrow(ManifestIntegrityError)
  })

  it('throws ManifestIntegrityError when protocol is wrong', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      mockJsonResponse({ ...VALID_MANIFEST, protocol: 'evil' }),
    )

    await expect(loadManifest('/test/manifest.json')).rejects.toThrow(ManifestIntegrityError)
  })

  it('throws ManifestIntegrityError when version is not supported', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      mockJsonResponse({ ...VALID_MANIFEST, version: 999 }),
    )

    await expect(loadManifest('/test/manifest.json')).rejects.toThrow(ManifestIntegrityError)
  })

  it('throws ManifestIntegrityError when circuitVersion is missing', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      mockJsonResponse({ ...VALID_MANIFEST, circuitVersion: '' }),
    )

    await expect(loadManifest('/test/manifest.json')).rejects.toThrow(ManifestIntegrityError)
  })

  it('throws ManifestIntegrityError when artifacts map is empty', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      mockJsonResponse({ ...VALID_MANIFEST, artifacts: {} }),
    )

    await expect(loadManifest('/test/manifest.json')).rejects.toThrow(ManifestIntegrityError)
  })

  it('throws ManifestIntegrityError when artifacts is missing', async () => {
    const withoutArtifacts: Record<string, unknown> = { ...VALID_MANIFEST }
    delete withoutArtifacts.artifacts
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockJsonResponse(withoutArtifacts))

    await expect(loadManifest('/test/manifest.json')).rejects.toThrow(ManifestIntegrityError)
  })
})

// ── fetchAndVerify ────────────────────────────────────────────────────────────

describe('fetchAndVerify', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('returns the artifact bytes when digest matches', async () => {
    const content = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello"
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockBinaryResponse(content))

    const manifest: ArtifactManifest = {
      ...VALID_MANIFEST,
      artifacts: {
        '/test/artifact.bin': {
          sha256: '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969',
          size: 5,
        },
      },
    }

    const data = await fetchAndVerify('/test/artifact.bin', manifest)
    expect(new Uint8Array(data)).toEqual(content)
  })

  it('throws ArtifactIntegrityError when digest does not match', async () => {
    const content = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello"
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockBinaryResponse(content))

    const manifest: ArtifactManifest = {
      ...VALID_MANIFEST,
      artifacts: {
        '/test/artifact.bin': {
          sha256: '0000000000000000000000000000000000000000000000000000000000000000',
          size: 5,
        },
      },
    }

    await expect(fetchAndVerify('/test/artifact.bin', manifest)).rejects.toThrow(ArtifactIntegrityError)
  })

  it('throws ManifestIntegrityError when path is not in manifest', async () => {
    await expect(fetchAndVerify('/test/unknown.bin', VALID_MANIFEST)).rejects.toThrow(ManifestIntegrityError)
  })

  it('throws ArtifactFetchError when HTTP request fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockBinaryResponse(new Uint8Array(), 500))

    const manifest: ArtifactManifest = {
      ...VALID_MANIFEST,
      artifacts: {
        '/test/missing.bin': { sha256: 'a'.repeat(64), size: 0 },
      },
    }

    await expect(fetchAndVerify('/test/missing.bin', manifest)).rejects.toThrow(ArtifactFetchError)
  })

  it('throws ArtifactIntegrityError when size does not match', async () => {
    const content = new Uint8Array([0x01, 0x02, 0x03])
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockBinaryResponse(content))

    const manifest: ArtifactManifest = {
      ...VALID_MANIFEST,
      artifacts: {
        '/test/size-mismatch.bin': {
          sha256: '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
          size: 999,
        },
      },
    }

    await expect(fetchAndVerify('/test/size-mismatch.bin', manifest)).rejects.toThrow(ArtifactIntegrityError)
  })

  it('includes cache: no-store in fetch requests', async () => {
    const content = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockBinaryResponse(content))

    const manifest: ArtifactManifest = {
      ...VALID_MANIFEST,
      artifacts: {
        '/test/no-cache.bin': {
          sha256: '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969',
          size: 5,
        },
      },
    }

    await fetchAndVerify('/test/no-cache.bin', manifest)
    expect(fetchSpy).toHaveBeenCalledWith('/test/no-cache.bin', { cache: 'no-store' })
  })
})

// ── verifyManifestNetwork ─────────────────────────────────────────────────────

describe('verifyManifestNetwork', () => {
  it('does not throw when network matches', () => {
    expect(() =>
      verifyManifestNetwork(VALID_MANIFEST, 'Test SDF Network ; September 2015'),
    ).not.toThrow()
  })

  it('throws ManifestIntegrityError when network does not match', () => {
    expect(() =>
      verifyManifestNetwork(VALID_MANIFEST, 'Public Global Stellar Network ; September 2015'),
    ).toThrow(ManifestIntegrityError)
  })
})

// ── loadVerifiedCircuit ───────────────────────────────────────────────────────

describe('loadVerifiedCircuit', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    clearCircuitCache()
  })

  it('loads, verifies, and parses a circuit artifact', async () => {
    const fakeCircuit: CompiledCircuit = {
      noir_version: '1.0.0-beta.9',
      hash: 12345,
      abi: { parameters: [] },
      bytecode: 'abcd',
      debug_symbols: '{}',
      file_map: {},
    }

    const circuitJson = JSON.stringify(fakeCircuit)
    const circuitBytes = new TextEncoder().encode(circuitJson)
    const circuitHash = await sha256(circuitBytes.buffer)

    const testManifest: ArtifactManifest = {
      ...VALID_MANIFEST,
      artifacts: {
        '/test/test_circuit.json': {
          sha256: circuitHash,
          size: circuitBytes.length,
        },
      },
    }

    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(mockJsonResponse(testManifest))
      .mockResolvedValueOnce(
        new Response(circuitBytes, {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )

    const circuit = await loadVerifiedCircuit('/test/test_circuit.json', '/test/manifest.json')
    expect(circuit.noir_version).toBe('1.0.0-beta.9')
    expect(circuit.hash).toBe(12345)
  })

  it('caches the circuit after first load', async () => {
    const fakeCircuit: CompiledCircuit = {
      noir_version: '1.0.0-beta.9',
      hash: 67890,
      abi: { parameters: [] },
      bytecode: 'wxyz',
      debug_symbols: '{}',
      file_map: {},
    }

    const circuitJson = JSON.stringify(fakeCircuit)
    const circuitBytes = new TextEncoder().encode(circuitJson)
    const circuitHash = await sha256(circuitBytes.buffer)

    const testManifest: ArtifactManifest = {
      ...VALID_MANIFEST,
      artifacts: {
        '/test/test_circuit.json': {
          sha256: circuitHash,
          size: circuitBytes.length,
        },
      },
    }

    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(mockJsonResponse(testManifest))
      .mockResolvedValueOnce(
        new Response(circuitBytes, {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )

    const first = await loadVerifiedCircuit('/test/test_circuit.json', '/test/manifest.json')
    expect(first.hash).toBe(67890)

    const second = await loadVerifiedCircuit('/test/test_circuit.json', '/test/manifest.json')
    expect(second.hash).toBe(67890)
    expect(second).toBe(first)
    expect(vi.mocked(globalThis.fetch)).toHaveBeenCalledTimes(2)
  })

  it('clears cache on demand', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(mockJsonResponse(VALID_MANIFEST))

    clearCircuitCache()

    const manifest = await loadManifest('/test/manifest.json')
    expect(manifest.protocol).toBe('harpocrates')
  })
})

// ── ArtifactIntegrityError ────────────────────────────────────────────────────

describe('ArtifactIntegrityError', () => {
  it('exposes artifactPath, expectedDigest, and actualDigest', () => {
    const error = new ArtifactIntegrityError(
      '/noir/evil.json',
      'expected123',
      'actual456',
    )

    expect(error.artifactPath).toBe('/noir/evil.json')
    expect(error.expectedDigest).toBe('expected123')
    expect(error.actualDigest).toBe('actual456')
    expect(error.message).toBe('Proof system integrity check failed')
    expect(error.name).toBe('ArtifactIntegrityError')
  })

  it('does not include artifact hashes in the user-facing message', () => {
    const error = new ArtifactIntegrityError(
      '/noir/evil.json',
      'expected123',
      'actual456',
    )

    expect(error.message).not.toContain('expected123')
    expect(error.message).not.toContain('actual456')
  })
})

// ── ManifestIntegrityError ────────────────────────────────────────────────────

describe('ManifestIntegrityError', () => {
  it('carries a descriptive message', () => {
    const error = new ManifestIntegrityError('test error')
    expect(error.message).toBe('test error')
    expect(error.name).toBe('ManifestIntegrityError')
  })
})

// ── ArtifactFetchError ────────────────────────────────────────────────────────

describe('ArtifactFetchError', () => {
  it('exposes artifactPath and httpStatus', () => {
    const error = new ArtifactFetchError('/noir/missing.json', 404)
    expect(error.artifactPath).toBe('/noir/missing.json')
    expect(error.httpStatus).toBe(404)
    expect(error.message).toBe('Proof system artifact could not be loaded')
    expect(error.name).toBe('ArtifactFetchError')
  })
})
