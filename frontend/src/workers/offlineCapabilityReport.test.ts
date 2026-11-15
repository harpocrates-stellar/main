import { describe, expect, it, vi } from 'vitest'
import browserArtifactManifest from '../../../zk/browser.artifacts.manifest.json'
import {
  PROOF_WORKER_MEMORY_LIMITS,
  buildOfflineWorkerCapabilityReport,
} from '../proofWorkerMemory'
import { ProofWorkerManager } from './proof-worker-manager'

describe('offline worker capability report', () => {
  it('inspects browser capabilities and configured artifact metadata without network or artifact loading', () => {
    const fetchSpy = vi.fn()
    const workerConstructSpy = vi.fn()
    const wasmCompileSpy = vi.fn()

    const syntheticGlobal = {
      Worker: function MockWorker() {
        workerConstructSpy()
      },
      WebAssembly: { compile: wasmCompileSpy },
      crypto: { subtle: {} },
      BigInt,
      ArrayBuffer,
      SharedArrayBuffer,
      crossOriginIsolated: true,
      navigator: { hardwareConcurrency: 12 },
      fetch: fetchSpy,
    } as unknown as typeof globalThis

    const manager = new ProofWorkerManager()
    const report = manager.getOfflineCapabilityReport({ globalObj: syntheticGlobal })

    expect(fetchSpy).not.toHaveBeenCalled()
    expect(workerConstructSpy).not.toHaveBeenCalled()
    expect(wasmCompileSpy).not.toHaveBeenCalled()

    expect(report.reportVersion).toBe(1)
    expect(report.inspectionMode).toBe('offline-static')
    expect(report.networkContacted).toBe(false)
    expect(report.artifactsLoaded).toBe(false)
    expect(report.readyForWorkerProving).toBe(true)

    expect(report.browserSupport.ok).toBe(true)
    expect(report.browserSupport.tier).toBe('supported')
    expect(report.browserSupport.crossOriginIsolated).toBe(true)
    expect(report.browserSupport.sharedArrayBufferAvailable).toBe(true)
    expect(report.browserSupport.maxRecommendedThreads).toBe(8)

    expect(report.configuredArtifacts.metadataValid).toBe(true)
    expect(report.configuredArtifacts.metadataIssues).toEqual([])
    expect(report.configuredArtifacts.manifestFormat).toBe(browserArtifactManifest.format)
    expect(report.configuredArtifacts.toolchain).toEqual({
      nargo: browserArtifactManifest.toolchain.nargo,
      barretenberg: browserArtifactManifest.toolchain.barretenberg,
      provingScheme: browserArtifactManifest.toolchain.proving_scheme,
      oracleHash: browserArtifactManifest.toolchain.oracle_hash,
    })
    expect(report.configuredArtifacts.artifacts).toHaveLength(
      browserArtifactManifest.artifacts.length,
    )
    expect(report.configuredArtifacts.supportedPublicFrames).toEqual([
      'browser_v1',
      'unscoped_v1',
      'scoped_v2',
    ])
    expect(report.memoryBudgets).toEqual(PROOF_WORKER_MEMORY_LIMITS)

    manager.destroy()
  })

  it('falls back to 1 recommended thread when cross-origin isolation is absent', () => {
    const nonIsolatedGlobal = {
      Worker: function MockWorker() {},
      WebAssembly: { compile: () => {} },
      crypto: { subtle: {} },
      BigInt,
      ArrayBuffer,
      SharedArrayBuffer,
      crossOriginIsolated: false,
      navigator: { hardwareConcurrency: 8 },
    } as unknown as typeof globalThis

    const report = buildOfflineWorkerCapabilityReport({ globalObj: nonIsolatedGlobal })
    expect(report.readyForWorkerProving).toBe(true)
    expect(report.browserSupport.maxRecommendedThreads).toBe(1)
  })

  it('marks proving unavailable when required browser capabilities are missing', () => {
    const missingCapabilitiesGlobal = {
      Worker: undefined,
      WebAssembly: undefined,
      crypto: {},
      BigInt,
      ArrayBuffer,
    } as unknown as typeof globalThis

    const report = buildOfflineWorkerCapabilityReport({ globalObj: missingCapabilitiesGlobal })
    expect(report.readyForWorkerProving).toBe(false)
    expect(report.browserSupport.ok).toBe(false)
    expect(report.browserSupport.tier).toBe('unsupported')
    expect(report.browserSupport.missing).toEqual([
      'Worker',
      'moduleWorkerType',
      'WebAssembly',
      'SubtleCrypto',
    ])
    expect(report.configuredArtifacts.metadataValid).toBe(true)
  })

  it('detects malformed or oversized configured artifact metadata fail-closed', () => {
    const validGlobal = {
      Worker: function MockWorker() {},
      WebAssembly: { compile: () => {} },
      crypto: { subtle: {} },
      BigInt,
      ArrayBuffer,
    } as unknown as typeof globalThis

    const brokenManifest = {
      format: 'wrong.format',
      version: 2,
      toolchain: { nargo: '1.0.0-beta.9' },
      artifacts: [
        {
          path: 'frontend/public/noir/silent_witness.json',
          role: 'published_acir',
          raw_bytes: PROOF_WORKER_MEMORY_LIMITS.maxArtifactBytes + 1,
          normalized_bytes: 100,
          raw_sha256: 'not-a-sha256',
          normalized_sha256: 'a'.repeat(64),
        },
      ],
    }

    const report = buildOfflineWorkerCapabilityReport({
      globalObj: validGlobal,
      manifestOverride: brokenManifest,
    })

    expect(report.readyForWorkerProving).toBe(false)
    expect(report.browserSupport.ok).toBe(true)
    expect(report.configuredArtifacts.metadataValid).toBe(false)
    expect(report.configuredArtifacts.metadataIssues).toEqual([
      'invalid_manifest_format',
      'unsupported_manifest_version',
      'incomplete_toolchain_metadata',
      'invalid_artifact_digest:frontend/public/noir/silent_witness.json',
      'artifact_exceeds_memory_limit:frontend/public/noir/silent_witness.json',
    ])
  })
})
