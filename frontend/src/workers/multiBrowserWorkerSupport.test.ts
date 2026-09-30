import { describe, expect, it } from 'vitest'
import {
  browserBuildTargets,
  browserSupportMatrix,
  requiredBrowserCapabilities,
} from '../../browser-support.mjs'
import {
  MULTI_BROWSER_WORKER_EXPECTATIONS,
  PROOF_WORKER_CAPABILITIES,
  assessWorkerSupport,
  detectWorkerCapabilities,
  expectationFor,
  expectedDocumentedCapabilities,
  expectedWorkerBuildTargets,
  matrixRequiresModuleWorkers,
  assertWorkerSupportOrThrow,
} from './multiBrowserWorkerSupport'

describe('multi-browser proof worker support', () => {
  it('aligns worker expectations 1:1 with the canonical browser support matrix', () => {
    expect(MULTI_BROWSER_WORKER_EXPECTATIONS).toHaveLength(browserSupportMatrix.length)
    for (const entry of browserSupportMatrix) {
      const row = expectationFor(entry.browser, entry.platform)
      expect(row).not.toBeNull()
      expect(row!.minimum).toBe(entry.minimum)
      expect(row!.tier).toBe(entry.tier)
      expect(row!.moduleWorkersRequired).toBe(true)
    }
  })

  it('requires module Web Workers in the documented capability floor', () => {
    expect(matrixRequiresModuleWorkers()).toBe(true)
    expect(expectedDocumentedCapabilities()).toEqual(requiredBrowserCapabilities)
    expect(expectedWorkerBuildTargets()).toEqual(browserBuildTargets)
  })

  it('marks supported desktop browsers as full worker proving surfaces', () => {
    for (const browser of ['Chrome', 'Edge', 'Firefox']) {
      const row = expectationFor(browser, 'desktop')
      expect(row?.tier).toBe('supported')
      expect(row?.moduleWorkersRequired).toBe(true)
      expect(row?.memoryConstrained).toBe(false)
    }
    const safariMac = expectationFor('Safari', 'macOS')
    expect(safariMac?.tier).toBe('supported')
    expect(safariMac?.memoryConstrained).toBe(false)
  })

  it('keeps iOS/iPadOS Safari as best-effort and memory-constrained', () => {
    const ios = expectationFor('Safari', 'iOS/iPadOS')
    expect(ios?.tier).toBe('best-effort')
    expect(ios?.moduleWorkersRequired).toBe(true)
    expect(ios?.memoryConstrained).toBe(true)
  })

  it('fail-closes unknown browsers instead of inventing a support tier', () => {
    expect(expectationFor('Internet Explorer', 'desktop')).toBeNull()
    expect(expectationFor('Chrome', 'watchOS')).toBeNull()
  })

  it('detects proof-worker capabilities on the current test runtime', () => {
    const snapshot = detectWorkerCapabilities()
    for (const id of PROOF_WORKER_CAPABILITIES) {
      expect(typeof snapshot[id]).toBe('boolean')
    }
    // jsdom + @vitest/web-worker provides Worker; WebAssembly/BigInt/ArrayBuffer are standard.
    expect(snapshot.Worker).toBe(true)
    expect(snapshot.WebAssembly).toBe(true)
    expect(snapshot.BigInt).toBe(true)
    expect(snapshot.ArrayBuffer).toBe(true)
  })

  it('assesses the current runtime as worker-capable (positive path)', () => {
    const assessment = assessWorkerSupport()
    expect(assessment.ok).toBe(true)
    expect(assessment.tier).toBe('supported')
    expect(assessment.missing).toEqual([])
    expect(assessment.reason).not.toMatch(/secret|witness|nullifier|credential|key|media/i)
    expect(() => assertWorkerSupportOrThrow()).not.toThrow()
  })

  it('fail-closes when Worker is missing (negative / dependency-failure)', () => {
    const fake = {
      ...globalThis,
      Worker: undefined,
      WebAssembly,
      BigInt,
      ArrayBuffer,
      crypto: globalThis.crypto,
    } as unknown as typeof globalThis
    const assessment = assessWorkerSupport(fake)
    expect(assessment.ok).toBe(false)
    expect(assessment.tier).toBe('unsupported')
    expect(assessment.missing).toContain('Worker')
    expect(assessment.reason).toContain('Worker')
    expect(assessment.reason).not.toMatch(/secret|witness|nullifier|credential|private.?key|media/i)
    expect(() => assertWorkerSupportOrThrow(fake)).toThrow(/unavailable/i)
  })

  it('fail-closes when WebAssembly is missing (unsupported environment)', () => {
    const fake = Object.create(globalThis) as typeof globalThis
    Object.defineProperty(fake, 'WebAssembly', { value: undefined, configurable: true })
    Object.defineProperty(fake, 'Worker', { value: globalThis.Worker, configurable: true })
    const assessment = assessWorkerSupport(fake)
    expect(assessment.ok).toBe(false)
    expect(assessment.missing).toContain('WebAssembly')
    expect(assessment.reason).toMatch(/WebAssembly/)
  })

  it('fail-closes when SubtleCrypto is unavailable (secure-context boundary)', () => {
    const fake = {
      Worker: globalThis.Worker,
      WebAssembly,
      BigInt,
      ArrayBuffer,
      crypto: {},
    } as unknown as typeof globalThis
    const assessment = assessWorkerSupport(fake)
    expect(assessment.ok).toBe(false)
    expect(assessment.missing).toContain('SubtleCrypto')
    expect(assessment.reason).toMatch(/SubtleCrypto/)
  })

  it('never embeds secret-like payloads in assessment reasons (privacy regression)', () => {
    const poison = 'credentialSecret=supersecret nullifier=aabb witness=99 media=/tmp/x.mp4'
    const fake = {
      Worker: undefined,
      WebAssembly: undefined,
      BigInt,
      ArrayBuffer,
      crypto: {},
      // Deliberately noisy environment fields — assessment must ignore them.
      __poison: poison,
    } as unknown as typeof globalThis
    const assessment = assessWorkerSupport(fake)
    expect(assessment.reason).not.toContain('supersecret')
    expect(assessment.reason).not.toContain('aabb')
    expect(assessment.reason).not.toContain('.mp4')
    expect(assessment.reason).not.toContain(poison)
  })

  it('keeps build targets unique and non-empty for worker-backed releases', () => {
    expect(browserBuildTargets.length).toBeGreaterThanOrEqual(5)
    expect(new Set(browserBuildTargets).size).toBe(browserBuildTargets.length)
    for (const target of ['chrome111', 'edge111', 'firefox114', 'safari16.4', 'ios16.4']) {
      expect(browserBuildTargets).toContain(target)
    }
  })
})
