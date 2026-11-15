import { describe, it, expect, beforeAll } from 'vitest'
import { spawnSync, execSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  createProofManifest,
  manifestStatementHash,
  normalizeManifest,
  parseManifest,
  serializeManifest,
  MAX_EXTENSION_DEPTH,
  MAX_MANIFEST_EXTENSIONS,
} from '../src/manifest.js'
import { classifyVerification } from '../src/normalize.js'

const __filename = fileURLToPath(import.meta.url)
const cliRoot = resolve(__filename, '..', '..')
const distCli = resolve(cliRoot, 'dist', 'cli.js')
const CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4'

const BASE_INPUT = {
  proofId: 'A0'.repeat(32),
  tier: 'silent' as const,
  network: 'Test SDF Network ; September 2015',
  contractId: CONTRACT_ID,
  transactionRef: 'B1'.repeat(32),
  videoHash: 'C2'.repeat(32),
  metadataHash: 'D3'.repeat(32),
  sourceHash: 'E4'.repeat(32),
  timestamp: '2026-07-24T12:00:00.000Z',
}

function runCliStdin(args: string[], stdin: string) {
  const res = spawnSync(process.execPath, [distCli, ...args], {
    cwd: cliRoot,
    encoding: 'utf-8',
    input: stdin,
  })
  return {
    status: res.status,
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
  }
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npm run build', { cwd: cliRoot, stdio: 'pipe' })
  }
})

describe('Manifest optional extensions — SDK normalization and critical identity', () => {
  it('round-trips unknown optional extensions without altering critical statement identity', () => {
    const base = normalizeManifest(createProofManifest(BASE_INPUT))
    const withExtRaw = JSON.stringify({
      ...createProofManifest(BASE_INPUT),
      extensions: {
        'org.example.audit-trail': {
          zField: [3, 1, 2],
          aField: 'ticket-42',
          required: false,
        },
        'io.archive.mirror': 'ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
      },
    })

    const normalized = normalizeManifest(withExtRaw)
    expect(normalized.proofId).toBe(BASE_INPUT.proofId.toLowerCase())
    expect(normalized.extensions).toEqual({
      'io.archive.mirror': 'ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
      'org.example.audit-trail': {
        aField: 'ticket-42',
        required: false,
        zField: [3, 1, 2],
      },
    })

    // Critical statement identity must match byte-for-byte with and without optional extensions
    expect(manifestStatementHash(normalized)).toBe(manifestStatementHash(base))

    // Re-serializing and parsing round-trips nested extension keys deterministically
    const reserialized = serializeManifest(normalized)
    expect(parseManifest(reserialized)).toEqual(normalized)
    expect(Object.keys((JSON.parse(reserialized) as { extensions: Record<string, unknown> }).extensions)).toEqual([
      'io.archive.mirror',
      'org.example.audit-trail',
    ])
  })

  it('preserves verification classification when optional extensions are present', () => {
    const manifest = normalizeManifest({
      ...createProofManifest(BASE_INPUT),
      extensions: {
        'org.newsroom.desk': { deskId: 'investigative-eu', critical: false },
      },
    })
    const tx = { status: 'confirmed' as const, txHash: manifest.transactionRef, contractMatch: true }
    const record = {
      videoHash: manifest.videoHash,
      metadataHash: manifest.metadataHash,
      tier: 1,
      status: 1,
      createdAt: '1000',
      source: null,
      issuer: null,
    }
    expect(classifyVerification(manifest, tx, record)).toBe('valid')
  })

  it('rejects unsupported required extensions via required:true, critical:true, or criticalExtensions', () => {
    const base = createProofManifest(BASE_INPUT)

    expect(() =>
      parseManifest(
        JSON.stringify({
          ...base,
          extensions: {
            'org.example.policy-gate': { required: true, policyVersion: 2 },
          },
        }),
      ),
    ).toThrow('unsupported required manifest extension: org.example.policy-gate')

    expect(() =>
      parseManifest(
        JSON.stringify({
          ...base,
          extensions: {
            'org.example.mandatory-sig': { critical: true, alg: 'ed25519' },
          },
        }),
      ),
    ).toThrow('unsupported required manifest extension: org.example.mandatory-sig')

    expect(() =>
      parseManifest(
        JSON.stringify({
          ...base,
          extensions: {
            'org.example.custom': { note: 'hello' },
          },
          criticalExtensions: ['org.example.custom'],
        }),
      ),
    ).toThrow('unsupported required manifest extension: org.example.custom')
  })

  it('accepts required extensions only when explicitly allowlisted in supportedExtensions', () => {
    const base = createProofManifest(BASE_INPUT)
    const raw = JSON.stringify({
      ...base,
      extensions: {
        'org.example.policy-gate': { required: true, policyVersion: 2 },
      },
      criticalExtensions: ['org.example.policy-gate'],
    })

    const parsed = normalizeManifest(raw, {
      supportedExtensions: new Set(['org.example.policy-gate']),
    })
    expect(parsed.extensions?.['org.example.policy-gate']).toEqual({
      policyVersion: 2,
      required: true,
    })
    expect(parsed.criticalExtensions).toEqual(['org.example.policy-gate'])
  })

  it('rejects sensitive/witness fields, invalid names, excessive count, and excessive depth in extensions', () => {
    const base = createProofManifest(BASE_INPUT)

    expect(() =>
      parseManifest(
        JSON.stringify({
          ...base,
          extensions: { 'org.example.leak': { nested: { nullifierSecret: 'deadbeef' } } },
        }),
      ),
    ).toThrow('prohibited sensitive field')

    expect(() =>
      parseManifest(
        JSON.stringify({
          ...base,
          extensions: { 'org.example.witness-leak': 'value' },
        }),
      ),
    ).toThrow('prohibited sensitive field')

    expect(() =>
      parseManifest(
        JSON.stringify({
          ...base,
          extensions: { ' invalid space ': 'x' },
        }),
      ),
    ).toThrow('is invalid')

    // Exceeding MAX_MANIFEST_EXTENSIONS
    const tooMany: Record<string, string> = {}
    for (let i = 0; i <= MAX_MANIFEST_EXTENSIONS; i++) {
      tooMany[`ext.${i}`] = 'ok'
    }
    expect(() => parseManifest(JSON.stringify({ ...base, extensions: tooMany }))).toThrow(
      'exceed maximum count',
    )

    // Exceeding MAX_EXTENSION_DEPTH
    let deep: unknown = 'leaf'
    for (let i = 0; i <= MAX_EXTENSION_DEPTH + 1; i++) {
      deep = { child: deep }
    }
    expect(() =>
      parseManifest(JSON.stringify({ ...base, extensions: { 'org.example.deep': deep } })),
    ).toThrow('exceeds maximum depth')
  })
})

describe('CLI manifest --normalize and verify extension handling', () => {
  it('normalizes a manifest via CLI while preserving unknown optional extensions', () => {
    const inputManifest = {
      ...createProofManifest(BASE_INPUT),
      extensions: {
        'org.example.workflow': { reviewer: 'bot-1', step: 2 },
      },
    }
    const res = runCliStdin(['manifest', '--normalize', '--input', '-', '--format', 'text'], JSON.stringify(inputManifest))
    expect(res.status).toBe(0)
    expect(res.stderr).toBe('')

    const normalized = JSON.parse(res.stdout.trim())
    expect(normalized.proofId).toBe(BASE_INPUT.proofId.toLowerCase())
    expect(normalized.extensions).toEqual({
      'org.example.workflow': { reviewer: 'bot-1', step: 2 },
    })
  })

  it('preserves optional extensions in verify --offline receipt output', () => {
    const inputManifest = {
      ...createProofManifest(BASE_INPUT),
      extensions: {
        'org.example.bundle-hint': { region: 'eu-central' },
      },
    }
    const res = runCliStdin(
      ['verify', '--manifest', '-', '--contract-id', CONTRACT_ID, '--offline', '--output', 'json'],
      JSON.stringify(inputManifest),
    )
    expect(res.status).toBe(6)
    const receipt = JSON.parse(res.stdout.trim())
    expect(receipt.manifest.extensions).toEqual({
      'org.example.bundle-hint': { region: 'eu-central' },
    })
  })

  it('exits 8 fail-closed on unsupported required extensions in both manifest --normalize and verify', () => {
    const unsupportedRequired = JSON.stringify({
      ...createProofManifest(BASE_INPUT),
      extensions: {
        'org.example.strict-gate': { required: true },
      },
    })

    const normRes = runCliStdin(['manifest', '--normalize', '--input', '-'], unsupportedRequired)
    expect(normRes.status).toBe(8)
    expect(normRes.stdout).toBe('')
    expect(normRes.stderr).toContain('unsupported required manifest extension: org.example.strict-gate')

    const verifyRes = runCliStdin(
      ['verify', '--manifest', '-', '--contract-id', CONTRACT_ID, '--offline', '--output', 'json'],
      unsupportedRequired,
    )
    expect(verifyRes.status).toBe(8)
    expect(verifyRes.stdout).toBe('')
    expect(verifyRes.stderr).toContain('unsupported required manifest extension: org.example.strict-gate')
  })
})
