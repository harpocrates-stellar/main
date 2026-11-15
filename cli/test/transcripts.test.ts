import { describe, it, expect, beforeAll } from 'vitest'
import { spawnSync, execSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DYNAMIC_ISO_PLACEHOLDER,
  TRANSCRIPT_PROTOCOL,
  TRANSCRIPT_SCHEMA_VERSION,
  normalizeTranscriptOutput,
  parseTranscriptSuite,
  verifyTranscriptCase,
  verifyTranscriptSuite,
  type CliTranscriptCase,
} from '../src/transcripts.js'
import { parseLineageFixture, createFixtureLineageFetcher, verifyLineageTree } from '../src/verify-lineage.js'

const __filename = fileURLToPath(import.meta.url)
const cliRoot = resolve(__filename, '..', '..')
const distCli = resolve(cliRoot, 'dist', 'cli.js')
const fixturePath = fileURLToPath(
  new URL('../../devx/fixtures/cli-transcripts/transcripts.json', import.meta.url),
)

function runCliCase(entry: CliTranscriptCase) {
  const dir = mkdtempSync(join(tmpdir(), 'harpocrates-transcript-test-'))
  try {
    for (const file of entry.files ?? []) {
      writeFileSync(join(dir, file.name), file.content, 'utf-8')
    }
    const argv = entry.argv.map((arg) => arg.replaceAll('{{dir}}', dir))
    const res = spawnSync(process.execPath, [distCli, ...argv], {
      cwd: dir,
      encoding: 'utf-8',
      input: entry.stdin,
      env: {
        PATH: process.env.PATH ?? '',
        // Point default RPC to an closed local port to guarantee zero network reliance
        HARPOCRATES_RPC_URL: 'http://127.0.0.1:1',
      },
    })
    return {
      exitCode: res.status ?? 1,
      stdout: res.stdout ?? '',
      stderr: res.stderr ?? '',
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

beforeAll(() => {
  if (!existsSync(distCli)) {
    execSync('npm run build', { cwd: cliRoot, stdio: 'pipe' })
  }
  expect(existsSync(distCli)).toBe(true)
})

describe('Committed reproducible CLI transcript fixtures', () => {
  const rawSuite = readFileSync(fixturePath, 'utf-8')
  const suite = parseTranscriptSuite(rawSuite)

  it('validates the committed suite metadata and case coverage', () => {
    expect(suite.protocol).toBe(TRANSCRIPT_PROTOCOL)
    expect(suite.schemaVersion).toBe(TRANSCRIPT_SCHEMA_VERSION)
    expect(suite.cases.length).toBeGreaterThanOrEqual(10)
    const ids = suite.cases.map((c) => c.id)
    expect(ids).toContain('hash-stdin-json')
    expect(ids).toContain('manifest-from-metadata')
    expect(ids).toContain('verify-offline-pending')
    expect(ids).toContain('verify-lineage-valid')
    expect(ids).toContain('verify-lineage-revoked-ancestor')
    expect(ids).toContain('verify-lineage-cycle-detected')
  })

  const executedResults = new Map<string, ReturnType<typeof runCliCase>>()

  it.each(suite.cases.map((c) => [c.id, c] as const))(
    'reproduces transcript "%s" without network endpoints',
    async (_id, entry) => {
      const actual = runCliCase(entry)
      executedResults.set(entry.id, actual)
      const outcome = await verifyTranscriptCase(entry, () => actual)
      expect(outcome.mismatches).toEqual([])
      expect(outcome.passed).toBe(true)
    },
  )

  it('verifies the full suite via verifyTranscriptSuite', async () => {
    const summary = await verifyTranscriptSuite(
      suite,
      (entry) => executedResults.get(entry.id) ?? runCliCase(entry),
    )
    expect(summary.passed).toBe(true)
    expect(summary.failed).toBe(0)
    expect(summary.total).toBe(suite.cases.length)
  })
})

describe('Transcript validator and runner boundary checks', () => {
  const baseSuite = {
    protocol: TRANSCRIPT_PROTOCOL,
    schemaVersion: TRANSCRIPT_SCHEMA_VERSION,
    description: 'Synthetic test suite',
    cases: [
      {
        id: 'sample-help',
        description: 'Print help',
        argv: ['help'],
        expected: {
          exitCode: 0,
          stdout: 'Usage:\n',
          stderr: '',
        },
      },
    ],
  }

  it('rejects malformed JSON and unsupported schema versions', () => {
    expect(() => parseTranscriptSuite('{not-json')).toThrow('not valid JSON')
    expect(() =>
      parseTranscriptSuite(JSON.stringify({ ...baseSuite, schemaVersion: 99 })),
    ).toThrow('unsupported transcript suite schemaVersion')
    expect(() =>
      parseTranscriptSuite(JSON.stringify({ ...baseSuite, protocol: 'other' })),
    ).toThrow('protocol must be')
  })

  it('rejects duplicate case IDs, path traversal, and real media extensions', () => {
    expect(() =>
      parseTranscriptSuite(
        JSON.stringify({
          ...baseSuite,
          cases: [baseSuite.cases[0], baseSuite.cases[0]],
        }),
      ),
    ).toThrow('duplicate transcript case id')

    expect(() =>
      parseTranscriptSuite(
        JSON.stringify({
          ...baseSuite,
          cases: [
            {
              ...baseSuite.cases[0],
              files: [{ name: '../escape.json', content: '{}' }],
            },
          ],
        }),
      ),
    ).toThrow('must be a relative filename')

    expect(() =>
      parseTranscriptSuite(
        JSON.stringify({
          ...baseSuite,
          cases: [
            {
              ...baseSuite.cases[0],
              files: [{ name: 'evidence.mp4', content: 'bytes' }],
            },
          ],
        }),
      ),
    ).toThrow('prohibited media or witness extension')
  })

  it('rejects secrets, private keys, and witness material in fixtures', () => {
    expect(() =>
      parseTranscriptSuite(
        JSON.stringify({
          ...baseSuite,
          cases: [
            {
              ...baseSuite.cases[0],
              stdin: '{"nullifierSecret":"abcd"}',
            },
          ],
        }),
      ),
    ).toThrow('prohibited secret or witness material')

    expect(() =>
      parseTranscriptSuite(
        JSON.stringify({
          ...baseSuite,
          cases: [
            {
              ...baseSuite.cases[0],
              stdin: '{"witnessData":"private"}',
            },
          ],
        }),
      ),
    ).toThrow('prohibited secret or witness material')
  })

  it('reports mismatches fail-closed when an implementation drifts', async () => {
    const entry = baseSuite.cases[0]
    const drift = await verifyTranscriptCase(entry, () => ({
      exitCode: 8,
      stdout: 'wrong\n',
      stderr: 'harpocrates: error\n',
    }))
    expect(drift.passed).toBe(false)
    expect(drift.mismatches).toHaveLength(3)
  })

  it('normalizes dynamic ISO-8601 verifiedAt fields only when requested', () => {
    const sample = '{"verifiedAt": "2026-11-15T12:34:56.789Z"}'
    expect(normalizeTranscriptOutput(sample, false)).toBe(sample)
    expect(normalizeTranscriptOutput(sample, true)).toBe(
      `{"verifiedAt": "${DYNAMIC_ISO_PLACEHOLDER}"}`,
    )
  })
})

describe('Offline lineage fixture parser and CLI boundary', () => {
  it('parses valid synthetic lineage fixtures and rejects malformed ones', async () => {
    const valid = parseLineageFixture(
      JSON.stringify({
        lineages: {
          root: {
            parentProofIds: ['leaf'],
            operationType: 'crop',
          },
        },
        proofs: {
          leaf: 'valid',
        },
      }),
    )
    const tree = await verifyLineageTree('root', createFixtureLineageFetcher(valid))
    expect(tree.success).toBe(true)

    expect(() => parseLineageFixture('not-json')).toThrow('not valid JSON')
    expect(() =>
      parseLineageFixture(JSON.stringify({ lineages: {}, proofs: {}, extra: true })),
    ).toThrow('unsupported fields')
    expect(() =>
      parseLineageFixture(JSON.stringify({ lineages: {}, proofs: { leaf: 'bogus' } })),
    ).toThrow('invalid status')
  })

  it('exits 8 cleanly when --fixture points to malformed JSON in verify-lineage', () => {
    const res = runCliCase({
      id: 'bad-lineage-fixture',
      description: 'Malformed lineage fixture',
      argv: [
        'verify-lineage',
        '--output-digest',
        'aa'.repeat(32),
        '--contract-id',
        'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4',
        '--fixture',
        '{{dir}}/bad.json',
      ],
      files: [{ name: 'bad.json', content: '{malformed' }],
      expected: { exitCode: 8, stdout: '', stderr: '' },
    })
    expect(res.exitCode).toBe(8)
    expect(res.stdout).toBe('')
    expect(res.stderr).toContain('harpocrates: invalid or unreadable lineage fixture')
  })
})
