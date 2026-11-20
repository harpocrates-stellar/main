import { describe, expect, it, vi } from 'vitest'
import {
  EXIT_CODES,
  VERIFY_EXIT_CODES,
  helpText,
  resolveBatchExitCode,
  resolveLineageExitCode,
} from '../src/cli.js'
import {
  MAX_LINEAGE_DEPTH,
  MAX_LINEAGE_FANOUT,
  verifyLineageTree,
  type LineageFetcher,
} from '../src/verify-lineage.js'
import type { LineageRecord } from '../src/stellar-lookup.js'

describe('CLI verification exit codes', () => {
  it('assigns distinct exit codes for valid, incomplete, invalid, error, and unavailable', () => {
    const distinct = new Set([
      EXIT_CODES.VALID,
      EXIT_CODES.INCOMPLETE,
      EXIT_CODES.INVALID,
      EXIT_CODES.ERROR,
      EXIT_CODES.UNAVAILABLE,
    ])
    expect(distinct.size).toBe(5)
    expect(EXIT_CODES.VALID).toBe(0)
    expect(EXIT_CODES.INCOMPLETE).toBe(6)
    expect(EXIT_CODES.INVALID).toBe(7)
    expect(EXIT_CODES.ERROR).toBe(8)
    expect(EXIT_CODES.UNAVAILABLE).toBe(9)
    expect(VERIFY_EXIT_CODES.pending).toBe(EXIT_CODES.INCOMPLETE)
    expect(VERIFY_EXIT_CODES.failed).toBe(EXIT_CODES.INVALID)
  })

  it('documents incomplete (6), invalid (7), error (8), and unavailable (9) in help output', () => {
    const help = helpText()
    expect(help).toContain('6   incomplete / pending')
    expect(help).toContain('7   invalid / failed')
    expect(help).toContain('8   error')
    expect(help).toContain('9   unavailable')
  })
})

describe('verifyLineageTree + resolveLineageExitCode', () => {
  it('returns unavailable (9) when getLineage throws', async () => {
    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async () => {
        throw new Error('RPC connection refused')
      }),
      getProofStatus: vi.fn(async () => 'valid'),
    }

    const result = await verifyLineageTree('root_digest', fetcher)
    expect(result.success).toBe(false)
    expect(result.unavailableCount).toBe(1)
    expect(result.incompleteCount).toBe(0)
    expect(result.missingCount).toBe(0)
    expect(resolveLineageExitCode(result)).toBe(EXIT_CODES.UNAVAILABLE)
  })

  it('returns unavailable (9) rather than missing (3) when getProofStatus throws', async () => {
    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async () => null),
      getProofStatus: vi.fn(async () => {
        throw new Error('RPC timeout')
      }),
    }

    const result = await verifyLineageTree('leaf_digest', fetcher)
    expect(result.success).toBe(false)
    expect(result.unavailableCount).toBe(1)
    expect(result.missingCount).toBe(0)
    expect(resolveLineageExitCode(result)).toBe(EXIT_CODES.UNAVAILABLE)
  })

  it('returns incomplete (6) when depth bound truncates lineage traversal', async () => {
    const lineages: Record<string, LineageRecord> = {}
    for (let i = 0; i <= MAX_LINEAGE_DEPTH + 1; i++) {
      lineages[`level_${i}`] = {
        parentProofIds: [`level_${i + 1}`],
        parentCommitments: ['c'],
        manifestDigest: `m${i}`,
        actor: 'GACTOR',
        operationType: 'crop',
        outputDigest: `level_${i}`,
        depth: i + 1,
      }
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async () => 'valid'),
    }

    const result = await verifyLineageTree('level_0', fetcher, { maxDepth: MAX_LINEAGE_DEPTH })
    expect(result.success).toBe(false)
    expect(result.incompleteCount).toBe(1)
    expect(result.unavailableCount).toBe(0)
    expect(resolveLineageExitCode(result)).toBe(EXIT_CODES.INCOMPLETE)
  })

  it('returns incomplete (6) when fan-out bound truncates lineage traversal', async () => {
    const lineages: Record<string, LineageRecord> = {
      fanout_node: {
        parentProofIds: ['p1', 'p2', 'p3', 'p4', 'p5'],
        parentCommitments: ['c1', 'c2', 'c3', 'c4', 'c5'],
        manifestDigest: 'm',
        actor: 'GACTOR',
        operationType: 'compose',
        outputDigest: 'fanout_node',
        depth: 1,
      },
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async () => 'valid'),
    }

    const result = await verifyLineageTree('fanout_node', fetcher, { maxFanout: MAX_LINEAGE_FANOUT })
    expect(result.success).toBe(false)
    expect(result.incompleteCount).toBe(1)
    expect(resolveLineageExitCode(result)).toBe(EXIT_CODES.INCOMPLETE)
  })

  it('returns invalid (7) when an ancestor is disputed or a cycle is detected', async () => {
    const disputedFetcher: LineageFetcher = {
      getLineage: vi.fn(async () => null),
      getProofStatus: vi.fn(async () => 'disputed'),
    }
    const disputedResult = await verifyLineageTree('disputed_leaf', disputedFetcher)
    expect(disputedResult.success).toBe(false)
    expect(resolveLineageExitCode(disputedResult)).toBe(EXIT_CODES.INVALID)

    const cycleFetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => ({
        parentProofIds: [digest === 'a' ? 'b' : 'a'],
        parentCommitments: ['c'],
        manifestDigest: 'm',
        actor: 'GACTOR',
        operationType: 'crop',
        outputDigest: digest,
        depth: 1,
      })),
      getProofStatus: vi.fn(async () => 'valid'),
    }
    const cycleResult = await verifyLineageTree('a', cycleFetcher)
    expect(cycleResult.success).toBe(false)
    expect(cycleResult.cycleDetected).toBe(true)
    expect(resolveLineageExitCode(cycleResult)).toBe(EXIT_CODES.INVALID)
  })
})

describe('resolveBatchExitCode', () => {
  it('never reports an empty batch as success (0)', () => {
    expect(resolveBatchExitCode([])).toBe(EXIT_CODES.INCOMPLETE)
  })

  it('returns 0 only when every check in a non-empty batch succeeds', () => {
    expect(resolveBatchExitCode([EXIT_CODES.VALID, EXIT_CODES.VALID])).toBe(EXIT_CODES.VALID)
  })

  it('never reports skipped/incomplete checks as success', () => {
    expect(resolveBatchExitCode([EXIT_CODES.VALID, EXIT_CODES.INCOMPLETE])).toBe(EXIT_CODES.INCOMPLETE)
  })

  it('prioritizes invalid > unavailable > incomplete > valid', () => {
    expect(resolveBatchExitCode([EXIT_CODES.VALID, EXIT_CODES.INCOMPLETE, EXIT_CODES.UNAVAILABLE])).toBe(
      EXIT_CODES.UNAVAILABLE,
    )
    expect(
      resolveBatchExitCode([EXIT_CODES.VALID, EXIT_CODES.INCOMPLETE, EXIT_CODES.UNAVAILABLE, EXIT_CODES.INVALID]),
    ).toBe(EXIT_CODES.INVALID)
    expect(resolveBatchExitCode([EXIT_CODES.INVALID, EXIT_CODES.REVOKED])).toBe(EXIT_CODES.REVOKED)
  })
})
