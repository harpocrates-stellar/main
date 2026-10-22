import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Account, Address, StrKey, xdr } from '@stellar/stellar-sdk'

const { getAccountMock, simulateTransactionMock, ServerMock } = vi.hoisted(() => {
  const getAccountMock = vi.fn()
  const simulateTransactionMock = vi.fn()
  const ServerMock = vi.fn(() => ({
    getAccount: getAccountMock,
    simulateTransaction: simulateTransactionMock,
  }))
  return { getAccountMock, simulateTransactionMock, ServerMock }
})

vi.mock('@stellar/stellar-sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@stellar/stellar-sdk')>()
  return {
    ...actual,
    rpc: {
      ...actual.rpc,
      Server: ServerMock,
      Api: {
        ...actual.rpc.Api,
        isSimulationError: (sim: unknown) =>
          Boolean(sim && typeof sim === 'object' && 'error' in sim && (sim as { error?: unknown }).error),
        isSimulationSuccess: (sim: unknown) =>
          Boolean(sim && typeof sim === 'object' && 'result' in sim && !('error' in sim)),
        isSimulationRestore: () => false,
      },
    },
  }
})

import { lookupLineage, MalformedLineageError } from '../src/stellar-lookup.js'
import { handleLineage, LINEAGE_EXIT_CODES } from '../src/lineage.js'
import { parseCliArgs } from '../src/args.js'

const CONTRACT_ID = StrKey.encodeContract(Uint8Array.from({ length: 32 }, (_, i) => i + 1))
const SOURCE_ADDRESS = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF'
const NETWORK = 'Test SDF Network ; September 2015'
const OUTPUT_DIGEST = 'cd'.repeat(32)
const PARENT_A = 'a1'.repeat(32)
const PARENT_B = 'b2'.repeat(32)
const MANIFEST_DIGEST = 'ee'.repeat(32)
const COMMITMENT = 'f0'.repeat(32)

const bytes = (hex: string) => xdr.ScVal.scvBytes(Buffer.from(hex, 'hex'))

function lineageStruct(overrides: Record<string, xdr.ScVal | undefined> = {}): xdr.ScVal {
  const fields: Record<string, xdr.ScVal | undefined> = {
    actor: new Address(SOURCE_ADDRESS).toScVal(),
    depth: xdr.ScVal.scvU32(2),
    manifest_digest: bytes(MANIFEST_DIGEST),
    operation_type: xdr.ScVal.scvSymbol('crop'),
    output_digest: bytes(OUTPUT_DIGEST),
    parent_commitments: xdr.ScVal.scvVec([bytes(COMMITMENT), bytes(COMMITMENT)]),
    parent_proof_ids: xdr.ScVal.scvVec([bytes(PARENT_A), bytes(PARENT_B)]),
    ...overrides,
  }
  return xdr.ScVal.scvMap(
    Object.keys(fields)
      .sort()
      .filter((key) => fields[key] !== undefined)
      .map((key) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val: fields[key] as xdr.ScVal })),
  )
}

function mockRetval(retval: xdr.ScVal): void {
  simulateTransactionMock.mockResolvedValue({ result: { retval } })
}

class ExitSignal extends Error {
  readonly code: number
  constructor(code: number) {
    super(`exit(${code})`)
    this.code = code
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  getAccountMock.mockResolvedValue(new Account(SOURCE_ADDRESS, '1'))
})

describe('lookupLineage', () => {
  const options = { rpcUrl: 'https://rpc.example.org', sourceAddress: SOURCE_ADDRESS, networkPassphrase: NETWORK }

  it('decodes an existing lineage record', async () => {
    mockRetval(lineageStruct())

    const record = await lookupLineage(CONTRACT_ID, OUTPUT_DIGEST.toUpperCase(), options)

    expect(record).toEqual({
      outputDigest: OUTPUT_DIGEST,
      parentProofIds: [PARENT_A, PARENT_B],
      transformationKind: 'crop',
      depth: 2,
    })
    expect(ServerMock).toHaveBeenCalledWith('https://rpc.example.org')
    expect(getAccountMock).toHaveBeenCalledWith(SOURCE_ADDRESS)
    expect(simulateTransactionMock).toHaveBeenCalledTimes(1)
  })

  it('returns null when the registry has no record', async () => {
    mockRetval(xdr.ScVal.scvVoid())
    await expect(lookupLineage(CONTRACT_ID, OUTPUT_DIGEST, options)).resolves.toBeNull()
  })

  it.each<[string, xdr.ScVal]>([
    ['a non-struct value', xdr.ScVal.scvU32(7)],
    ['missing parent ids', lineageStruct({ parent_proof_ids: undefined })],
    ['a short parent id', lineageStruct({ parent_proof_ids: xdr.ScVal.scvVec([bytes('ab')]) })],
    ['missing transformation kind', lineageStruct({ operation_type: undefined })],
    ['a non-numeric depth', lineageStruct({ depth: xdr.ScVal.scvSymbol('deep') })],
    ['a mismatched output digest', lineageStruct({ output_digest: bytes('00'.repeat(32)) })],
  ])('throws MalformedLineageError for %s', async (_label, retval) => {
    mockRetval(retval)
    await expect(lookupLineage(CONTRACT_ID, OUTPUT_DIGEST, options)).rejects.toBeInstanceOf(MalformedLineageError)
  })

  it('propagates simulation errors', async () => {
    simulateTransactionMock.mockResolvedValue({ error: 'HostError: boom' })
    await expect(lookupLineage(CONTRACT_ID, OUTPUT_DIGEST, options)).rejects.toThrow('HostError: boom')
  })

  it('rejects an invalid digest before constructing rpc.Server', async () => {
    await expect(lookupLineage(CONTRACT_ID, 'not-hex', options)).rejects.toThrow(
      'outputDigest must be a 32-byte hex string',
    )
    expect(ServerMock).not.toHaveBeenCalled()
  })
})

describe('lineage CLI command', () => {
  let stdoutChunks: string[]
  let stderrChunks: string[]

  beforeEach(() => {
    stdoutChunks = []
    stderrChunks = []
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stdoutChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    })
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderrChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    })
    vi.spyOn(process, 'exit').mockImplementation(((code?: string | number | null) => {
      throw new ExitSignal(Number(code ?? 0))
    }) as never)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  async function run(extra: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
    const { flags } = parseCliArgs([
      'lineage',
      '--contract-id',
      CONTRACT_ID,
      '--rpc-url',
      'https://rpc.example.org',
      '--source-address',
      SOURCE_ADDRESS,
      ...extra,
    ])
    try {
      await handleLineage(flags)
    } catch (err) {
      if (err instanceof ExitSignal) {
        return { code: err.code, stdout: stdoutChunks.join(''), stderr: stderrChunks.join('') }
      }
      throw err
    }
    throw new Error('Expected lineage command to exit')
  }

  function expectNoMetadata(output: string): void {
    expect(output).not.toContain(MANIFEST_DIGEST)
    expect(output).not.toContain(COMMITMENT)
    expect(output).not.toContain(SOURCE_ADDRESS)
  }

  it('prints parents, transformation kind and depth in text mode', async () => {
    mockRetval(lineageStruct())

    const { code, stdout, stderr } = await run(['--output-digest', OUTPUT_DIGEST])

    expect(code).toBe(LINEAGE_EXIT_CODES.found)
    expect(stderr).toBe('')
    expect(stdout).toContain(`Output digest:  ${OUTPUT_DIGEST}`)
    expect(stdout).toContain('Transformation: crop')
    expect(stdout).toContain('Depth:          2')
    expect(stdout).toContain(`  - ${PARENT_A}`)
    expect(stdout).toContain(`  - ${PARENT_B}`)
    expectNoMetadata(stdout)
  })

  it('prints a stable JSON shape in JSON mode', async () => {
    mockRetval(lineageStruct())

    const { code, stdout } = await run(['--output-digest', OUTPUT_DIGEST, '--output', 'json'])

    expect(code).toBe(0)
    expect(JSON.parse(stdout)).toEqual({
      outputDigest: OUTPUT_DIGEST,
      contractId: CONTRACT_ID,
      network: NETWORK,
      transformationKind: 'crop',
      depth: 2,
      parentProofIds: [PARENT_A, PARENT_B],
    })
    expectNoMetadata(stdout)
  })

  it('exits 3 with a clear message when no lineage record exists', async () => {
    mockRetval(xdr.ScVal.scvVoid())

    const { code, stdout, stderr } = await run(['--output-digest', OUTPUT_DIGEST])

    expect(code).toBe(LINEAGE_EXIT_CODES.not_found)
    expect(code).toBe(3)
    expect(stdout).toBe('')
    expect(stderr).toContain(`no lineage record found for output digest ${OUTPUT_DIGEST}`)
  })

  it('exits 8 on a malformed registry response without echoing it', async () => {
    mockRetval(lineageStruct({ depth: xdr.ScVal.scvSymbol('deep') }))

    const { code, stdout, stderr } = await run(['--output-digest', OUTPUT_DIGEST])

    expect(code).toBe(LINEAGE_EXIT_CODES.error)
    expect(stdout).toBe('')
    expect(stderr).toContain('malformed lineage record')
    expectNoMetadata(stderr)
  })

  it('exits 8 when the RPC dependency fails', async () => {
    simulateTransactionMock.mockRejectedValue(new Error('network down'))

    const { code, stderr } = await run(['--output-digest', OUTPUT_DIGEST])

    expect(code).toBe(8)
    expect(stderr).toContain('lineage lookup dependency failed')
  })

  it.each([[[]], [['--output-digest', 'zz']], [['--output-digest', OUTPUT_DIGEST, '--output', 'yaml']]])(
    'exits 2 on usage errors without an RPC call (%j)',
    async (extra) => {
      const { code } = await run(extra)
      expect(code).toBe(2)
      expect(ServerMock).not.toHaveBeenCalled()
    },
  )

  it('is registered as a CLI command with its flags', () => {
    expect(parseCliArgs(['lineage', '--outputDigest', 'ab', '-o', 'json'])).toEqual({
      command: 'lineage',
      flags: { outputDigest: 'ab', output: 'json' },
    })
  })
})
