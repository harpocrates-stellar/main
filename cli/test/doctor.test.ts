import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { StrKey, Networks } from '@stellar/stellar-sdk'

const {
  getHealthMock,
  getNetworkMock,
  getLedgerEntriesMock,
  ServerMock,
} = vi.hoisted(() => {
  const getHealthMock = vi.fn()
  const getNetworkMock = vi.fn()
  const getLedgerEntriesMock = vi.fn()
  const ServerMock = vi.fn(() => ({
    getHealth: getHealthMock,
    getNetwork: getNetworkMock,
    getLedgerEntries: getLedgerEntriesMock,
  }))
  return {
    getHealthMock,
    getNetworkMock,
    getLedgerEntriesMock,
    ServerMock,
  }
})

vi.mock('@stellar/stellar-sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@stellar/stellar-sdk')>()
  return {
    ...actual,
    rpc: {
      ...actual.rpc,
      Server: ServerMock,
    },
  }
})

import {
  runDiagnostics,
  formatDoctorReport,
  handleDoctor,
  main,
} from '../src/cli.js'

const VALID_CONTRACT_ID = StrKey.encodeContract(Uint8Array.from({ length: 32 }, (_, i) => i + 1))

class ExitSignal extends Error {
  readonly code: number
  constructor(code: number) {
    super(`exit(${code})`)
    this.code = code
  }
}

describe('doctor command diagnostics', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getHealthMock.mockResolvedValue({ status: 'healthy' })
    getNetworkMock.mockResolvedValue({
      passphrase: Networks.TESTNET,
      protocolVersion: 29,
    })
    getLedgerEntriesMock.mockResolvedValue({
      entries: [{ xdr: 'mockEntry' }],
    })
  })

  it('reports all checks pass for a healthy environment with valid contract', async () => {
    const report = await runDiagnostics({
      contractId: VALID_CONTRACT_ID,
      network: Networks.TESTNET,
    })

    expect(report.ok).toBe(true)
    expect(report.checks).toHaveLength(4)

    const [nodeCheck, rpcCheck, netCheck, contractCheck] = report.checks
    expect(nodeCheck.name).toBe('node_version')
    expect(nodeCheck.status).toMatch(/^(pass|warn)$/)
    expect(rpcCheck.name).toBe('rpc_reachability')
    expect(rpcCheck.status).toBe('pass')
    expect(netCheck.name).toBe('network_passphrase')
    expect(netCheck.status).toBe('pass')
    expect(contractCheck.name).toBe('contract_existence')
    expect(contractCheck.status).toBe('pass')

    expect(ServerMock).toHaveBeenCalled()
    expect(getHealthMock).toHaveBeenCalledTimes(1)
    expect(getNetworkMock).toHaveBeenCalledTimes(1)
    expect(getLedgerEntriesMock).toHaveBeenCalledTimes(1)
  })

  it('omits contract_existence check when no contract-id is provided', async () => {
    const report = await runDiagnostics({})

    expect(report.ok).toBe(true)
    expect(report.checks).toHaveLength(3)
    expect(report.checks.map((c) => c.name)).toEqual([
      'node_version',
      'rpc_reachability',
      'network_passphrase',
    ])
    expect(getLedgerEntriesMock).not.toHaveBeenCalled()
  })

  it('fails rpc_reachability and skips dependent checks when RPC is unreachable', async () => {
    getHealthMock.mockRejectedValueOnce(new Error('ECONNREFUSED 127.0.0.1:8000'))

    const report = await runDiagnostics({
      contractId: VALID_CONTRACT_ID,
    })

    expect(report.ok).toBe(false)
    const rpcCheck = report.checks.find((c) => c.name === 'rpc_reachability')
    expect(rpcCheck?.status).toBe('fail')
    expect(rpcCheck?.message).toContain('unreachable')

    const netCheck = report.checks.find((c) => c.name === 'network_passphrase')
    expect(netCheck?.status).toBe('fail')
    expect(netCheck?.message).toContain('Skipped')

    const contractCheck = report.checks.find((c) => c.name === 'contract_existence')
    expect(contractCheck?.status).toBe('fail')
    expect(contractCheck?.message).toContain('Skipped')

    expect(getNetworkMock).not.toHaveBeenCalled()
    expect(getLedgerEntriesMock).not.toHaveBeenCalled()
  })

  it('fails network_passphrase when server passphrase does not match expected', async () => {
    getNetworkMock.mockResolvedValueOnce({
      passphrase: 'Public Global Stellar Network ; September 2015',
    })

    const report = await runDiagnostics({
      network: Networks.TESTNET,
    })

    expect(report.ok).toBe(false)
    const netCheck = report.checks.find((c) => c.name === 'network_passphrase')
    expect(netCheck?.status).toBe('fail')
    expect(netCheck?.message).toContain('mismatch')
    expect(netCheck?.message).toContain(Networks.TESTNET)
  })

  it('fails contract_existence when contract does not exist on-chain', async () => {
    getLedgerEntriesMock.mockResolvedValueOnce({
      entries: [],
    })

    const report = await runDiagnostics({
      contractId: VALID_CONTRACT_ID,
    })

    expect(report.ok).toBe(false)
    const contractCheck = report.checks.find((c) => c.name === 'contract_existence')
    expect(contractCheck?.status).toBe('fail')
    expect(contractCheck?.message).toContain('not found on-chain')
  })

  it('fails contract_existence when contract ID is invalid without calling getLedgerEntries', async () => {
    const report = await runDiagnostics({
      contractId: 'not-a-valid-contract-id',
    })

    expect(report.ok).toBe(false)
    const contractCheck = report.checks.find((c) => c.name === 'contract_existence')
    expect(contractCheck?.status).toBe('fail')
    expect(contractCheck?.message).toContain('invalid')
    expect(getLedgerEntriesMock).not.toHaveBeenCalled()
  })

  it('times out bounded by the RPC timeout', async () => {
    getHealthMock.mockImplementationOnce(
      () => new Promise((resolve) => setTimeout(resolve, 500)),
    )

    const report = await runDiagnostics({
      timeoutMs: 50,
    })

    expect(report.ok).toBe(false)
    const rpcCheck = report.checks.find((c) => c.name === 'rpc_reachability')
    expect(rpcCheck?.status).toBe('fail')
    expect(rpcCheck?.message).toContain('timed out')
  })

  it('never prints secrets or addresses beyond the supplied contract id', () => {
    const report = {
      ok: true,
      checks: [
        { name: 'node_version', status: 'pass' as const, message: 'Node.js v22.0.0 supported' },
        { name: 'rpc_reachability', status: 'pass' as const, message: 'RPC endpoint is reachable' },
        { name: 'contract_existence', status: 'pass' as const, message: `Contract exists on-chain (${VALID_CONTRACT_ID})` },
      ],
    }
    const output = formatDoctorReport(report)
    expect(output).toContain(VALID_CONTRACT_ID)
    // No secret keys (S...) or Stellar account addresses (G...)
    expect(output).not.toMatch(/\bS[A-Z0-9]{55}\b/)
    expect(output).not.toMatch(/\bG[A-Z0-9]{55}\b/)
  })
})

describe('CLI doctor command integration', () => {
  let stdoutChunks: string[]
  let stderrChunks: string[]

  beforeEach(() => {
    vi.clearAllMocks()
    stdoutChunks = []
    stderrChunks = []
    getHealthMock.mockResolvedValue({ status: 'healthy' })
    getNetworkMock.mockResolvedValue({
      passphrase: Networks.TESTNET,
      protocolVersion: 29,
    })
    getLedgerEntriesMock.mockResolvedValue({
      entries: [{ xdr: 'mockEntry' }],
    })

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
    }) as (code?: string | number | null | undefined) => never)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
    try {
      await main(args)
      return { code: 0, stdout: stdoutChunks.join(''), stderr: stderrChunks.join('') }
    } catch (err) {
      if (err instanceof ExitSignal) {
        return {
          code: err.code,
          stdout: stdoutChunks.join(''),
          stderr: stderrChunks.join(''),
        }
      }
      throw err
    }
  }

  it('runs doctor command in text mode and exits 0 when all checks pass', async () => {
    const res = await runCli(['doctor'])
    expect(res.code).toBe(0)
    expect(res.stdout).toContain('[PASS] rpc_reachability')
    expect(res.stdout).toContain('[PASS] network_passphrase')
  })

  it('runs doctor command with --output json and prints structured JSON report', async () => {
    const res = await runCli(['doctor', '--output', 'json'])
    expect(res.code).toBe(0)
    const json = JSON.parse(res.stdout)
    expect(json.ok).toBe(true)
    expect(Array.isArray(json.checks)).toBe(true)
  })

  it('exits non-zero when any check fails', async () => {
    getHealthMock.mockRejectedValueOnce(new Error('RPC connection refused'))
    const res = await runCli(['doctor'])
    expect(res.code).not.toBe(0)
    expect(res.stdout).toContain('[FAIL] rpc_reachability')
  })

  it('exits non-zero in JSON mode when a check fails and outputs ok: false', async () => {
    getHealthMock.mockRejectedValueOnce(new Error('RPC connection refused'))
    const res = await runCli(['doctor', '-o', 'json'])
    expect(res.code).not.toBe(0)
    const json = JSON.parse(res.stdout)
    expect(json.ok).toBe(false)
  })
})
