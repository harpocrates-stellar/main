import { parseArgs } from 'node:util'

export type Command =
  | 'verify'
  | 'status'
  | 'check-compat'
  | 'manifest'
  | 'hash'
  | 'verify-receipt'
  | 'compare-receipt'
  | 'c2pa'
  | 'verify-lineage'
  | 'verify-bundle'
  | 'compare-trust-policy'
  | 'register'
  | 'version' main
  | 'help'

export interface ParsedArgs {
  command: Command
  flags: Record<string, string>
}

export class CliUsageError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CliUsageError'
  }
}

type OptionSpec = { type: 'string' | 'boolean'; short?: string }
type OptionSet = Record<string, OptionSpec>

const text: OptionSpec = { type: 'string' }
const toggle: OptionSpec = { type: 'boolean' }
const alias = (short: string): OptionSpec => ({ type: 'string', short })

const HELP_HINT = "run 'harpocrates help' for usage"

// Handlers read both the kebab-case flag and its camelCase fallback, so both
// spellings are accepted for every multi-word flag.
const ON_CHAIN: OptionSet = {
  'contract-id': text,
  contractId: text,
  'tx-hash': text,
  txHash: text,
}

const COMMAND_OPTIONS: Record<Exclude<Command, 'help'>, OptionSet> = {
  verify: {
    ...ON_CHAIN,
    manifest: alias('m'),
    'rpc-url': text,
    rpcUrl: text,
    'source-address': text,
    sourceAddress: text,
    network: text,
    output: alias('o'),
    offline: toggle,
    debug: toggle,
    timeout: text,
  },
  status: {
    'contract-id': text,
    contractId: text,
    'proof-id': text,
    proofId: text,
    'rpc-url': text,
    rpcUrl: text,
    'source-address': text,
    sourceAddress: text,
    network: text,
    output: alias('o'),
    debug: toggle,
  },
  'check-compat': {
    manifest: alias('m'),
    'contract-id': text,
    contractId: text,
    network: text,
    output: alias('o'),
    debug: toggle,
  },
  manifest: {
    ...ON_CHAIN,
    input: alias('i'),
    output: alias('o'),
    format: text,
    'video-hash': text,
    videoHash: text,
    network: text,
    debug: toggle,
  },
  hash: {
    file: alias('f'),
    output: alias('o'),
    debug: toggle,
  },
  'verify-receipt': {
    receipt: alias('r'),
    keys: alias('k'),
    network: text,
    'proof-id': text,
    proofId: text,
    output: alias('o'),
    debug: toggle,
  },
  'compare-receipt': {
    base: alias('b'),
    target: alias('t'),
    'receipt-a': text,
    receiptA: text,
    'receipt-b': text,
    receiptB: text,
    candidate: text,
    output: alias('o'),
    debug: toggle,
  },
  c2pa: {
    manifest: alias('m'),
    receipt: alias('r'),
    output: alias('o'),
    title: text,
    debug: toggle,
  },
  'verify-lineage': {
    'output-digest': text,
    outputDigest: text,
    'contract-id': text,
    contractId: text,
    'rpc-url': text,
    rpcUrl: text,
    'source-address': text,
    sourceAddress: text,
    network: text,
    output: alias('o'),
    debug: toggle,
  },
  register: {
    kind: text,
    'contract-id': text,
    contractId: text,
    'proof-id': text,
    proofId: text,
    'video-hash': text,
    videoHash: text,
    'source-hash': text,
    sourceHash: text,
    'metadata-hash': text,
    metadataHash: text,
    'rpc-url': text,
    rpcUrl: text,
    network: text,
    'signer-file': text,
    signerFile: text,
    'dry-run': toggle,
    dryRun: toggle,
    output: alias('o'),
    debug: toggle,
  },
  'compare-trust-policy': {
    'policy-a': text,
    policyA: text,
    'policy-b': text,
    policyB: text,
    bundle: alias('b'),
    output: alias('o'),
    debug: toggle,
  },
  version: {},
}

// Environment variable defaults for flags that are otherwise required on every call.
// Explicit flags always take precedence over these values.
const ENV_DEFAULTS: Partial<Record<Exclude<Command, 'help'>, { keys: string[]; env: string }>> = {
  verify: {
    keys: ['rpc-url', 'rpcUrl'],
    env: 'HARPOCRATES_RPC_URL',
  },
  manifest: {
    keys: ['contract-id', 'contractId'],
    env: 'HARPOCRATES_CONTRACT_ID',
  },
  hash: {
    keys: [],
    env: '',
  },
  'verify-receipt': {
    keys: [],
    env: '',
  },
  'compare-receipt': {
    keys: [],
    env: '',
  },
  c2pa: {
    keys: [],
    env: '',
  },
  'verify-lineage': {
    keys: [],
    env: '',
  },
  register: {
    keys: [],
    env: '',
  },
  version: {
    keys: [],
    env: '',
  },
  'compare-trust-policy': {
    keys: [],
    env: '',
  },
}

function applyEnvDefaults(command: Exclude<Command, 'help'>, flags: Record<string, string>): void {
  const spec = ENV_DEFAULTS[command]
  if (!spec || spec.keys.length === 0 || spec.env === '') return
  const hasFlag = spec.keys.some((key) => flags[key] !== undefined)
  if (hasFlag) return
  const envValue = process.env[spec.env]
  if (envValue !== undefined && envValue !== '') {
    flags[spec.keys[0]] = envValue
  }
}

function describeUsageError(command: string, err: unknown): string {
  const message = err instanceof Error ? err.message : String(err)
  const code = (err as { code?: string }).code
  if (code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION') {
    const option = /Unknown option '([^']+)'/.exec(message)?.[1] ?? 'option'
    return `unknown option ${option} for '${command}'; ${HELP_HINT}`
  }
  if (code === 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL') {
    const arg = /Unexpected argument '([^']+)'/.exec(message)?.[1] ?? 'argument'
    return `unexpected argument ${arg} for '${command}'; ${HELP_HINT}`
  }
  const reason = message.split(/\.\s/)[0].replace(/\.$/, '')
  return `${reason} for '${command}'; ${HELP_HINT}`
}

export function parseCliArgs(argv: string[]): ParsedArgs {
  if (argv.length > 0 && (argv[0] === '--version' || argv[0] === '-v' || argv[0] === 'version')) {
    return { command: 'version', flags: {} }
  }

  let [rawCommand, ...rest] = argv
  if (rawCommand === 'compare') {
    rawCommand = 'compare-receipt'
  }

  const command = rawCommand
  if (command === undefined || !Object.prototype.hasOwnProperty.call(COMMAND_OPTIONS, command)) {
    return { command: 'help', flags: {} }
  }

  const options = COMMAND_OPTIONS[command as Exclude<Command, 'help'>]
  const allowPositionals = command === 'compare-receipt'
  let values: Record<string, unknown>
  let positionals: string[] = []
  try {
    const parsed = parseArgs({ args: rest, options, strict: true, allowPositionals })
    values = parsed.values
    positionals = parsed.positionals
  } catch (err) {
    throw new CliUsageError(describeUsageError(command, err))
  }

  // Handlers expect string values; booleans become 'true'.
  const flags: Record<string, string> = {}
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined) flags[key] = String(value)
  }

  if (command === 'compare-receipt') {
    if (positionals.length > 2) {
      throw new CliUsageError(`unexpected argument '${positionals[2]}' for '${command}'; ${HELP_HINT}`)
    }
    if (positionals.length > 0 && !flags.base && !flags.b && !flags['receipt-a'] && !flags.receiptA) {
      flags.base = positionals[0]
    }
    if (positionals.length > 1 && !flags.target && !flags.t && !flags['receipt-b'] && !flags.receiptB && !flags.candidate) {
      flags.target = positionals[1]
    }
  }

  if (flags.timeout !== undefined) {
    const timeout = Number(flags.timeout)
    if (!Number.isInteger(timeout) || timeout <= 0) {
      throw new CliUsageError(
        `invalid value ${flags.timeout} for '--timeout'; expected a positive integer of milliseconds; ${HELP_HINT}`,
      )
    }
  }

  applyEnvDefaults(command as Exclude<Command, 'help'>, flags)

  return { command: command as Command, flags }
}
