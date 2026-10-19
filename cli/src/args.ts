import { parseArgs } from 'node:util'

export type Command = 'verify' | 'manifest' | 'hash' | 'verify-receipt' | 'c2pa' | 'help'

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
  c2pa: {
    manifest: alias('m'),
    receipt: alias('r'),
    output: alias('o'),
    title: text,
    debug: toggle,
  },
}

function describeUsageError(command: string, err: unknown): string {
  const message = err instanceof Error ? err.message : String(err)
  const code = (err as { code?: string }).code
  const hint = "run 'harpocrates help' for usage"
  if (code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION') {
    const option = /Unknown option '([^']+)'/.exec(message)?.[1] ?? 'option'
    return `unknown option ${option} for '${command}'; ${hint}`
  }
  if (code === 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL') {
    const arg = /Unexpected argument '([^']+)'/.exec(message)?.[1] ?? 'argument'
    return `unexpected argument ${arg} for '${command}'; ${hint}`
  }
  const reason = message.split(/\.\s/)[0].replace(/\.$/, '')
  return `${reason} for '${command}'; ${hint}`
}

export function parseCliArgs(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv
  if (command === undefined || !Object.prototype.hasOwnProperty.call(COMMAND_OPTIONS, command)) {
    return { command: 'help', flags: {} }
  }

  const options = COMMAND_OPTIONS[command as Exclude<Command, 'help'>]
  let values: Record<string, unknown>
  try {
    values = parseArgs({ args: rest, options, strict: true, allowPositionals: false }).values
  } catch (err) {
    throw new CliUsageError(describeUsageError(command, err))
  }

  // Handlers expect string values; booleans become 'true'.
  const flags: Record<string, string> = {}
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined) flags[key] = String(value)
  }
  if (flags.timeout !== undefined) {
    const timeout = Number(flags.timeout)
    if (!Number.isInteger(timeout) || timeout <= 0) {
      throw new CliUsageError(
        `invalid value ${flags.timeout} for '--timeout'; expected a positive integer of milliseconds; ${hint}`,
      )
    }
  }
  return { command: command as Command, flags }
}
