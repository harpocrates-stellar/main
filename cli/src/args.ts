import { parseArgs } from 'node:util'
import { COMMAND_DEFINITIONS } from './commands.js'

export type Command = 'verify' | 'manifest' | 'hash' | 'verify-receipt' | 'c2pa' | 'completion' | 'help'

export interface ParsedArgs {
  command: Command
  flags: Record<string, string>
  positionals?: string[]
}

export class CliUsageError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CliUsageError'
  }
}

type OptionSpec = { type: 'string' | 'boolean'; short?: string }
type OptionSet = Record<string, OptionSpec>

function toCamelCase(str: string): string {
  return str.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())
}

function buildCommandOptions(): Record<Exclude<Command, 'help'>, OptionSet> {
  const result: Record<string, OptionSet> = {}
  for (const cmd of COMMAND_DEFINITIONS) {
    if (cmd.name === 'help') continue
    const options: OptionSet = {}
    // Global debug flag on all non-help commands
    options.debug = { type: 'boolean' }

    for (const flag of cmd.flags) {
      const spec: OptionSpec = {
        type: flag.type,
        ...(flag.short ? { short: flag.short } : {}),
      }
      options[flag.name] = spec
      if (flag.name.includes('-')) {
        options[toCamelCase(flag.name)] = { type: flag.type }
      }
    }
    result[cmd.name] = options
  }
  return result as Record<Exclude<Command, 'help'>, OptionSet>
}

const COMMAND_OPTIONS: Record<Exclude<Command, 'help'>, OptionSet> = buildCommandOptions()

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
  const allowPositionals = command === 'completion'
  let parsed: { values: Record<string, unknown>; positionals: string[] }
  try {
    parsed = parseArgs({ args: rest, options, strict: true, allowPositionals })
  } catch (err) {
    throw new CliUsageError(describeUsageError(command, err))
  }

  // Handlers expect string values; booleans become 'true'.
  const flags: Record<string, string> = {}
  for (const [key, value] of Object.entries(parsed.values)) {
    if (value !== undefined) flags[key] = String(value)
  }
  const result: ParsedArgs = { command: command as Command, flags }
  if (parsed.positionals.length > 0) {
    result.positionals = parsed.positionals
  }
  return result
}
