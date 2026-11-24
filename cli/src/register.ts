import type { ParsedArgs } from './args.js'

export async function handleRegister(
  _flags: ParsedArgs['flags'],
  _debugLog: (event: Record<string, unknown>) => void,
): Promise<void> {
  process.stderr.write('error: register command is not implemented\n')
  process.exit(2)
}
