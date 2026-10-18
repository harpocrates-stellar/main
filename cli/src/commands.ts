export interface FlagDefinition {
  name: string
  short?: string
  type: 'string' | 'boolean'
  description: string
  placeholder?: string
  acceptsStdin?: boolean
  required?: boolean
  defaultText?: string
  helpLabel?: string
}

export interface CommandDefinition {
  name: string
  description: string
  summary: string
  flags: FlagDefinition[]
  prerequisites?: string[]
  notes?: string[]
  helpOrder?: number
}

export const COMMAND_DEFINITIONS: CommandDefinition[] = [
  {
    name: 'verify',
    summary: 'Verify a proof against the Stellar network.',
    description: 'Verify options:',
    helpOrder: 3,
    flags: [
      {
        name: 'contract-id',
        type: 'string',
        description: 'Contract ID on Stellar (required).',
        required: true,
        helpLabel: '--contract-id    ',
      },
      {
        name: 'manifest',
        short: 'm',
        type: 'string',
        description: 'Path to a proof manifest JSON file (use "-" for stdin).',
        acceptsStdin: true,
        helpLabel: '--manifest       ',
      },
      {
        name: 'tx-hash',
        type: 'string',
        description: 'Transaction hash to verify on-chain.',
        helpLabel: '--tx-hash        ',
      },
      {
        name: 'network',
        type: 'string',
        description: 'Network passphrase (default: testnet).',
        helpLabel: '--network        ',
      },
      {
        name: 'rpc-url',
        type: 'string',
        description: 'Stellar RPC URL (default: testnet).',
        helpLabel: '--rpc-url        ',
      },
      {
        name: 'source-address',
        type: 'string',
        description: 'Source address for simulation.',
        helpLabel: '--source-address ',
      },
      {
        name: 'output',
        short: 'o',
        type: 'string',
        description: 'Output format: "text" (default) or "json".',
        helpLabel: '--output, -o     ',
      },
      {
        name: 'offline',
        type: 'boolean',
        description: 'Skip on-chain lookup; validate locally only.',
        helpLabel: '--offline        ',
      },
    ],
  },
  {
    name: 'manifest',
    summary: 'Create a proof manifest from metadata.',
    description: 'Manifest options:',
    helpOrder: 4,
    flags: [
      {
        name: 'input',
        short: 'i',
        type: 'string',
        description: 'Path to metadata JSON file (use "-" for stdin; required).',
        acceptsStdin: true,
        required: true,
        helpLabel: '--input, -i      ',
      },
      {
        name: 'tx-hash',
        type: 'string',
        description: 'Transaction hash from the registration (required).',
        required: true,
        helpLabel: '--tx-hash        ',
      },
      {
        name: 'contract-id',
        type: 'string',
        description: 'Contract ID on Stellar (required).',
        required: true,
        helpLabel: '--contract-id    ',
      },
      {
        name: 'video-hash',
        type: 'string',
        description: '32-byte hex video hash (required).',
        required: true,
        helpLabel: '--video-hash     ',
      },
      {
        name: 'network',
        type: 'string',
        description: 'Network passphrase (default: testnet).',
        helpLabel: '--network        ',
      },
      {
        name: 'output',
        short: 'o',
        type: 'string',
        description: 'File path to write the manifest to.',
        helpLabel: '--output, -o     ',
      },
      {
        name: 'format',
        type: 'string',
        description: 'Output format when printing to stdout: "json" (default) or "text".',
        helpLabel: '--format         ',
      },
    ],
  },
  {
    name: 'hash',
    summary: 'Compute the SHA-256 hash of a file.',
    description: 'Hash options:',
    helpOrder: 5,
    flags: [
      {
        name: 'file',
        short: 'f',
        type: 'string',
        description: 'Path to the file to hash (use "-" for stdin; required).',
        acceptsStdin: true,
        required: true,
        helpLabel: '--file, -f       ',
      },
    ],
  },
  {
    name: 'verify-receipt',
    summary: 'Verify an offline signed receipt.',
    description: 'Verify Receipt options:',
    helpOrder: 2,
    flags: [
      {
        name: 'receipt',
        short: 'r',
        type: 'string',
        description: 'Path to signed receipt JSON or QR payload (use "-" for stdin).',
        acceptsStdin: true,
        helpLabel: '--receipt, -r    ',
      },
      {
        name: 'keys',
        short: 'k',
        type: 'string',
        description: 'Path to JSON file mapping key IDs to JWKs.',
        helpLabel: '--keys, -k       ',
      },
      {
        name: 'network',
        type: 'string',
        description: 'Optional expected network passphrase.',
        helpLabel: '--network        ',
      },
      {
        name: 'proof-id',
        type: 'string',
        description: 'Optional expected proof ID.',
        helpLabel: '--proof-id       ',
      },
      {
        name: 'output',
        short: 'o',
        type: 'string',
        description: 'Output format: "text" (default) or "json".',
        helpLabel: '--output, -o     ',
      },
    ],
  },
  {
    name: 'c2pa',
    summary: 'Export C2PA authenticity assertions from a proof manifest.',
    description: 'C2PA export options:',
    helpOrder: 1,
    prerequisites: [
      '  Prerequisite: install deps and build first (cd cli && npm ci && npm run build).',
      '  The output is deterministic, unsigned C2PA JSON. It never contains media,\n  witnesses, secrets, proof bytes, or private keys; sign it with your own\n  C2PA tooling and key material.',
    ],
    flags: [
      {
        name: 'manifest',
        short: 'm',
        type: 'string',
        description: 'Path to a proof manifest JSON file (use "-" for stdin; required).',
        acceptsStdin: true,
        required: true,
        helpLabel: '--manifest      ',
      },
      {
        name: 'receipt',
        short: 'r',
        type: 'string',
        description: 'Optional verification receipt JSON; adds a verification assertion.',
        helpLabel: '--receipt       ',
      },
      {
        name: 'output',
        short: 'o',
        type: 'string',
        description: 'File path to write the exported assertions to.',
        helpLabel: '--output, -o    ',
      },
      {
        name: 'title',
        type: 'string',
        description: 'Optional human-readable title carried by the exported claim.',
        helpLabel: '--title         ',
      },
    ],
  },
  {
    name: 'completion',
    summary: 'Generate shell completion script (bash, zsh, fish).',
    description: 'Completion options:',
    flags: [],
  },
  {
    name: 'help',
    summary: 'Show this help message.',
    description: 'Help options:',
    flags: [],
  },
]

export function renderHelp(): string {
  const lines: string[] = [
    'Harpocrates CLI – headless verification and proof utilities',
    '',
    'Usage:',
    '  harpocrates <command> [options]',
    '',
    'Commands:',
  ]

  for (const cmd of COMMAND_DEFINITIONS) {
    const paddedName = cmd.name.padEnd(14, ' ')
    lines.push(`  ${paddedName} ${cmd.summary}`)
  }

  // Render option blocks in specified helpOrder
  const orderedCommands = [...COMMAND_DEFINITIONS]
    .filter((c) => c.flags.length > 0 && c.helpOrder !== undefined)
    .sort((a, b) => (a.helpOrder ?? 99) - (b.helpOrder ?? 99))

  for (const cmd of orderedCommands) {
    lines.push('')
    lines.push(cmd.description)
    for (const flag of cmd.flags) {
      let lineStr: string
      if (flag.helpLabel) {
        lineStr = `  ${flag.helpLabel} ${flag.description}`
      } else {
        let flagPart = `--${flag.name}`
        if (flag.short) {
          flagPart += `, -${flag.short}`
        }
        lineStr = `  ${flagPart.padEnd(16, ' ')} ${flag.description}`
      }
      lines.push(lineStr)
    }
    if (cmd.prerequisites) {
      for (const prereq of cmd.prerequisites) {
        lines.push(`${prereq}`)
      }
    }
  }

  lines.push('')
  lines.push('Environment variables:')
  lines.push('  HARPOCRATES_SOURCE_ADDRESS   Source address for Stellar simulation.')
  lines.push('  HARPOCRATES_DEBUG            Equivalent to --debug.')
  lines.push('')
  lines.push('Debugging:')
  lines.push('  --debug                      Emit redacted structured diagnostics to stderr.')
  lines.push('                               Sensitive fields (secrets, witnesses, tokens,')
  lines.push('                               credentials) are never logged.')
  lines.push('')
  lines.push('Exit codes:')
  lines.push('  0   valid')
  lines.push('  1   expired')
  lines.push('  2   revoked')
  lines.push('  3   not_found / missing')
  lines.push('  4   network_mismatch')
  lines.push('  5   contract_mismatch')
  lines.push('  6   pending')
  lines.push('  7   failed')
  lines.push('  8   error')

  return lines.join('\n')
}
