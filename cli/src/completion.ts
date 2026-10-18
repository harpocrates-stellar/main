import { COMMAND_DEFINITIONS, type CommandDefinition } from './commands.js'

export const SUPPORTED_SHELLS = ['bash', 'zsh', 'fish'] as const
export type SupportedShell = (typeof SUPPORTED_SHELLS)[number]

export function isSupportedShell(shell: string): shell is SupportedShell {
  return (SUPPORTED_SHELLS as readonly string[]).includes(shell)
}

function getSubcommands(): CommandDefinition[] {
  // Exclude 'help' and 'completion' from subcommands or include them?
  // User can run 'harpocrates help' and 'harpocrates completion'.
  // Typically subcommands for completion include all commands except completion maybe, or include all commands.
  // Acceptance criteria: "Each shell script completes commands and their flags"
  // "Command/flag table is the single source for help and completions"
  return COMMAND_DEFINITIONS
}

export function generateBashCompletion(): string {
  const commands = getSubcommands()
  const commandNames = commands.map((c) => c.name).join(' ')

  const cases = commands
    .map((cmd) => {
      const flags: string[] = []
      for (const flag of cmd.flags) {
        flags.push(`--${flag.name}`)
        if (flag.short) {
          flags.push(`-${flag.short}`)
        }
      }
      if (cmd.name === 'completion') {
        // completion accepts bash, zsh, fish
        const parts = [...flags, ...SUPPORTED_SHELLS].filter(Boolean)
        return `    ${cmd.name})
      opts="${parts.join(' ')}"
      ;;`
      }
      return `    ${cmd.name})
      opts="${flags.join(' ')}"
      ;;`
    })
    .join('\n')

  return `#!/usr/bin/env bash
# Bash completion script for harpocrates

_harpocrates_completions() {
  local cur prev words cword
  _init_completion || return

  local commands="${commandNames}"
  local opts=""

  # Find the sub-command if one was entered earlier in the line
  local subcmd=""
  local i
  for (( i=1; i < cword; i++ )); do
    local w="\${words[i]}"
    case "\${commands}" in
      *" \${w} "*|"\${w} "*|*" \${w}"|"\${w}")
        subcmd="\${w}"
        break
        ;;
    esac
  done

  if [[ -z "\${subcmd}" ]]; then
    if [[ "\${cur}" == -* ]]; then
      opts="--help"
      COMPREPLY=( $(compgen -W "\${opts}" -- "\${cur}") )
      return 0
    else
      COMPREPLY=( $(compgen -W "\${commands}" -- "\${cur}") )
      return 0
    fi
  fi

  case "\${subcmd}" in
${cases}
    *)
      opts=""
      ;;
  esac

  COMPREPLY=( $(compgen -W "\${opts}" -- "\${cur}") )
  return 0
}

complete -F _harpocrates_completions harpocrates
`
}

export function generateZshCompletion(): string {
  const commands = getSubcommands()

  const commandLines = commands
    .map((cmd) => {
      // Escape colons and single quotes in summary
      const summary = cmd.summary.replace(/'/g, "'\\''").replace(/:/g, '\\:')
      return `    '${cmd.name}:${summary}'`
    })
    .join('\n')

  const commandCases = commands
    .map((cmd) => {
      const flagLines: string[] = []
      for (const flag of cmd.flags) {
        const desc = flag.description.replace(/'/g, "'\\''").replace(/\[/g, '\\[').replace(/\]/g, '\\]').replace(/:/g, '\\:')
        if (flag.type === 'string') {
          if (flag.short) {
            flagLines.push(`        '(-${flag.short} --${flag.name})'{-${flag.short},--${flag.name}}'=[${desc}]:value:'`)
          } else {
            flagLines.push(`        '--${flag.name}=[${desc}]:value:'`)
          }
        } else {
          if (flag.short) {
            flagLines.push(`        '(-${flag.short} --${flag.name})'{-${flag.short},--${flag.name}}'[${desc}]'`)
          } else {
            flagLines.push(`        '--${flag.name}[${desc}]'`)
          }
        }
      }
      if (cmd.name === 'completion') {
        return `    (${cmd.name})
      local -a shells=(bash zsh fish)
      _values 'shell' $shells
      ;;`
      }
      return `    (${cmd.name})
      _arguments -s -S \\
${flagLines.join(' \\\n')}
      ;;`
    })
    .join('\n')

  return `#compdef harpocrates

_harpocrates() {
  local curcontext="$curcontext" state line
  typeset -A opt_args

  _arguments -C \\
    '1: :->command' \\
    '*:: :->args'

  case $state in
    (command)
      local -a commands
      commands=(
${commandLines}
      )
      _describe -t commands 'harpocrates command' commands
      ;;
    (args)
      case $line[1] in
${commandCases}
      esac
      ;;
  esac
}

_harpocrates "$@"
`
}

export function generateFishCompletion(): string {
  const commands = getSubcommands()
  const lines: string[] = [
    '# Fish completion script for harpocrates',
    '# Disable file completion by default',
    'complete -c harpocrates -f',
    '',
    '# Commands',
  ]

  for (const cmd of commands) {
    const desc = cmd.summary.replace(/'/g, "\\'")
    lines.push(`complete -c harpocrates -n "__fish_use_subcommand" -a "${cmd.name}" -d '${desc}'`)
  }

  lines.push('')
  lines.push('# Command-specific flags')

  for (const cmd of commands) {
    for (const flag of cmd.flags) {
      const desc = flag.description.replace(/'/g, "\\'")
      const shortPart = flag.short ? `-s ${flag.short} ` : ''
      const requirePart = flag.type === 'string' ? '-r ' : ''
      lines.push(
        `complete -c harpocrates -n "__fish_seen_subcommand_from ${cmd.name}" ${shortPart}-l ${flag.name} ${requirePart}-d '${desc}'`
      )
    }
  }

  // completion args
  lines.push('')
  lines.push('# completion shell arguments')
  lines.push(
    `complete -c harpocrates -n "__fish_seen_subcommand_from completion" -a "bash zsh fish" -d 'Shell type'`
  )

  return lines.join('\n') + '\n'
}

export function generateCompletion(shell: SupportedShell): string {
  switch (shell) {
    case 'bash':
      return generateBashCompletion()
    case 'zsh':
      return generateZshCompletion()
    case 'fish':
      return generateFishCompletion()
  }
}
