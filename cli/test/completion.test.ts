import { describe, expect, it } from 'vitest'
import { COMMAND_DEFINITIONS, renderHelp } from '../src/commands.js'
import {
  generateBashCompletion,
  generateFishCompletion,
  generateZshCompletion,
  SUPPORTED_SHELLS,
} from '../src/completion.js'
import { parseCliArgs, CliUsageError } from '../src/args.js'

describe('shell completion scripts', () => {
  const bashScript = generateBashCompletion()
  const zshScript = generateZshCompletion()
  const fishScript = generateFishCompletion()

  it('matches snapshot for bash completion script', () => {
    expect(bashScript).toMatchSnapshot()
  })

  it('matches snapshot for zsh completion script', () => {
    expect(zshScript).toMatchSnapshot()
  })

  it('matches snapshot for fish completion script', () => {
    expect(fishScript).toMatchSnapshot()
  })

  it('asserts every command in COMMAND_DEFINITIONS appears in each script', () => {
    for (const cmd of COMMAND_DEFINITIONS) {
      expect(bashScript).toContain(cmd.name)
      expect(zshScript).toContain(cmd.name)
      expect(fishScript).toContain(cmd.name)
    }
  })

  it('asserts every flag in COMMAND_DEFINITIONS appears in each script', () => {
    for (const cmd of COMMAND_DEFINITIONS) {
      for (const flag of cmd.flags) {
        // Assert long flag appears
        expect(bashScript).toContain(`--${flag.name}`)
        expect(zshScript).toContain(`--${flag.name}`)
        expect(fishScript).toContain(`-l ${flag.name}`)

        // If short flag exists, assert it appears as well
        if (flag.short) {
          expect(bashScript).toContain(`-${flag.short}`)
          expect(zshScript).toContain(`-${flag.short}`)
          expect(fishScript).toContain(`-s ${flag.short}`)
        }
      }
    }
  })

  it('exposes completion command in parseCliArgs', () => {
    const res = parseCliArgs(['completion', 'bash'])
    expect(res.command).toBe('completion')
    expect(res.positionals).toEqual(['bash'])
  })

  it('rejects unknown flags on completion command', () => {
    expect(() => parseCliArgs(['completion', '--bogus'])).toThrow(CliUsageError)
  })

  it('defines all supported shells', () => {
    expect(SUPPORTED_SHELLS).toEqual(['bash', 'zsh', 'fish'])
  })

  it('single-source table generates identical commands and flags in help output', () => {
    const help = renderHelp()
    for (const cmd of COMMAND_DEFINITIONS) {
      expect(help).toContain(cmd.name)
      for (const flag of cmd.flags) {
        expect(help).toContain(`--${flag.name}`)
      }
    }
  })

  it('fails with exit code 2 when an unknown shell is passed', async () => {
    const { spawnSync } = await import('node:child_process')
    const { fileURLToPath } = await import('node:url')
    const cliPath = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
    const res = spawnSync(process.execPath, [cliPath, 'completion', 'unknownshell'], {
      encoding: 'utf-8',
    })
    expect(res.status).toBe(2)
    expect(res.stderr).toContain("harpocrates: unknown shell: 'unknownshell'")
  }, 30000)

  it('fails with exit code 2 when no shell is passed', async () => {
    const { spawnSync } = await import('node:child_process')
    const { fileURLToPath } = await import('node:url')
    const cliPath = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
    const res = spawnSync(process.execPath, [cliPath, 'completion'], {
      encoding: 'utf-8',
    })
    expect(res.status).toBe(2)
    expect(res.stderr).toContain('harpocrates: unknown shell')
  }, 30000)

  it('prints valid completion script with exit code 0 for valid shells', async () => {
    const { spawnSync } = await import('node:child_process')
    const { fileURLToPath } = await import('node:url')
    const cliPath = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
    for (const shell of SUPPORTED_SHELLS) {
      const res = spawnSync(process.execPath, [cliPath, 'completion', shell], {
        encoding: 'utf-8',
      })
      expect(res.status).toBe(0)
      expect(res.stdout).toContain('harpocrates')
    }
  }, 30000)
})
