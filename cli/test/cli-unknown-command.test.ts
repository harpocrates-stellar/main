import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const cli = resolve(import.meta.dirname, '../dist/cli.js')
const run = (args: string[]) => spawnSync(process.execPath, [cli, ...args], {
  encoding: 'utf8', timeout: 10_000,
})

describe('CLI unknown command handling', () => {
  it('returns usage error, writes help to stderr and does not echo flag values', () => {
    const result = run(['verfy', '--secret', 'do-not-echo'])
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(2)
    expect(result.stderr).toMatch(/^harpocrates: unknown command "verfy"\r?\nRun "harpocrates help" for usage\.\r?\n$/)
    expect(result.stderr).not.toContain('do-not-echo')
    expect(result.stdout).toBe('')
  })

  it('does not echo an equals-form flag value in the command position', () => {
    const result = run(['--secret=do-not-echo'])
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(2)
    expect(result.stderr).toContain('unknown command "--secret"')
    expect(result.stderr).not.toContain('do-not-echo')
  })

  it.each([['help'], []])('keeps explicit and implicit help successful: %j', (...args) => {
    const result = run(args)
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    expect(result.stdout).toContain('Harpocrates CLI')
    expect(result.stderr).toBe('')
  })
})
