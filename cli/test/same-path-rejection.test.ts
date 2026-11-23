import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  assertDistinctInputOutputPaths,
  pathsResolveToSameFile,
  SameInputOutputPathError,
} from '../src/path-guard.js'

async function tryCreateSymlink(target: string, linkPath: string, type?: 'file' | 'dir' | 'junction'): Promise<boolean> {
  try {
    await symlink(target, linkPath, type)
    return true
  } catch (err) {
    const code = (err as { code?: string } | undefined)?.code
    if (code === 'EPERM' || code === 'EACCES') {
      return false
    }
    throw err
  }
}

describe('pathsResolveToSameFile', () => {
  let workDir: string

  beforeEach(async () => {
    workDir = await mkdtemp(join(tmpdir(), 'harpocrates-same-path-'))
  })

  afterEach(async () => {
    await rm(workDir, { recursive: true, force: true })
  })

  it('detects identical paths and unnormalized relative aliases', async () => {
    const file = join(workDir, 'source.json')
    await writeFile(file, '{"ok":true}', 'utf-8')

    expect(await pathsResolveToSameFile(file, file)).toBe(true)
    expect(await pathsResolveToSameFile(file, join(workDir, '.', 'source.json'))).toBe(true)
  })

  it('detects symlink aliases pointing to the same file', async () => {
    const file = join(workDir, 'source.json')
    const alias = join(workDir, 'alias.json')
    await writeFile(file, '{"ok":true}', 'utf-8')

    const created = await tryCreateSymlink(file, alias, 'file')
    if (!created) return

    expect(await pathsResolveToSameFile(file, alias)).toBe(true)
    expect(await pathsResolveToSameFile(alias, file)).toBe(true)
  })

  it('detects directory symlink / junction aliases resolving to the same file', async () => {
    const realDir = join(workDir, 'real')
    const linkDir = join(workDir, 'linked')
    await mkdir(realDir)
    const file = join(realDir, 'manifest.json')
    await writeFile(file, '{"version":2}', 'utf-8')

    const created = await tryCreateSymlink(
      realDir,
      linkDir,
      process.platform === 'win32' ? 'junction' : 'dir',
    )
    if (!created) return

    expect(await pathsResolveToSameFile(file, join(linkDir, 'manifest.json'))).toBe(true)
  })

  it('detects hard-link aliases pointing to the same file', async () => {
    const file = join(workDir, 'source.json')
    const hardlink = join(workDir, 'hardlink.json')
    await writeFile(file, '{"ok":true}', 'utf-8')
    await link(file, hardlink)

    expect(await pathsResolveToSameFile(file, hardlink)).toBe(true)
  })

  it('allows distinct output paths and stdin input', async () => {
    const file = join(workDir, 'source.json')
    const distinct = join(workDir, 'output.json')
    await writeFile(file, '{"ok":true}', 'utf-8')

    expect(await pathsResolveToSameFile(file, distinct)).toBe(false)
    expect(await pathsResolveToSameFile('-', distinct)).toBe(false)
  })
})

describe('assertDistinctInputOutputPaths', () => {
  let workDir: string

  beforeEach(async () => {
    workDir = await mkdtemp(join(tmpdir(), 'harpocrates-path-guard-'))
  })

  afterEach(async () => {
    await rm(workDir, { recursive: true, force: true })
  })

  it('rejects --input and --output resolving to the same file and preserves source bytes', async () => {
    const inputPath = join(workDir, 'metadata.json')
    const originalBytes = Buffer.from('{"proofId":"abc","tier":"source"}\n', 'utf-8')
    await writeFile(inputPath, originalBytes)

    await expect(
      assertDistinctInputOutputPaths([{ flag: '--input', path: inputPath }], inputPath),
    ).rejects.toThrow(SameInputOutputPathError)

    await expect(
      assertDistinctInputOutputPaths([{ flag: '--input', path: inputPath }], inputPath),
    ).rejects.toThrow('--output must not resolve to the same file as --input')

    expect(await readFile(inputPath)).toEqual(originalBytes)
  })

  it('rejects --output aliasing --manifest or --receipt via link and preserves bytes', async () => {
    const manifestPath = join(workDir, 'manifest.json')
    const receiptPath = join(workDir, 'receipt.json')
    const receiptAlias = join(workDir, 'receipt-alias.json')
    const manifestBytes = Buffer.from('{"manifest":true}\n', 'utf-8')
    const receiptBytes = Buffer.from('{"receipt":true}\n', 'utf-8')
    await writeFile(manifestPath, manifestBytes)
    await writeFile(receiptPath, receiptBytes)

    const symlinkCreated = await tryCreateSymlink(receiptPath, receiptAlias, 'file')
    if (!symlinkCreated) {
      await link(receiptPath, receiptAlias)
    }

    await expect(
      assertDistinctInputOutputPaths(
        [
          { flag: '--manifest', path: manifestPath },
          { flag: '--receipt', path: receiptPath },
        ],
        receiptAlias,
      ),
    ).rejects.toThrow('--output must not resolve to the same file as --receipt')

    expect(await readFile(manifestPath)).toEqual(manifestBytes)
    expect(await readFile(receiptPath)).toEqual(receiptBytes)
  })

  it('allows distinct output path and omitted output path', async () => {
    const manifestPath = join(workDir, 'manifest.json')
    const outputPath = join(workDir, 'c2pa-export.json')
    await writeFile(manifestPath, '{"manifest":true}\n', 'utf-8')

    await expect(
      assertDistinctInputOutputPaths([{ flag: '--manifest', path: manifestPath }], outputPath),
    ).resolves.toBeUndefined()

    await expect(
      assertDistinctInputOutputPaths([{ flag: '--manifest', path: manifestPath }], undefined),
    ).resolves.toBeUndefined()
  })
})
