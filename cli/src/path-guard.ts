import { realpath, stat } from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'

function normalizeForCompare(targetPath: string): string {
  return process.platform === 'win32' ? targetPath.toLowerCase() : targetPath
}

async function resolveCanonicalPath(filePath: string): Promise<string> {
  const absolute = resolve(filePath)
  try {
    return await realpath(absolute)
  } catch (err) {
    const code = (err as { code?: string } | undefined)?.code
    if (code === 'ENOENT') {
      try {
        const parentReal = await realpath(dirname(absolute))
        return resolve(parentReal, basename(absolute))
      } catch {
        return absolute
      }
    }
    return absolute
  }
}

export async function pathsResolveToSameFile(inputPath: string, outputPath: string): Promise<boolean> {
  if (!inputPath || !outputPath || inputPath === '-' || outputPath === '-') {
    return false
  }

  const [canonicalInput, canonicalOutput] = await Promise.all([
    resolveCanonicalPath(inputPath),
    resolveCanonicalPath(outputPath),
  ])

  if (normalizeForCompare(canonicalInput) === normalizeForCompare(canonicalOutput)) {
    return true
  }

  try {
    const [inStat, outStat] = await Promise.all([stat(inputPath), stat(outputPath)])
    if (inStat.dev === outStat.dev && inStat.ino === outStat.ino && inStat.ino !== 0) {
      return true
    }
  } catch {
    // One or both paths do not exist yet; canonical path comparison above is authoritative.
  }

  return false
}

export class SameInputOutputPathError extends Error {
  readonly inputFlag: string

  constructor(inputFlag: string) {
    super(`--output must not resolve to the same file as ${inputFlag}`)
    this.name = 'SameInputOutputPathError'
    this.inputFlag = inputFlag
  }
}

export async function assertDistinctInputOutputPaths(
  inputs: Array<{ flag: string; path: string | undefined }>,
  outputPath: string | undefined,
): Promise<void> {
  if (!outputPath) return
  for (const input of inputs) {
    if (input.path && (await pathsResolveToSameFile(input.path, outputPath))) {
      throw new SameInputOutputPathError(input.flag)
    }
  }
}
