import { lstat, readlink, realpath, stat, writeFile } from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'

const MAX_SYMLINK_HOPS = 40

export class SameFileCollisionError extends Error {
  readonly code = 'SAME_INPUT_OUTPUT_FILE' as const

  constructor(
    message = 'output path resolves to an input file; refusing to overwrite source data',
  ) {
    super(message)
    this.name = 'SameFileCollisionError'
  }
}

async function tryNativeRealpath(targetPath: string): Promise<string | null> {
  try {
    return await realpath(targetPath)
  } catch {
    return null
  }
}

/**
 * Resolve a path canonicalizing existing ancestor directories and following
 * any trailing or intermediate symlinks (including dangling symlinks) up to
 * `MAX_SYMLINK_HOPS` hops.
 */
export async function resolveCanonicalTargetPath(rawPath: string): Promise<string> {
  let current = resolve(rawPath)

  for (let hop = 0; hop < MAX_SYMLINK_HOPS; hop++) {
    const directReal = await tryNativeRealpath(current)
    if (directReal !== null) {
      return directReal
    }

    // Target itself may not exist yet or may be a dangling symlink.
    try {
      const linkStats = await lstat(current)
      if (linkStats.isSymbolicLink()) {
        const linkTarget = await readlink(current)
        current = resolve(dirname(current), linkTarget)
        continue
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      if (code !== 'ENOENT' && code !== 'ENOTDIR') {
        throw err
      }
    }

    // Walk up to the nearest existing ancestor directory and resolve its realpath.
    const pendingSegments: string[] = []
    let probe = current
    while (true) {
      const parent = dirname(probe)
      if (parent === probe) {
        return resolve(probe, ...pendingSegments.reverse())
      }
      pendingSegments.push(basename(probe))
      const parentReal = await tryNativeRealpath(parent)
      if (parentReal !== null) {
        return resolve(parentReal, ...pendingSegments.reverse())
      }
      probe = parent
    }
  }

  throw new SameFileCollisionError('too many symbolic link levels while resolving path')
}

function normalizePathComparisonKey(canonicalPath: string): string {
  return process.platform === 'win32' ? canonicalPath.toLowerCase() : canonicalPath
}

/**
 * Return `true` when `inputPath` and `outputPath` resolve to the same
 * filesystem entry via lexical normalization, symlinks, symlinked parent
 * directories, or hardlinks (`dev` + `ino`).
 */
export async function pathsResolveToSameFile(
  inputPath: string,
  outputPath: string,
): Promise<boolean> {
  if (inputPath === '-' || outputPath === '-' || inputPath.trim() === '' || outputPath.trim() === '') {
    return false
  }

  const [canonicalIn, canonicalOut] = await Promise.all([
    resolveCanonicalTargetPath(inputPath),
    resolveCanonicalTargetPath(outputPath),
  ])

  if (normalizePathComparisonKey(canonicalIn) === normalizePathComparisonKey(canonicalOut)) {
    return true
  }

  // Also detect hardlinks when both resolved targets exist on disk.
  try {
    const [inStat, outStat] = await Promise.all([
      stat(canonicalIn, { bigint: true }),
      stat(canonicalOut, { bigint: true }),
    ])
    if (inStat.ino !== 0n && inStat.ino === outStat.ino && inStat.dev === outStat.dev) {
      return true
    }
  } catch {
    // One of the files does not exist yet, so it cannot be an existing hardlink.
  }

  return false
}

/**
 * Reject with `SameFileCollisionError` if `outputPath` resolves to any file in
 * `inputPaths`. Must be called BEFORE opening or truncating `outputPath`.
 */
export async function assertDistinctInputOutputPaths(
  inputPaths: readonly (string | undefined)[],
  outputPath: string | undefined,
): Promise<void> {
  if (!outputPath || outputPath === '-') return
  for (const inputPath of inputPaths) {
    if (!inputPath || inputPath === '-') continue
    if (await pathsResolveToSameFile(inputPath, outputPath)) {
      throw new SameFileCollisionError()
    }
  }
}

/**
 * Verify `outputPath` does not alias any `inputPaths` immediately before
 * writing UTF-8 content to disk.
 */
export async function writeDistinctOutputFile(
  inputPaths: readonly (string | undefined)[],
  outputPath: string,
  content: string,
): Promise<void> {
  await assertDistinctInputOutputPaths(inputPaths, outputPath)
  await writeFile(outputPath, content, 'utf-8')
}
