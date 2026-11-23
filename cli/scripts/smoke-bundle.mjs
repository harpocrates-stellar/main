#!/usr/bin/env node
// Smoke test for dist/harpocrates.mjs: copy the bundle into an empty temp dir
// (no node_modules, no package.json anywhere above it) and make sure
// `node harpocrates.mjs help` works and the checksum file matches.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const cliRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const bundle = resolve(cliRoot, 'dist', 'harpocrates.mjs')
const checksumFile = `${bundle}.sha256`

function fail(msg) {
  console.error(`smoke-bundle: ${msg}`)
  process.exit(1)
}

if (!existsSync(bundle)) fail(`missing ${bundle}, run npm run bundle first`)
if (!existsSync(checksumFile)) fail(`missing ${checksumFile}`)

const bytes = readFileSync(bundle)
if (!bytes.toString('utf8', 0, 20).startsWith('#!/usr/bin/env node')) fail('bundle has no node shebang')

const [expected, name] = readFileSync(checksumFile, 'utf8').trim().split(/\s+/)
const actual = createHash('sha256').update(bytes).digest('hex')
if (name !== 'harpocrates.mjs') fail(`checksum file names "${name}", expected harpocrates.mjs`)
if (expected !== actual) fail(`checksum mismatch: file says ${expected}, bundle is ${actual}`)

const dir = mkdtempSync(join(tmpdir(), 'harpocrates-bundle-'))
try {
  const copy = join(dir, 'harpocrates.mjs')
  copyFileSync(bundle, copy)
  if (existsSync(join(dir, 'node_modules'))) fail('temp dir unexpectedly has node_modules')

  const res = spawnSync(process.execPath, [copy, 'help'], {
    cwd: dir,
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '', NODE_PATH: '' },
  })
  if (res.error) fail(`failed to spawn node: ${res.error.message}`)
  if (res.status !== 0) fail(`help exited ${res.status}\n${res.stderr}`)
  if (!res.stdout.includes('Usage:') || !res.stdout.includes('harpocrates <command>')) {
    fail(`unexpected help output:\n${res.stdout}`)
  }
  console.log(`smoke-bundle: ok (help ran from ${dir}, sha256 ${actual})`)
} finally {
  rmSync(dir, { recursive: true, force: true })
}
