import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import {
  browserBuildTargets,
  browserSupportMatrix,
  requiredBrowserCapabilities,
} from '../browser-support.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const frontendRoot = resolve(here, '..')
const docs = await readFile(resolve(frontendRoot, 'BROWSER_SUPPORT.md'), 'utf8')
const viteConfig = await readFile(resolve(frontendRoot, 'vite.config.ts'), 'utf8')

assert.equal(new Set(browserBuildTargets).size, browserBuildTargets.length, 'duplicate build target')
assert.equal(new Set(requiredBrowserCapabilities).size, requiredBrowserCapabilities.length, 'duplicate capability')
assert.ok(browserSupportMatrix.length > 0, 'support matrix is empty')

for (const entry of browserSupportMatrix) {
  assert.match(entry.minimum, /^\d+(?:\.\d+)?$/, `invalid minimum for ${entry.browser}`)
  assert.ok(['supported', 'best-effort'].includes(entry.tier), `invalid tier for ${entry.browser}`)
  assert.ok(
    docs.includes(`| ${entry.browser} | ${entry.platform} | ${entry.minimum}+ | ${entry.tier}`),
    `BROWSER_SUPPORT.md is missing ${entry.browser} ${entry.platform} ${entry.minimum}+`,
  )
}

for (const target of browserBuildTargets) {
  assert.ok(docs.includes(`\`${target}\``), `BROWSER_SUPPORT.md is missing build target ${target}`)
}

for (const capability of requiredBrowserCapabilities) {
  assert.ok(docs.includes(capability), `BROWSER_SUPPORT.md is missing capability: ${capability}`)
}

assert.match(
  viteConfig,
  /target:\s*\[\.\.\.browserBuildTargets\]/,
  'vite.config.ts must consume the canonical browserBuildTargets',
)

console.log(`browser support matrix OK: ${browserSupportMatrix.length} rows, ${browserBuildTargets.length} build targets`)
