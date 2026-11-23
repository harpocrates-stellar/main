#!/usr/bin/env node
// Builds dist/harpocrates.mjs, a single-file ESM bundle of the CLI with all
// runtime deps (including @stellar/stellar-sdk) inlined, plus a sha256sum-style
// checksum file next to it. Does not touch the tsc output in dist/.
import { build } from 'esbuild'
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, statSync } from 'node:fs'
import { basename, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const cliRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outfile = resolve(cliRoot, 'dist', 'harpocrates.mjs')

await build({
  absWorkingDir: cliRoot,
  entryPoints: ['src/cli.ts'],
  outfile,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  legalComments: 'eof',
  logLevel: 'warning',
  // src/cli.ts already starts with `#!/usr/bin/env node` and esbuild keeps it
  // as the first line. The banner only adds a `require` for CJS deps that
  // require() node builtins, which ESM output can't do on its own.
  banner: {
    js: "import { createRequire as __harpocratesCreateRequire } from 'node:module';\nconst require = __harpocratesCreateRequire(import.meta.url);",
  },
})

const bytes = readFileSync(outfile)
if (!bytes.subarray(0, 21).toString('utf8').startsWith('#!/usr/bin/env node\n')) {
  throw new Error(`${outfile} does not start with a node shebang`)
}

const digest = createHash('sha256').update(bytes).digest('hex')
writeFileSync(`${outfile}.sha256`, `${digest}  ${basename(outfile)}\n`)

console.log(`bundled ${basename(outfile)} (${statSync(outfile).size} bytes)`)
console.log(`sha256 ${digest}`)
