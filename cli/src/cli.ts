#!/usr/bin/env node

import { createReadStream } from 'node:fs'
import { writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { StrKey } from '@stellar/stellar-sdk'
import { asHex32 } from './hashing.js'
import { createProofManifest, parseManifest, serializeManifest } from './manifest.js'
import { validateMetadata, fileHash, canonicalMetadataHash, type HarpocratesMetadata } from './metadata.js'
import {
  lookupByVideoHash,
  lookupProofStatus,
  resolveContractId,
  resolveRpcUrl,
  verifyTransaction,
  getLineage,
  getProofStatus,
  LookupTimeoutError,
  type ProofLifecycleStatus,
} from './stellar-lookup.js'
import { createReceipt, formatReceipt, type VerificationReceipt } from './receipt.js'
import { classifyVerification } from './normalize.js'
import { verifyVerificationReceipt, decodeReceiptFromQr, type SignedVerificationReceipt } from './signed-receipt.js'
import {
  assertC2paInputWithinLimit,
  exportC2paAssertions,
  parseC2paReceiptInput,
  serializeC2paExport,
  type C2paExport,
} from './c2pa.js'
import { verifyLineageTree, formatLineageTree } from './verify-lineage.js'
import { logStructured, redactSensitive } from './logging.js'
import { createRequire } from 'node:module'
import { parseCliArgs, CliUsageError, type ParsedArgs } from './args.js'
import { DEFAULT_NETWORK_PASSPHRASE, resolveNetwork } from './network.js'

function getCliVersion(): string {
  const require = createRequire(import.meta.url)
  const pkg = require('../package.json') as { version?: string }
  return pkg.version ?? '0.0.0'
}

// ── I/O helpers ───────────────────────────────────────────────────────────

async function readText(path: string): Promise<string> {
  const chunks: Buffer[] = []
  let size = 0
  const source = path === '-' ? process.stdin : createReadStream(path)
  for await (const chunk of source) {
    size += Buffer.byteLength(chunk)
    if (size > 1024 * 1024) {
      if (path !== '-') source.destroy()
      throw new Error('input exceeds 1 MiB limit')
    }
    chunks.push(Buffer.from(chunk))
  }
  return Buffer.concat(chunks).toString('utf-8')
}

function printJson(data: unknown): void {
  process.stdout.write(JSON.stringify(data, null, 2) + '\n')
}

function printText(text: string): void {
  process.stdout.write(text + '\n')
}

function makeDebugLog(debug: boolean): (event: Record<string, unknown>) => void {
  const sink = {
    info: (message: string) => process.stderr.write(message + '\n'),
    warn: (message: string) => process.stderr.write(message + '\n'),
    error: (message: string) => process.stderr.write(message + '\n'),
    debug: (message: string) => process.stderr.write(message + '\n'),
  }
  return (event: Record<string, unknown>) => {
    if (debug) logStructured(sink, 'debug', event)
  }
}

function exit(code: number, message?: string): never {
  if (message) {
    process.stderr.write(`harpocrates: ${message}\n`)
  }
  process.exit(code)
}

// ── Main dispatcher ───────────────────────────────────────────────────────

export async function main(args: string[] = process.argv.slice(2)): Promise<void> {
  let parsed: ParsedArgs
  try {
    parsed = parseCliArgs(args)
  } catch (err) {
    if (err instanceof CliUsageError) exit(2, err.message)
    throw err
  }
  const { command, flags } = parsed
  const debugLog = makeDebugLog(flags.debug === 'true' || process.env.HARPOCRATES_DEBUG === '1')

  switch (command) {
    case 'verify':
      return await handleVerify(flags, debugLog)
    case 'status':
      return await handleStatus(flags, debugLog)
    case 'manifest':
      return await handleManifest(flags, debugLog)
    case 'hash':
      return await handleHash(flags)
    case 'verify-receipt':
      return await handleVerifyReceipt(flags, debugLog)
    case 'c2pa':
      return await handleC2pa(flags, debugLog)
    case 'verify-lineage':
      return await handleVerifyLineage(flags, debugLog)
    case 'register': {
      const { handleRegister } = await import('./register.js')
      return await handleRegister(flags, debugLog)
    }
    case 'help':
      return printHelp()
    default:
      return printUnknownCommand(command)
  }
}

export const MAX_BATCH_SIZE = 1000

export interface VerifyManifestOptions {
  contractId: string
  network?: string
  txHash?: string
  rpcUrl?: string
  sourceAddress?: string
  offline?: boolean
  timeoutMs?: number
  debugLog?: (event: Record<string, unknown>) => void
}

export class VerificationError extends Error {
  readonly exitCode: number
  readonly result?: string

  constructor(message: string, exitCode: number, result?: string) {
    super(message)
    this.name = 'VerificationError'
    this.exitCode = exitCode
    this.result = result
  }
}

export async function verifyManifest(
  rawManifest: string | ReturnType<typeof parseManifest>,
  options: VerifyManifestOptions,
): Promise<VerificationReceipt> {
  const {
    contractId,
    network = resolveNetwork(DEFAULT_NETWORK_PASSPHRASE),
    txHash,
    rpcUrl,
    sourceAddress,
    offline = false,
    timeoutMs,
    debugLog = () => {},
  } = options

  if (!contractId || !StrKey.isValidContract(contractId)) {
    throw new VerificationError('a valid --contract-id is required for verification', 8)
  }

  let manifest: ReturnType<typeof parseManifest>
  if (typeof rawManifest === 'string') {
    try {
      manifest = parseManifest(rawManifest)
    } catch {
      throw new VerificationError('invalid or unreadable manifest', 8)
    }
  } else {
    manifest = rawManifest
  }

  if (manifest.contractId !== contractId) {
    throw new VerificationError('contract_mismatch', 5, 'contract_mismatch')
  }
  if (manifest.network !== network) {
    throw new VerificationError('network_mismatch', 4, 'network_mismatch')
  }
  if (txHash && txHash.toLowerCase() !== manifest.transactionRef.toLowerCase()) {
    throw new VerificationError('transaction hash does not match manifest', 8)
  }

  debugLog({ event: 'verify.manifest', manifest: redactSensitive(manifest) })

  if (offline) {
    return createReceipt(
      manifest,
      { status: 'pending', txHash: manifest.transactionRef },
      null,
      'pending',
    )
  }

  try {
    const txVerification = await verifyTransaction(manifest.transactionRef, contractId, {
      rpcUrl,
      sourceAddress,
      timeoutMs,
    })

    const chainRecord = await lookupByVideoHash(contractId, manifest.videoHash, {
      rpcUrl,
      sourceAddress,
      networkPassphrase: network,
      timeoutMs,
    })

    const result = classifyVerification(manifest, txVerification, chainRecord)
    return createReceipt(manifest, txVerification, chainRecord, result)
  } catch (err) {
    if (err instanceof LookupTimeoutError) {
      throw new VerificationError('verification dependency failed: RPC timeout', 8)
    }
    throw new VerificationError('verification dependency failed', 8)
  }
}

async function handleVerify(flags: Record<string, string>, debugLog: (event: Record<string, unknown>) => void): Promise<void> {
  const contractId = flags['contract-id'] || flags.contractId
  const manifestPath = flags.manifest || flags.m
  const manifestsDir = flags.manifests
  const txHash = flags['tx-hash'] || flags.txHash
  const rpcUrl = flags['rpc-url'] || flags.rpcUrl
  const sourceAddress = flags['source-address'] || flags.sourceAddress || process.env.HARPOCRATES_SOURCE_ADDRESS
  const outputFormat = flags.output || flags.o || 'text'
  const offline = flags.offline === 'true'
  const network = resolveNetwork(flags.network || DEFAULT_NETWORK_PASSPHRASE)
  const timeoutMs = parseTimeout(flags.timeout)

  if (!contractId || !StrKey.isValidContract(contractId)) {
    exit(8, 'a valid --contract-id is required for verification')
  }

  if (!manifestPath && !manifestsDir) {
    exit(8, '--manifest or --manifests is required for verification')
  }

  const exitCodes: Record<string, number> = {
    valid: 0,
    expired: 1,
    revoked: 2,
    not_found: 3,
    network_mismatch: 4,
    contract_mismatch: 5,
    pending: 6,
    failed: 7,
    error: 8,
  }

  // ── Batch mode ──────────────────────────────────────────────────────────
  if (manifestsDir) {
    const concurrency = parseConcurrency(flags.concurrency)
    return await handleBatchVerify({
      manifestsDir,
      contractId,
      network,
      rpcUrl,
      sourceAddress,
      offline,
      timeoutMs,
      concurrency,
      outputFormat,
      debugLog,
      exitCodes,
    })
  }

  // ── Single-manifest mode ─────────────────────────────────────────────────
  let rawContent: string
  try {
    rawContent = await readText(manifestPath!)
  } catch {
    exit(8, 'invalid or unreadable manifest')
  }

  try {
    const receipt = await verifyManifest(rawContent, {
      contractId,
      network,
      txHash,
      rpcUrl,
      sourceAddress,
      offline,
      timeoutMs,
      debugLog,
    })

    if (outputFormat === 'json') {
      printJson(receipt)
    } else {
      printText(formatReceipt(receipt))
    }

    exit(exitCodes[receipt.result] ?? 8)
  } catch (err) {
    if (err instanceof VerificationError) {
      exit(err.exitCode, err.message)
    }
    exit(8, 'verification dependency failed')
  }
}

function parseConcurrency(raw: string | undefined): number {
  if (raw === undefined) return 4
  const value = Number(raw)
  if (!Number.isInteger(value) || value < 1 || value > 16) {
    exit(2, '--concurrency must be an integer between 1 and 16')
  }
  return value
}

interface BatchVerifyContext {
  manifestsDir: string
  contractId: string
  network: string
  rpcUrl?: string
  sourceAddress?: string
  offline: boolean
  timeoutMs: number
  concurrency: number
  outputFormat: string
  debugLog: (event: Record<string, unknown>) => void
  exitCodes: Record<string, number>
}

async function handleBatchVerify(ctx: BatchVerifyContext): Promise<void> {
  const { readdir, stat } = await import('node:fs/promises')
  const { join } = await import('node:path')

  let entries: string[]
  try {
    const dirStat = await stat(ctx.manifestsDir)
    if (!dirStat.isDirectory()) {
      exit(8, `--manifests path is not a directory: ${ctx.manifestsDir}`)
    }
    const allFiles = await readdir(ctx.manifestsDir)
    entries = allFiles.filter((f) => f.endsWith('.json')).sort()
  } catch {
    exit(8, `cannot read manifests directory: ${ctx.manifestsDir}`)
  }

  if (entries.length > MAX_BATCH_SIZE) {
    exit(8, `batch size ${entries.length} exceeds maximum allowed limit of ${MAX_BATCH_SIZE}`)
  }

  const counts: Record<string, number> = {
    valid: 0,
    expired: 0,
    revoked: 0,
    not_found: 0,
    network_mismatch: 0,
    contract_mismatch: 0,
    pending: 0,
    failed: 0,
    error: 0,
  }

  type ItemOutcome = { file: string; receipt?: VerificationReceipt; error?: string; result: string }
  const outcomes: ItemOutcome[] = new Array(entries.length)

  let cursor = 0
  const workerCount = Math.min(ctx.concurrency, Math.max(1, entries.length))
  const isJsonl = ctx.outputFormat === 'jsonl'

  const workers = Array.from({ length: workerCount }, async () => {
    while (cursor < entries.length) {
      const idx = cursor++
      const fileName = entries[idx]
      const fullPath = join(ctx.manifestsDir, fileName)

      try {
        const raw = await readText(fullPath)
        const receipt = await verifyManifest(raw, {
          contractId: ctx.contractId,
          network: ctx.network,
          rpcUrl: ctx.rpcUrl,
          sourceAddress: ctx.sourceAddress,
          offline: ctx.offline,
          timeoutMs: ctx.timeoutMs,
          debugLog: ctx.debugLog,
        })
        outcomes[idx] = { file: fileName, receipt, result: receipt.result }
        if (isJsonl) {
          process.stdout.write(JSON.stringify({ file: fileName, receipt, result: receipt.result }) + '\n')
        }
      } catch (err) {
        const result = err instanceof VerificationError && err.result ? err.result : 'error'
        const errMsg = err instanceof Error ? err.message : String(err)
        outcomes[idx] = { file: fileName, error: errMsg, result }
        if (isJsonl) {
          process.stdout.write(JSON.stringify({ file: fileName, error: errMsg, result }) + '\n')
        }
      }
    }
  })

  await Promise.all(workers)

  for (const item of outcomes) {
    if (item) {
      counts[item.result] = (counts[item.result] ?? 0) + 1
    }
  }

  const allVerified = outcomes.length > 0 && outcomes.every((o) => o && o.result === 'valid')

  if (ctx.outputFormat === 'json') {
    printJson({
      total: outcomes.length,
      counts,
      allVerified,
      items: outcomes,
    })
  } else if (!isJsonl) {
    printText('═══════════════════════════════════════════')
    printText('  Harpocrates Batch Verification Summary')
    printText('═══════════════════════════════════════════')
    printText(`  Total items:     ${outcomes.length}`)
    printText(`  Valid:           ${counts.valid}`)
    printText(`  Expired:         ${counts.expired}`)
    printText(`  Revoked:         ${counts.revoked}`)
    printText(`  Not found:       ${counts.not_found}`)
    printText(`  Network mismatch:${counts.network_mismatch}`)
    printText(`  Contract mismatch:${counts.contract_mismatch}`)
    printText(`  Pending:         ${counts.pending}`)
    printText(`  Failed:          ${counts.failed}`)
    printText(`  Errors:          ${counts.error}`)
    printText('═══════════════════════════════════════════')
  }

  if (!allVerified) {
    exit(1)
  }
  exit(0)
}

function parseTimeout(raw: string | undefined): number {
  if (raw === undefined) return 15000
  if (!/^[0-9]+$/.test(raw)) exit(2, '--timeout must be a positive integer')
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value <= 0) {
    exit(2, '--timeout must be a positive integer')
  }
  return value
}

async function handleManifest(flags: Record<string, string>, debugLog: (event: Record<string, unknown>) => void): Promise<void> {
  const inputPath = flags.input || flags.i
  const outputPath = flags.output || flags.o
  const outputFormat = flags.format || 'json'

  if (!inputPath) {
    exit(2, '--input is required for manifest creation')
  }

  let metadata: HarpocratesMetadata
  try {
    let raw: string
    if (inputPath === '-') {
      raw = await readText('-')
    } else {
      raw = await readText(inputPath)
    }
    const parsed = JSON.parse(raw)
    metadata = validateMetadata(parsed)
  } catch {
    exit(8, 'invalid or unreadable metadata')
  }

  debugLog({ event: 'manifest.input_metadata', metadata: redactSensitive(metadata) })

  if (!flags['tx-hash'] && !flags.txHash) {
    exit(2, '--tx-hash is required for manifest creation')
  }
  if (!flags['contract-id'] && !flags.contractId) {
    exit(2, '--contract-id is required for manifest creation')
  }
  if (!StrKey.isValidContract(flags['contract-id'] || flags.contractId)) {
    exit(8, 'invalid contract ID')
  }
  if (!/^[0-9a-fA-F]{64}$/.test(flags['tx-hash'] || flags.txHash)) {
    exit(8, 'invalid transaction hash')
  }

  const manifest = createProofManifest({
    proofId: metadata.proofId,
    tier: metadata.tier,
    network: resolveNetwork(flags.network || DEFAULT_NETWORK_PASSPHRASE),
    contractId: flags['contract-id'] || flags.contractId,
    transactionRef: flags['tx-hash'] || flags.txHash,
    videoHash: flags['video-hash'] || flags.videoHash || '',
    metadataHash: canonicalMetadataHash(metadata),
    sourceHash: metadata.sourceHash,
    timestamp: metadata.timestamp,
  })
  try {
    parseManifest(serializeManifest(manifest))
  } catch {
    exit(8, 'invalid manifest fields')
  }

  const serialized = serializeManifest(manifest)

  if (outputPath) {
    await writeFile(outputPath, serialized, 'utf-8')
    printText(`Manifest written to ${outputPath}`)
  } else {
    if (outputFormat === 'text') {
      printText(serialized)
    } else {
      printJson(JSON.parse(serialized))
    }
  }
}

async function handleHash(flags: Record<string, string>): Promise<void> {
  const filePath = flags.file || flags.f
  const outputFormat = flags.output || flags.o || 'text'

  if (!filePath) {
    exit(2, '--file is required for hashing')
  }

  if (outputFormat !== 'text' && outputFormat !== 'json') {
    exit(2, 'invalid --output value: expected "text" or "json"')
  }

  try {
    let hash: string
    let bytes: number
    if (filePath === '-') {
      const digest = createHash('sha256')
      bytes = 0
      for await (const chunk of process.stdin) {
        bytes += Buffer.byteLength(chunk)
        digest.update(chunk)
      }
      hash = digest.digest('hex')
    } else {
      hash = await fileHash(filePath)
      const { stat } = await import('node:fs/promises')
      bytes = (await stat(filePath)).size
    }

    if (outputFormat === 'json') {
      printJson({
        algorithm: 'sha256',
        digest: hash,
        bytes,
      })
    } else {
      printText(hash)
    }
  } catch {
    exit(8, 'hashing failed')
  }
}

async function handleVerifyReceipt(flags: Record<string, string>, debugLog: (event: Record<string, unknown>) => void): Promise<void> {
  const receiptPath = flags.receipt || flags.r
  const keysPath = flags.keys || flags.k
  const network = flags.network ? resolveNetwork(flags.network) : undefined
  const proofId = flags['proof-id'] || flags.proofId

  if (!receiptPath) exit(2, '--receipt is required')
  if (!keysPath) exit(2, '--keys is required for verification')

  let receipt: SignedVerificationReceipt
  try {
    const raw = await readText(receiptPath)
    if (raw.trim().startsWith('{')) {
      receipt = JSON.parse(raw)
    } else {
      receipt = decodeReceiptFromQr(raw.trim())
    }
  } catch {
    exit(8, 'invalid or unreadable receipt')
  }

  let keys: Record<string, JsonWebKey>
  try {
    const rawKeys = await readText(keysPath)
    keys = JSON.parse(rawKeys)
  } catch {
    exit(8, 'invalid or unreadable keys file')
  }

  debugLog({ event: 'verify-receipt.input', receipt: redactSensitive(receipt) })

  const result = await verifyVerificationReceipt(receipt, {
    keys,
    expectedNetworkPassphrase: network,
    expectedProofId: proofId,
  })

  if (result.valid) {
    if (flags.output === 'json' || flags.o === 'json') {
      printJson({ valid: true, receipt: result.receipt })
    } else {
      printText(`✅ Receipt is valid. Verified at: ${result.receipt.verifiedAt}, Result: ${result.receipt.result}`)
    }
    exit(0)
  } else {
    if (flags.output === 'json' || flags.o === 'json') {
      printJson({ valid: false, reason: result.reason })
    } else {
      printText(`❌ Invalid receipt: ${result.reason}`)
    }
    exit(8)
  }
}

async function handleC2pa(flags: Record<string, string>, debugLog: (event: Record<string, unknown>) => void): Promise<void> {
  const inputPath = flags.manifest || flags.m
  const receiptPath = flags.receipt || flags.r
  const outputPath = flags.output || flags.o
  const title = flags.title

  if (!inputPath) {
    exit(2, '--manifest is required for c2pa export')
  }

  let manifest: ReturnType<typeof parseManifest>
  try {
    const raw = await readText(inputPath)
    assertC2paInputWithinLimit(raw, 'manifest')
    manifest = parseManifest(raw)
  } catch {
    exit(8, 'invalid or unreadable manifest')
  }

  debugLog({ event: 'c2pa.manifest', manifest: redactSensitive(manifest) })

  let receipt: VerificationReceipt | undefined
  if (receiptPath) {
    try {
      const rawReceipt = await readText(receiptPath)
      assertC2paInputWithinLimit(rawReceipt, 'receipt')
      receipt = parseC2paReceiptInput(JSON.parse(rawReceipt))
    } catch {
      exit(8, 'invalid or unreadable receipt')
    }
  }

  let exported: C2paExport
  try {
    exported = exportC2paAssertions(manifest, receipt, title ? { title } : undefined)
  } catch {
    exit(8, 'c2pa export rejected the supplied inputs')
  }

  const serialized = serializeC2paExport(exported)

  if (outputPath) {
    await writeFile(outputPath, serialized, 'utf-8')
    printText(`C2PA assertions written to ${outputPath}`)
  } else {
    printText(serialized)
  }
}

async function handleVerifyLineage(
  flags: Record<string, string>,
  debugLog: (event: Record<string, unknown>) => void,
): Promise<void> {
  const outputDigest = flags['output-digest'] || flags.outputDigest
  const contractId = flags['contract-id'] || flags.contractId
  const rpcUrl = flags['rpc-url'] || flags.rpcUrl
  const sourceAddress = flags['source-address'] || flags.sourceAddress || process.env.HARPOCRATES_SOURCE_ADDRESS
  const network = resolveNetwork(flags.network || DEFAULT_NETWORK_PASSPHRASE)
  const outputFormat = flags.output || flags.o || 'text'

  if (!outputDigest) {
    exit(2, '--output-digest is required for lineage verification')
  }

  if (!contractId || !StrKey.isValidContract(contractId)) {
    exit(8, 'a valid --contract-id is required for verification')
  }

  if (!sourceAddress) {
    exit(8, 'a source address is required for simulation. Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS')
  }

  debugLog({
    action: 'verify-lineage',
    outputDigest,
    contractId,
    network,
  })

  const fetcher = {
    getLineage: (digest: string) =>
      getLineage(contractId, digest, {
        rpcUrl,
        networkPassphrase: network,
        sourceAddress,
      }),
    getProofStatus: (proofId: string) =>
      getProofStatus(contractId, proofId, {
        rpcUrl,
        networkPassphrase: network,
        sourceAddress,
      }),
  }

  const result = await verifyLineageTree(outputDigest, fetcher)

  if (outputFormat === 'json') {
    printJson(result)
  } else {
    printText(formatLineageTree(result.root))
    if (!result.success && result.failureReason) {
      printText(`\nVerification failed: ${result.failureReason}`)
    }
  }

  if (!result.success) {
    if (result.revokedCount > 0) exit(2, 'an ancestor is revoked')
    if (result.expiredCount > 0) exit(1, 'an ancestor is expired')
    if (result.missingCount > 0) exit(3, 'an ancestor is missing')
    exit(8, result.failureReason ?? 'lineage verification failed')
  }

  exit(0)
}

export const STATUS_EXIT_CODES: Record<ProofLifecycleStatus, number> = {
  registered: 0,
  expired: 1,
  revoked: 2,
  unknown: 3,
}

export function formatProofStatus(info: {
  proofId: string
  contractId: string
  network: string
  status: ProofLifecycleStatus
}): string {
  return [
    `Proof ID: ${info.proofId}`,
    `Contract: ${info.contractId}`,
    `Network:  ${info.network}`,
    `Status:   ${info.status}`,
  ].join('\n')
}

export async function handleStatus(
  flags: Record<string, string>,
  debugLog: (event: Record<string, unknown>) => void = () => {},
): Promise<void> {
  const rawProofId = flags['proof-id'] || flags.proofId
  const contractId = resolveContractId(flags['contract-id'] || flags.contractId)
  const rpcUrl = resolveRpcUrl(flags['rpc-url'] || flags.rpcUrl)
  const sourceAddress =
    flags['source-address'] || flags.sourceAddress || process.env.HARPOCRATES_SOURCE_ADDRESS
  const network = resolveNetwork(flags.network || DEFAULT_NETWORK_PASSPHRASE)
  const outputFormat = flags.output || flags.o || 'text'

  if (!rawProofId) {
    exit(2, '--proof-id is required for status lookup')
  }

  let proofId: string
  try {
    proofId = asHex32(rawProofId, 'proofId')
  } catch {
    exit(2, 'invalid --proof-id: must be a 32-byte hex string')
  }

  if (outputFormat !== 'text' && outputFormat !== 'json') {
    exit(2, 'invalid --output: expected "text" or "json"')
  }

  if (!contractId || !StrKey.isValidContract(contractId)) {
    exit(8, 'a valid --contract-id is required for status lookup')
  }

  debugLog({
    event: 'status.lookup',
    proofId,
    contractId,
    network,
  })

  let status: ProofLifecycleStatus
  try {
    status = await lookupProofStatus(contractId, proofId, {
      rpcUrl,
      sourceAddress,
      networkPassphrase: network,
    })
  } catch {
    exit(8, 'status lookup dependency failed')
  }

  const payload = {
    proofId,
    contractId,
    network,
    status,
  }

  if (outputFormat === 'json') {
    printJson(payload)
  } else {
    printText(formatProofStatus(payload))
  }

  exit(STATUS_EXIT_CODES[status] ?? 8)
}

export function helpText(): string {
  const help = `
Harpocrates CLI – headless verification and proof utilities

Usage:
  harpocrates <command> [options]
  harpocrates --version

Commands:
  verify         Verify a proof against the Stellar network.
  status         Report the on-chain lifecycle status of a proof by proof ID.
  verify-lineage Verify a derivative's full lineage back to registered originals.
  register       Register a source or seal proof using a local signing key.
  manifest       Create a proof manifest from metadata.
  hash           Compute the SHA-256 hash of a file.
  verify-receipt Verify an offline signed receipt.
  c2pa           Export C2PA authenticity assertions from a proof manifest.
  version        Print the CLI version.
  help           Show this help message.

Register options:
  --kind           Proof kind to register: "source" or "seal" (required).
  --contract-id    Contract ID on Stellar (required).
  --proof-id       Proof ID to register (required).
  --video-hash     32-byte hex video hash (required).
  --source-hash    32-byte hex source hash (required for source proofs).
  --metadata-hash  32-byte hex metadata hash (required for seal proofs).
  --rpc-url        Stellar RPC URL (default: testnet).
  --network        Network passphrase (default: testnet).
  --signer-file    Path to a file containing the signer secret key.
  --dry-run        Simulate only; stop before submitting.
  --output, -o     Output format: "text" (default) or "json".
  The signer secret is read only from HARPOCRATES_SIGNER_SECRET or --signer-file,
  never from a flag value, and is never logged.

Status options:
  --contract-id     Contract ID on Stellar (required).
  --proof-id        32-byte hex proof ID to inspect (required).
  --rpc-url         Stellar RPC URL (default: testnet).
  --source-address  Source address for simulation.
  --network         Network: testnet, mainnet/public, futurenet, or a full passphrase (default: testnet).
  --output, -o      Output format: "text" (default) or "json".

Lineage verification options:
  --output-digest  32-byte hex digest of the derivative (required).
  --contract-id    Contract ID on Stellar (required).
  --rpc-url        Stellar RPC URL (default: testnet).
  --source-address Source address for simulation.
  --network        Network: testnet, mainnet/public, futurenet, or a full passphrase (default: testnet).
  --output, -o     Output format: "text" (default) or "json".

C2PA export options:
  --manifest       Path to a proof manifest JSON file (use "-" for stdin; required).
  --receipt        Optional verification receipt JSON; adds a verification assertion.
  --output, -o     File path to write the exported assertions to.
  --title          Optional human-readable title carried by the exported claim.
  Prerequisite: install deps and build first (cd cli && npm ci && npm run build).
  The output is deterministic, unsigned C2PA JSON. It never contains media,
  witnesses, secrets, proof bytes, or private keys; sign it with your own
  C2PA tooling and key material.

Verify Receipt options:
  --receipt, -r     Path to signed receipt JSON or QR payload (use "-" for stdin).
  --keys, -k        Path to JSON file mapping key IDs to JWKs.
  --network         Optional expected network: testnet, mainnet/public, futurenet, or a full passphrase.
  --proof-id        Optional expected proof ID.
  --output, -o      Output format: "text" (default) or "json".

Verify options:
  --contract-id     Contract ID on Stellar (required).
  --manifest        Path to a proof manifest JSON file (use "-" for stdin).
  --manifests       Path to a directory containing manifest JSON files for batch verification.
  --concurrency     Max concurrent lookups in batch mode (1-16, default: 4).
  --tx-hash         Transaction hash to verify on-chain.
  --network         Network: testnet, mainnet/public, futurenet, or a full passphrase (default: testnet).
  --rpc-url         Stellar RPC URL (default: testnet).
  --source-address  Source address for simulation.
  --output, -o      Output format: "text" (default) or "json".
  --offline         Skip on-chain lookup; validate locally only.
  --timeout         RPC request timeout in milliseconds (default: 15000).

Manifest options:
  --input, -i       Path to metadata JSON file (use "-" for stdin; required).
  --tx-hash         Transaction hash from the registration (required).
  --contract-id     Contract ID on Stellar (required).
  --video-hash      32-byte hex video hash (required).
  --network         Network: testnet, mainnet/public, futurenet, or a full passphrase (default: testnet).
  --output, -o      File path to write the manifest to.
  --format          Output format when printing to stdout: "json" (default) or "text".

Hash options:
  --file, -f        Path to the file to hash (use "-" for stdin; required).
  --output, -o      Output format: "text" (default) or "json".

Environment variables:
  HARPOCRATES_SOURCE_ADDRESS   Source address for Stellar simulation.
  HARPOCRATES_SIGNER_SECRET    Signer secret key for the register command.
  HARPOCRATES_DEBUG            Equivalent to --debug.

Debugging:
  --debug                      Emit redacted structured diagnostics to stderr.
                                Sensitive fields (secrets, witnesses, tokens,
                                credentials) are never logged.

Exit codes:
  0   valid / registered
  1   expired
  2   revoked
  3   not_found / missing / unknown
  4   network_mismatch
  5   contract_mismatch
  6   pending
  7   failed
  8   error
      (RPC timeouts during verification also exit with 8)
  For a full table of every exit code and which commands emit them, see the Exit codes section in cli/README.md.
`
  return help.trim()
}

function printHelp(): void {
  printText(helpText())
  process.exit(0)
}

function printUnknownCommand(name: string): never {
  process.stderr.write(`harpocrates: unknown command "${name}"\n`)
  process.stderr.write('Run "harpocrates help" for usage.\n')
  process.exit(2)
}

const isDirectExecution =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))

if (isDirectExecution) {
  main().catch((err) => {
    void err
    process.stderr.write('harpocrates: unexpected error\n')
    process.exit(8)
  })
}