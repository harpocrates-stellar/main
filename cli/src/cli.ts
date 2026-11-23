#!/usr/bin/env node

import { createReadStream } from 'node:fs'
import { realpath, stat, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { basename, dirname, resolve } from 'node:path'
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
import {
  compareReceipts,
  formatComparisonResult,
  parseReceiptInput,
  type ReceiptComparisonResult,
} from './compare-receipt.js'
import { logStructured, redactSensitive } from './logging.js'
import { createRequire } from 'node:module'
import { parseCliArgs, CliUsageError, type ParsedArgs } from './args.js'
import { handleRegister } from './register.js'
import { DEFAULT_NETWORK_PASSPHRASE, resolveNetwork } from './network.js'
import { runCheckCompat } from './compat.js'

function getCliVersion(): string {
  const require = createRequire(import.meta.url)
  const pkg = require('../package.json') as { version?: string }
  return pkg.version ?? '0.0.0'
}

// ── I/O helpers ───────────────────────────────────────────────────────────

export async function readText(
  source: string | NodeJS.ReadableStream,
  limit: number = MAX_MANIFEST_BYTES,
): Promise<string> {
  const chunks: Buffer[] = []
  let size = 0
  const stream: NodeJS.ReadableStream =
    typeof source !== 'string'
      ? source
      : source === '-'
        ? process.stdin
        : createReadStream(source)
  for await (const chunk of stream) {
    size += Buffer.byteLength(chunk)
    if (size > limit) {
      if (typeof (stream as unknown as { destroy?: () => void }).destroy === 'function') {
        (stream as unknown as { destroy: () => void }).destroy()
      }
      throw new Error('input exceeds 1 MiB limit')
    }
    chunks.push(Buffer.from(chunk))
  }
  return Buffer.concat(chunks).toString('utf-8')
}

function normalizeForCompare(targetPath: string): string {
  return process.platform === 'win32' ? targetPath.toLowerCase() : targetPath
}

async function resolveCanonicalPath(filePath: string): Promise<string> {
  const absolute = resolve(filePath)
  try {
    return await realpath(absolute)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code
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

export const EXIT_CODES = {
  VALID: 0,
  EXPIRED: 1,
  REVOKED: 2,
  USAGE_ERROR: 2,
  NOT_FOUND: 3,
  NETWORK_MISMATCH: 4,
  CONTRACT_MISMATCH: 5,
  INCOMPLETE: 6,
  INVALID: 7,
  ERROR: 8,
  UNAVAILABLE: 9,
} as const

export const VERIFY_EXIT_CODES: Record<string, number> = {
  valid: EXIT_CODES.VALID,
  expired: EXIT_CODES.EXPIRED,
  revoked: EXIT_CODES.REVOKED,
  not_found: EXIT_CODES.NOT_FOUND,
  network_mismatch: EXIT_CODES.NETWORK_MISMATCH,
  contract_mismatch: EXIT_CODES.CONTRACT_MISMATCH,
  pending: EXIT_CODES.INCOMPLETE,
  failed: EXIT_CODES.INVALID,
  error: EXIT_CODES.ERROR,
}

export function resolveLineageExitCode(result: LineageTreeResult): number {
  if (result.success) return EXIT_CODES.VALID
  if (result.revokedCount > 0) return EXIT_CODES.REVOKED
  if (result.expiredCount > 0) return EXIT_CODES.EXPIRED
  if (result.cycleDetected || result.disputedCount > 0) return EXIT_CODES.INVALID
  if (result.missingCount > 0) return EXIT_CODES.NOT_FOUND
  if (result.unavailableCount > 0) return EXIT_CODES.UNAVAILABLE
  if (result.incompleteCount > 0) return EXIT_CODES.INCOMPLETE
  return EXIT_CODES.ERROR
}

const BATCH_EXIT_PRECEDENCE: readonly number[] = [
  EXIT_CODES.REVOKED,
  EXIT_CODES.EXPIRED,
  EXIT_CODES.INVALID,
  EXIT_CODES.CONTRACT_MISMATCH,
  EXIT_CODES.NETWORK_MISMATCH,
  EXIT_CODES.NOT_FOUND,
  EXIT_CODES.ERROR,
  EXIT_CODES.UNAVAILABLE,
  EXIT_CODES.INCOMPLETE,
]

/**
 * Aggregate exit codes across a batch of verification checks.
 * Never reports an empty or partially skipped batch as success (0).
 */
export function resolveBatchExitCode(codes: readonly number[]): number {
  if (codes.length === 0) return EXIT_CODES.INCOMPLETE
  for (const candidate of BATCH_EXIT_PRECEDENCE) {
    if (codes.includes(candidate)) return candidate
  }
  const firstNonZero = codes.find((code) => code !== EXIT_CODES.VALID)
  return firstNonZero ?? EXIT_CODES.VALID
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
    case 'check-compat':
      return await handleCheckCompat(flags, debugLog)
    case 'manifest':
      return await handleManifest(flags, debugLog)
    case 'hash':
      return await handleHash(flags)
    case 'verify-receipt':
      return await handleVerifyReceipt(flags, debugLog)
    case 'compare-receipt':
      return await handleCompareReceipt(flags, debugLog)
    case 'c2pa':
      return await handleC2pa(flags, debugLog)
    case 'verify-lineage':
      return await handleVerifyLineage(flags, debugLog)
    case 'verify-bundle':
      return await handleVerifyBundle(flags, debugLog)
    case 'register':
      return await handleRegister(flags, debugLog)
    case 'version':
      return printVersion()
    case 'help':
      return printHelp()
    default:
      return printUnknownCommand(command)
  }
}

async function handleVerify(flags: Record<string, string>, debugLog: (event: Record<string, unknown>) => void): Promise<void> {
  const contractId = flags['contract-id'] || flags.contractId
  const manifestPath = flags.manifest || flags.m
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

  // ── Read manifest (file, stdin, or flag-constructed) ──────────────────
  let manifest: ReturnType<typeof parseManifest>

  if (!manifestPath) {
    exit(8, '--manifest is required for verification')
  }
  try {
    manifest = parseManifest(await readText(manifestPath))
  } catch {
    exit(8, 'invalid or unreadable manifest')
  }

  if (manifest.contractId !== contractId) exit(5, 'contract_mismatch')
  if (manifest.network !== network) exit(4, 'network_mismatch')
  if (txHash && txHash.toLowerCase() !== manifest.transactionRef.toLowerCase()) {
    exit(8, 'transaction hash does not match manifest')
  }

  debugLog({ event: 'verify.manifest', manifest: redactSensitive(manifest) })

  let receipt: VerificationReceipt

  if (offline) {
    receipt = createReceipt(
      manifest,
      { status: 'pending', txHash: manifest.transactionRef },
      null,
      'pending',
    )
  } else {
    try {
      const txVerification = await verifyTransaction(manifest.transactionRef, contractId, { rpcUrl, sourceAddress, timeoutMs })

      const chainRecord = await lookupByVideoHash(contractId, manifest.videoHash, {
        rpcUrl,
        sourceAddress,
        networkPassphrase: network,
        timeoutMs,
      })

      const result = classifyVerification(manifest, txVerification, chainRecord)
      receipt = createReceipt(manifest, txVerification, chainRecord, result)
    } catch (err) {
      if (err instanceof LookupTimeoutError) exit(EXIT_CODES.UNAVAILABLE, 'verification dependency unavailable: RPC timeout')
      exit(EXIT_CODES.UNAVAILABLE, 'verification dependency unavailable')
    }
  }

  if (outputFormat === 'json') {
    printJson(receipt)
  } else {
    printText(formatReceipt(receipt))
  }

  exit(VERIFY_EXIT_CODES[receipt.result] ?? EXIT_CODES.ERROR)
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

  if (outputPath && (await pathsResolveToSameFile(inputPath, outputPath))) {
    exit(2, '--output must not resolve to the same file as --input')
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
    exit(EXIT_CODES.INVALID)
  }
}

async function handleCompareReceipt(
  flags: Record<string, string>,
  debugLog: (event: Record<string, unknown>) => void,
): Promise<void> {
  const basePath = flags.base || flags.b || flags['receipt-a'] || flags.receiptA
  const targetPath = flags.target || flags.t || flags['receipt-b'] || flags.receiptB || flags.candidate
  const outputFormat = flags.output || flags.o || 'text'

  if (!basePath || !targetPath) {
    exit(2, '--base and --target are required for receipt comparison')
  }

  if (basePath === '-' && targetPath === '-') {
    exit(2, 'cannot read both receipts from stdin')
  }

  if (outputFormat !== 'text' && outputFormat !== 'json') {
    exit(2, `invalid value "${outputFormat}" for --output; expected "text" or "json"`)
  }

  let baseRaw: string
  try {
    baseRaw = await readText(basePath)
  } catch (err) {
    debugLog({ event: 'compare-receipt.base-read-failed', error: String(err) })
    exit(8, `failed to read base receipt: ${basePath}`)
  }

  let targetRaw: string
  try {
    targetRaw = await readText(targetPath)
  } catch (err) {
    debugLog({ event: 'compare-receipt.target-read-failed', error: String(err) })
    exit(8, `failed to read target receipt: ${targetPath}`)
  }

  let baseParsed: unknown
  try {
    baseParsed = parseReceiptInput(baseRaw)
  } catch (err) {
    debugLog({ event: 'compare-receipt.base-parse-failed', error: String(err) })
    exit(8, `invalid base receipt: ${err instanceof Error ? err.message : String(err)}`)
  }

  let targetParsed: unknown
  try {
    targetParsed = parseReceiptInput(targetRaw)
  } catch (err) {
    debugLog({ event: 'compare-receipt.target-parse-failed', error: String(err) })
    exit(8, `invalid target receipt: ${err instanceof Error ? err.message : String(err)}`)
  }

  debugLog({
    event: 'compare-receipt.comparing',
    base: typeof baseParsed === 'object' && baseParsed !== null ? redactSensitive(baseParsed as Record<string, unknown>) : baseParsed,
    target: typeof targetParsed === 'object' && targetParsed !== null ? redactSensitive(targetParsed as Record<string, unknown>) : targetParsed,
  })

  let result: ReceiptComparisonResult
  try {
    result = compareReceipts(baseParsed, targetParsed)
  } catch (err) {
    debugLog({ event: 'compare-receipt.diff-failed', error: String(err) })
    exit(8, `comparison failed: ${err instanceof Error ? err.message : String(err)}`)
  }

  if (outputFormat === 'json') {
    printJson(result)
  } else {
    printText(formatComparisonResult(result))
  }

  if (result.match) {
    process.exit(0)
  } else {
    process.exit(1)
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

  if (outputPath && (await pathsResolveToSameFile(inputPath, outputPath))) {
    exit(2, '--output must not resolve to the same file as --manifest')
  }
  if (outputPath && receiptPath && (await pathsResolveToSameFile(receiptPath, outputPath))) {
    exit(2, '--output must not resolve to the same file as --receipt')
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
    const code = resolveLineageExitCode(result)
    if (code === EXIT_CODES.REVOKED) exit(code, 'an ancestor is revoked')
    if (code === EXIT_CODES.EXPIRED) exit(code, 'an ancestor is expired')
    if (code === EXIT_CODES.INVALID) exit(code, result.failureReason ?? 'lineage verification invalid')
    if (code === EXIT_CODES.NOT_FOUND) exit(code, 'an ancestor is missing')
    if (code === EXIT_CODES.UNAVAILABLE) exit(code, result.failureReason ?? 'lineage verification unavailable')
    if (code === EXIT_CODES.INCOMPLETE) exit(code, result.failureReason ?? 'lineage verification incomplete')
    exit(code, result.failureReason ?? 'lineage verification failed')
  }

  exit(EXIT_CODES.VALID)
}

export const STATUS_EXIT_CODES: Record<ProofLifecycleStatus, number> = {
  registered: 0,
  expired: 1,
  revoked: 2,
  unknown: 3,
}

async function handleVerifyBundle(
  flags: Record<string, string>,
  debugLog: (event: Record<string, unknown>) => void,
): Promise<void> {
  const bundlePath = flags.bundle || flags.b
  if (!bundlePath) exit(2, '--bundle is required')

  let bundle: ReturnType<typeof parseOfflineBundle>
  try {
    const raw = await readText(bundlePath)
    bundle = parseOfflineBundle(raw)
  } catch (err) {
    exit(8, err instanceof Error ? err.message : 'invalid or unreadable bundle')
  }

  debugLog({ event: 'verify-bundle.input', bundle: redactSensitive(bundle) })

  const report = await verifyOfflineBundle(bundle)

  if (flags.output === 'json' || flags.o === 'json') {
    printJson(report)
  } else {
    printText(formatOfflineBundleReport(report))
  }
  exit(report.summary.allValid ? 0 : 8)
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
    exit(EXIT_CODES.UNAVAILABLE, 'status lookup dependency unavailable')
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

export async function handleCheckCompat(
  flags: Record<string, string>,
  debugLog: (event: Record<string, unknown>) => void = () => {},
): Promise<void> {
  const code = await runCheckCompat(flags, {
    readText,
    writeStdout: (text) => process.stdout.write(text),
    writeStderr: (text) => process.stderr.write(text),
    debugLog,
  })
  exit(code)
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
  check-compat   Compare bundle metadata against selected network and contract config.
  verify-lineage Verify a derivative's full lineage back to registered originals.
  register       Register a source or seal proof using a local signing key.
  manifest       Create a proof manifest from metadata.
  hash           Compute the SHA-256 hash of a file.
  verify-receipt Verify an offline signed receipt.
  compare-receipt Compare two verification receipts and report canonical statement and trust differences.
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

Check-compat options:
  --manifest, -m    Path to a proof manifest JSON file (use "-" for stdin; required).
  --contract-id     Selected contract ID on Stellar to compare against (required).
  --network         Selected network: testnet, mainnet/public, futurenet, or a full passphrase (default: testnet).
  --output, -o      Output format: "text" (default) or "json".
  Performs local metadata inspection only: no signing, no chain writes, and no RPC calls.

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
  --output, -o     File path to write the exported assertions to (must differ from input paths, including symlinks).
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

Compare receipt options:
  --base, -b       Path to base verification receipt file (use "-" for stdin; required, or positional 1).
  --target, -t     Path to target verification receipt file (use "-" for stdin; required, or positional 2).
  --output, -o     Output format: "text" (default) or "json".
  Accepts VerificationReceipt, SignedVerificationReceipt, or QR payload.
  Exits 0 when identical, 1 when differences detected, 2 on usage error, 8 on read/parse error.

Verify options:
  --contract-id     Contract ID on Stellar (required).
  --manifest        Path to a proof manifest JSON file (use "-" for stdin).
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
  --output, -o      File path to write the manifest to (must differ from --input, including symlinks).
  --format          Output format when printing to stdout: "json" (default) or "text".

Hash options:
  --file, -f        Path to the file to hash (use "-" for stdin; required).
  --output, -o      Output format: "text" (default) or "json".

Verify-bundle options:
  --bundle, -b      Path to a local offline-verification bundle JSON (use "-"
                    for stdin; required). The bundle holds a trust snapshot
                    (verifier keys + network), manifests and signed receipts.
  --output, -o      Output format: "text" (default) or "json".
  Validates manifests and receipts offline; on-chain checks (proof status,
  transaction confirmation, lineage) are reported as unavailable.

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
  2   revoked / usage error
  3   not_found / missing / unknown
  4   network_mismatch
  5   contract_mismatch
  6   incomplete / pending (offline verification, skipped required checks, or bounded lineage)
  7   invalid / failed (failed transaction, invalid receipt, disputed ancestor, or lineage cycle)
  8   error (malformed input or internal error)
  9   unavailable (RPC timeout, network, or verification dependency unavailable)
  For a full table of every exit code and which commands emit them, see the Exit codes section in cli/README.md.
`
  return help.trim()
}

function printVersion(): void {
  printText(getCliVersion())
  process.exit(0)
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
