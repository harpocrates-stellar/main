import { createReadStream } from 'node:fs'
import { readdir, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { StrKey } from '@stellar/stellar-sdk'
import { sha256 } from './hashing.js'
import { parseManifest, serializeManifest, type ProofManifest } from './manifest.js'
import type { IdentityTier } from './metadata.js'
import { DEFAULT_NETWORK_PASSPHRASE, resolveNetwork } from './network.js'
import { classifyVerification } from './normalize.js'
import { createReceipt, type VerificationReceipt, type VerificationResult } from './receipt.js'
import {
  lookupByVideoHash,
  verifyTransaction,
  type ChainProofRecord,
  type TransactionVerification,
} from './stellar-lookup.js'

export const BATCH_VERIFY_PROTOCOL = 'harpocrates-batch-verification' as const
export const BATCH_VERIFY_VERSION = 1 as const
export const DEFAULT_MAX_BATCH_ITEMS = 64
export const ABSOLUTE_MAX_BATCH_ITEMS = 64
export const MAX_BATCH_INPUT_BYTES = 1024 * 1024

export class BatchBoundError extends Error {
  readonly code = 'BATCH_BOUND_EXCEEDED' as const
  constructor(message: string) {
    super(message)
    this.name = 'BatchBoundError'
  }
}

export type BatchProgressEvent =
  | {
      protocol: typeof BATCH_VERIFY_PROTOCOL
      version: typeof BATCH_VERIFY_VERSION
      type: 'progress'
      phase: 'start'
      total: number
      maxItems: number
    }
  | {
      protocol: typeof BATCH_VERIFY_PROTOCOL
      version: typeof BATCH_VERIFY_VERSION
      type: 'progress'
      phase: 'item'
      index: number
      completed: number
      total: number
      itemId: string
      proofId: string | null
      result: VerificationResult
      exitCode: number
    }
  | {
      protocol: typeof BATCH_VERIFY_PROTOCOL
      version: typeof BATCH_VERIFY_VERSION
      type: 'progress'
      phase: 'complete'
      completed: number
      total: number
      validCount: number
      failedCount: number
      pendingCount: number
      exitCode: number
    }

export type BatchVerificationResultRecord = {
  protocol: typeof BATCH_VERIFY_PROTOCOL
  version: typeof BATCH_VERIFY_VERSION
  type: 'result'
  index: number
  itemId: string
  proofId: string | null
  tier: IdentityTier | null
  network: string
  contractId: string
  result: VerificationResult
  exitCode: number
  reason?: string
  receipt: VerificationReceipt | null
}

export type BatchChainVerifier = {
  verifyTransaction(txHash: string, contractId: string): Promise<TransactionVerification>
  lookupByVideoHash(contractId: string, videoHash: string, networkPassphrase: string): Promise<ChainProofRecord | null>
}

export type RunBatchVerificationOptions = {
  manifestPaths: readonly string[]
  contractId: string
  network?: string
  offline?: boolean
  maxItems?: number
  rpcUrl?: string
  sourceAddress?: string
  timeoutMs?: number
  chainVerifier?: BatchChainVerifier
  onProgress?: (event: BatchProgressEvent) => void
  onResult?: (record: BatchVerificationResultRecord) => void
}

export type BatchVerificationRunSummary = {
  total: number
  validCount: number
  pendingCount: number
  failedCount: number
  exitCode: number
  results: BatchVerificationResultRecord[]
}

const EXIT_CODE_BY_RESULT: Record<VerificationResult, number> = {
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

const BATCH_EXIT_PRECEDENCE = [8, 2, 7, 5, 4, 1, 3, 6, 0] as const

function canonicalJsonLine(value: unknown): string {
  const sortKeysDeep = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sortKeysDeep)
    if (v !== null && typeof v === 'object') {
      const obj = v as Record<string, unknown>
      const out: Record<string, unknown> = {}
      for (const k of Object.keys(obj).sort()) {
        if (obj[k] !== undefined) {
          out[k] = sortKeysDeep(obj[k])
        }
      }
      return out
    }
    return v
  }
  return JSON.stringify(sortKeysDeep(value))
}

export function serializeBatchJsonLine(record: BatchProgressEvent | BatchVerificationResultRecord): string {
  return canonicalJsonLine(record)
}

async function readBoundedFileBytes(filePath: string, maxBytes = MAX_BATCH_INPUT_BYTES): Promise<Buffer> {
  const chunks: Buffer[] = []
  let size = 0
  const stream = createReadStream(filePath)
  for await (const chunk of stream) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    size += buf.byteLength
    if (size > maxBytes) {
      stream.destroy()
      throw new BatchBoundError('manifest exceeds the 1 MiB input limit')
    }
    chunks.push(buf)
  }
  return Buffer.concat(chunks, size)
}

/**
 * Compute a deterministic, privacy-safe item identity without exposing local
 * filesystem paths.
 */
export function computeDeterministicItemId(
  manifest: ProofManifest | null,
  rawBytes: Uint8Array | null,
  index: number,
): string {
  if (manifest !== null) {
    const canonicalBytes = new TextEncoder().encode(serializeManifest(manifest))
    return `manifest:${sha256(canonicalBytes)}`
  }
  if (rawBytes !== null) {
    return `raw:${sha256(rawBytes)}`
  }
  return `unreadable:${String(index).padStart(4, '0')}`
}

/**
 * Load a bounded list of manifest paths from either a directory (sorted
 * deterministically by filename, `.json` files only) or a JSON array file.
 */
export async function resolveBatchManifestSelection(
  selectionPath: string,
  maxItems = DEFAULT_MAX_BATCH_ITEMS,
): Promise<string[]> {
  if (!Number.isSafeInteger(maxItems) || maxItems <= 0 || maxItems > ABSOLUTE_MAX_BATCH_ITEMS) {
    throw new BatchBoundError(`maxItems must be between 1 and ${ABSOLUTE_MAX_BATCH_ITEMS}`)
  }

  const info = await stat(selectionPath)
  if (info.isDirectory()) {
    const entries = await readdir(selectionPath, { withFileTypes: true })
    const jsonFiles = entries
      .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.json'))
      .map((entry) => entry.name)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))

    if (jsonFiles.length === 0) {
      throw new BatchBoundError('batch directory contains no manifest JSON files')
    }
    if (jsonFiles.length > maxItems) {
      throw new BatchBoundError(`batch selection (${jsonFiles.length}) exceeds maximum of ${maxItems} items`)
    }
    return jsonFiles.map((name) => join(selectionPath, name))
  }

  const rawBuf = await readBoundedFileBytes(selectionPath, MAX_BATCH_INPUT_BYTES)
  let parsed: unknown
  try {
    parsed = JSON.parse(rawBuf.toString('utf-8'))
  } catch {
    throw new Error('batch manifest list is not valid JSON')
  }
  if (!Array.isArray(parsed)) {
    throw new Error('batch manifest list must be a JSON array of file paths')
  }
  if (parsed.length === 0) {
    throw new BatchBoundError('batch manifest list must contain at least 1 item')
  }
  if (parsed.length > maxItems) {
    throw new BatchBoundError(`batch selection (${parsed.length}) exceeds maximum of ${maxItems} items`)
  }
  for (const entry of parsed) {
    if (typeof entry !== 'string' || entry.trim() === '' || entry === '-') {
      throw new Error('batch manifest list entries must be non-empty file paths')
    }
  }
  return parsed as string[]
}

function aggregateExitCode(codes: readonly number[]): number {
  if (codes.length === 0) return 8
  const set = new Set(codes)
  for (const candidate of BATCH_EXIT_PRECEDENCE) {
    if (set.has(candidate)) return candidate
  }
  return 8
}

/**
 * Execute bounded batch manifest verification, emitting progress records via
 * `onProgress` (for `stderr`) and result records via `onResult` (for `stdout`).
 */
export async function runBatchVerification(
  options: RunBatchVerificationOptions,
): Promise<BatchVerificationRunSummary> {
  const maxItems = options.maxItems ?? DEFAULT_MAX_BATCH_ITEMS
  if (!Number.isSafeInteger(maxItems) || maxItems <= 0 || maxItems > ABSOLUTE_MAX_BATCH_ITEMS) {
    throw new BatchBoundError(`maxItems must be between 1 and ${ABSOLUTE_MAX_BATCH_ITEMS}`)
  }
  if (!StrKey.isValidContract(options.contractId)) {
    throw new Error('a valid contractId is required for batch verification')
  }
  if (options.manifestPaths.length === 0) {
    throw new BatchBoundError('batch manifest selection must contain at least 1 item')
  }
  if (options.manifestPaths.length > maxItems) {
    throw new BatchBoundError(
      `batch selection (${options.manifestPaths.length}) exceeds maximum of ${maxItems} items`,
    )
  }

  const network = resolveNetwork(options.network || DEFAULT_NETWORK_PASSPHRASE)
  const offline = options.offline === true
  const total = options.manifestPaths.length

  const verifier: BatchChainVerifier = options.chainVerifier ?? {
    verifyTransaction: (txHash, cid) =>
      verifyTransaction(txHash, cid, {
        rpcUrl: options.rpcUrl,
        sourceAddress: options.sourceAddress,
        timeoutMs: options.timeoutMs,
      }),
    lookupByVideoHash: (cid, videoHash, networkPassphrase) =>
      lookupByVideoHash(cid, videoHash, {
        rpcUrl: options.rpcUrl,
        sourceAddress: options.sourceAddress,
        networkPassphrase,
        timeoutMs: options.timeoutMs,
      }),
  }

  options.onProgress?.({
    protocol: BATCH_VERIFY_PROTOCOL,
    version: BATCH_VERIFY_VERSION,
    type: 'progress',
    phase: 'start',
    total,
    maxItems,
  })

  const results: BatchVerificationResultRecord[] = []

  for (let index = 0; index < total; index++) {
    const manifestPath = options.manifestPaths[index]
    let rawBytes: Buffer | null = null
    let manifest: ProofManifest | null = null
    let readReason: string | undefined

    try {
      rawBytes = await readBoundedFileBytes(manifestPath, MAX_BATCH_INPUT_BYTES)
      manifest = parseManifest(rawBytes.toString('utf-8'))
    } catch (err) {
      readReason =
        err instanceof BatchBoundError ? 'input_limit_exceeded' : 'invalid_or_unreadable_manifest'
    }

    const itemId = computeDeterministicItemId(manifest, rawBytes, index)

    let record: BatchVerificationResultRecord
    if (!manifest) {
      record = {
        protocol: BATCH_VERIFY_PROTOCOL,
        version: BATCH_VERIFY_VERSION,
        type: 'result',
        index,
        itemId,
        proofId: null,
        tier: null,
        network,
        contractId: options.contractId,
        result: 'error',
        exitCode: EXIT_CODE_BY_RESULT.error,
        reason: readReason ?? 'invalid_or_unreadable_manifest',
        receipt: null,
      }
    } else if (manifest.contractId !== options.contractId) {
      record = {
        protocol: BATCH_VERIFY_PROTOCOL,
        version: BATCH_VERIFY_VERSION,
        type: 'result',
        index,
        itemId,
        proofId: manifest.proofId,
        tier: manifest.tier,
        network,
        contractId: options.contractId,
        result: 'contract_mismatch',
        exitCode: EXIT_CODE_BY_RESULT.contract_mismatch,
        reason: 'contract_mismatch',
        receipt: null,
      }
    } else if (manifest.network !== network) {
      record = {
        protocol: BATCH_VERIFY_PROTOCOL,
        version: BATCH_VERIFY_VERSION,
        type: 'result',
        index,
        itemId,
        proofId: manifest.proofId,
        tier: manifest.tier,
        network,
        contractId: options.contractId,
        result: 'network_mismatch',
        exitCode: EXIT_CODE_BY_RESULT.network_mismatch,
        reason: 'network_mismatch',
        receipt: null,
      }
    } else if (offline) {
      const receipt = createReceipt(
        manifest,
        { status: 'pending', txHash: manifest.transactionRef },
        null,
        'pending',
      )
      record = {
        protocol: BATCH_VERIFY_PROTOCOL,
        version: BATCH_VERIFY_VERSION,
        type: 'result',
        index,
        itemId,
        proofId: manifest.proofId,
        tier: manifest.tier,
        network,
        contractId: options.contractId,
        result: 'pending',
        exitCode: EXIT_CODE_BY_RESULT.pending,
        receipt,
      }
    } else {
      try {
        const txVerification = await verifier.verifyTransaction(
          manifest.transactionRef,
          options.contractId,
        )
        const chainRecord = await verifier.lookupByVideoHash(
          options.contractId,
          manifest.videoHash,
          network,
        )
        const outcome = classifyVerification(manifest, txVerification, chainRecord)
        const receipt = createReceipt(manifest, txVerification, chainRecord, outcome)
        record = {
          protocol: BATCH_VERIFY_PROTOCOL,
          version: BATCH_VERIFY_VERSION,
          type: 'result',
          index,
          itemId,
          proofId: manifest.proofId,
          tier: manifest.tier,
          network,
          contractId: options.contractId,
          result: outcome,
          exitCode: EXIT_CODE_BY_RESULT[outcome],
          receipt,
        }
      } catch {
        record = {
          protocol: BATCH_VERIFY_PROTOCOL,
          version: BATCH_VERIFY_VERSION,
          type: 'result',
          index,
          itemId,
          proofId: manifest.proofId,
          tier: manifest.tier,
          network,
          contractId: options.contractId,
          result: 'error',
          exitCode: EXIT_CODE_BY_RESULT.error,
          reason: 'verification_dependency_failed',
          receipt: null,
        }
      }
    }

    results.push(record)
    options.onResult?.(record)
    options.onProgress?.({
      protocol: BATCH_VERIFY_PROTOCOL,
      version: BATCH_VERIFY_VERSION,
      type: 'progress',
      phase: 'item',
      index,
      completed: index + 1,
      total,
      itemId,
      proofId: record.proofId,
      result: record.result,
      exitCode: record.exitCode,
    })
  }

  const exitCode = aggregateExitCode(results.map((r) => r.exitCode))
  const validCount = results.filter((r) => r.result === 'valid').length
  const pendingCount = results.filter((r) => r.result === 'pending').length
  const failedCount = total - validCount - pendingCount

  options.onProgress?.({
    protocol: BATCH_VERIFY_PROTOCOL,
    version: BATCH_VERIFY_VERSION,
    type: 'progress',
    phase: 'complete',
    completed: total,
    total,
    validCount,
    failedCount,
    pendingCount,
    exitCode,
  })

  return {
    total,
    validCount,
    pendingCount,
    failedCount,
    exitCode,
    results,
  }
}
