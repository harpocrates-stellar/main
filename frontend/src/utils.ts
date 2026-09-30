import { sha256 as incrementalSha256 } from '@noble/hashes/sha2.js'

/** Convert an ArrayBuffer to a lowercase hex string. */
export function hex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

/** SHA-256 hash of a string or binary buffer, returned as lowercase hex. */
export async function sha256(input: ArrayBuffer | string): Promise<string> {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  return hex(await crypto.subtle.digest('SHA-256', bytes))
}

export type HashProgress = {
  processedBytes: number
  totalBytes: number
  percentage: number
}

export const DEFAULT_HASH_CHUNK_SIZE = 4 * 1024 * 1024

export async function sha256Blob(
  blob: Blob,
  onProgress?: (progress: HashProgress) => void,
  signal?: AbortSignal,
  chunkSize = DEFAULT_HASH_CHUNK_SIZE,
): Promise<string> {
  if (chunkSize <= 0) {
    throw new Error('Hash chunk size must be greater than zero.')
  }

  const totalBytes = blob.size
  let processedBytes = 0
  const hash = incrementalSha256.create()

  const reportProgress = () => {
    onProgress?.({
      processedBytes,
      totalBytes,
      percentage:
        totalBytes === 0 ? 100 : Math.floor((processedBytes / totalBytes) * 100),
    })
  }

  signal?.throwIfAborted()
  reportProgress()

  while (processedBytes < totalBytes) {
    signal?.throwIfAborted()

    const end = Math.min(processedBytes + chunkSize, totalBytes)
    const bytes = new Uint8Array(await blob.slice(processedBytes, end).arrayBuffer())

    signal?.throwIfAborted()
    hash.update(bytes)

    processedBytes = end
    reportProgress()

    await new Promise<void>((resolve) => setTimeout(resolve, 0))
  }

  return Array.from(hash.digest(), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
}

const BN254_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

/**
 * Derive a BN254 field element from a human-readable seed string.
 * Used to turn user-supplied credential/nullifier seeds into circuit secrets.
 */
export async function fieldSecret(label: string, seed: string): Promise<string> {
  const digest = await sha256(`harpocrates:${label}:${seed}`)
  const value = BigInt(`0x${digest}`) % BN254_FIELD_MODULUS
  return value === 0n ? '1' : value.toString(10)
}

/** Abbreviate a long hex string for display: first 12 + last 10 chars. */
export function shortHash(value: string): string {
  if (!value) return 'Not generated'
  return `${value.slice(0, 12)}...${value.slice(-10)}`
}
