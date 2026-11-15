/**
 * verificationService — network calls for the verification portal flow.
 *
 * Responsibility: talk to the Flask extract API, NeonDB Lookup, and the
 * Soroban on-chain registry. Returns plain data; no React state.
 */

import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import { ApiClientError, parseActionableApiError } from './apiError'
import { fetchWithTimeout, JSON_REQUEST_TIMEOUT_MS, UPLOAD_TIMEOUT_MS } from './http'
import { assertValidVideoHash } from './videoHash'

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:5050'
const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''
export type ExtractResult = {
  hasHarpocratesMetadata: boolean
  metadataHash?: string | null
}

/** Ask the Flask service to extract steganographic metadata from a video. */
export async function extractMetadata(file: File, signal?: AbortSignal): Promise<ExtractResult> {
  const form = new FormData()
  form.append('video', file)

  const response = await fetchWithTimeout(`${API_BASE}/api/stego/extract`, {
    method: 'POST',
    body: form,
    signal,
  }, UPLOAD_TIMEOUT_MS)
  if (!response.ok) {
    throw new ApiClientError(await parseActionableApiError(response, 'Extraction service is unavailable.'))
  }
  const data = await response.json()
  return {
    hasHarpocratesMetadata: data.metadata?.protocol === 'harpocrates',
    metadataHash: typeof data.metadataHash === 'string'
      ? data.metadataHash
      : typeof data.metadata_hash === 'string'
        ? data.metadata_hash
        : typeof data.metadata?.metadataHash === 'string'
          ? data.metadata.metadataHash
          : null,
  }
}

/** Look up all NeonDB proof events for a given video hash. */
export async function fetchProofEventsByVideo(
  videoHash: string,
  signal?: AbortSignal,
  apiBase: string = API_BASE,
): Promise<ProofEvent[]> {
  // Validate before building the URL so malformed hashes never reach the network.
  const safeHash = assertValidVideoHash(videoHash)
  const base = apiBase || API_BASE
  const response = await fetchWithTimeout(`${base}/api/proofs/by-video/${safeHash}`, { signal }, JSON_REQUEST_TIMEOUT_MS)
  if (!response.ok) {
    throw new ApiClientError(await parseActionableApiError(response, 'Database lookup failed.'))
  }
  const data = await response.json()
  return (data.events ?? []) as ProofEvent[]
}

/**
 * Simulate `get_by_video` against the Soroban registry.
 * Returns null when the contract ID is not configured or the record is not found.
 */
export async function getOnChainProof(
  videoHash: string,
  sourceAddress?: string,
): Promise<ChainProofRecord | null> {
  if (!CONTRACT_ID) return null
  const safeHash = assertValidVideoHash(videoHash)
  const { getProofByVideoHash } = await import('../stellar')
  return getProofByVideoHash(CONTRACT_ID, safeHash, sourceAddress)
}

export const VERIFICATION_LIMITS = {
  maxFileSizeBytes: 100 * 1024 * 1024,
  supportedTypes: ['video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo', 'video/avi'],
} as const

export async function getMetadataEnvelopeRaw(
  _proofId: string,
): Promise<{
  version?: number | string
  metadata_hash?: string
  metadataHash?: string
  bound_at?: number | string
  boundAt?: number | string
} | null> {
  if (!CONTRACT_ID) return null
  return null
}

export async function getTimestampClaimRaw(
  _proofId: string,
): Promise<{
  proof_id?: string
  proofId?: string
  claimed_at?: number | string
  claimedAt?: number | string
  sources?: number | string
} | null> {
  if (!CONTRACT_ID) return null
  return null
}

export async function getIndependentTimestampAnchorRaw(_proofId: string): Promise<boolean | null> {
  if (!CONTRACT_ID) return null
  return null
}

export async function getMetadataEnvelope(proofId: string) {
  const { getMetadataEnvelope: readEnvelope } = await import('../lib/harpocratesRegistry')
  return readEnvelope(proofId)
}
