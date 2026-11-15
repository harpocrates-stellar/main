/*
 * useEvidence — manages the full evidence creation flow: hashing → embedding → (optional) Noir proving → Stellar registration.
 *
 * Source-file hashing runs chunk-by-chunk inside a dedicated Web Worker with
 * byte-level progress, keeping the UI responsive for large videos.
 *
 * Silent Witness proving runs in a cancellable Web Worker so the UI keeps responsive
 * and in-flight proofs can be aborted without leaking witness material (see
 * docs/proof-worker.md).
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import { Building2, Fingerprint, KeyRound } from 'lucide-react'
import type { IdentityTier, ProofPackage, SilentWitnessProof, Stage } from '../types'
import type { RegisterProofResult } from '../stellarTypes'
import type { HashProgress } from '../utils'
import {
  ProofWorkerClient,
  ProofWorkerError,
} from '../workers/proofWorkerClient'
import { hashFileInWorker } from '../workers/fileHashWorkerClient'
import { BN254_FIELD_MODULUS, CIRCUIT_INPUT_SCHEMA_VERSION } from '../circuitInputSchema'
import { appConfig } from '../config'

export const TIERS = [
  {
    id: 'silent' as IdentityTier,
    title: 'Silent Witness',
    label: 'Anonymous Credential',
    icon: Fingerprint,
    description: 'Noir ZK proof, nullifier replay protection, no public creator identity.',
  },
  {
    id: 'source' as IdentityTier,
    title: 'Consistent Source',
    label: 'Pseudonymous Wallet',
    icon: KeyRound,
    description: 'Freighter signature links evidence to a recurring Stellar source.',
  },
  {
    id: 'seal' as IdentityTier,
    title: 'Public Seal',
    label: 'Institutional Issuer',
    icon: Building2,
    description:
      'Verified issuer account signs the evidence as an official source. The connected wallet must be registered by the admin first.',
  },]

const CONTRACT_ID = appConfig.harpocratesRegistryId

// Privacy-safe stable copy — never includes file names, hashes, or secrets.
const CANCELLED_MESSAGES: Record<Stage, string> = {
  idle: 'Request cancelled.',
  hashing: 'Upload cancelled.',
  embedding: 'Upload cancelled.',
  proving: 'Proof generation cancelled.',
  ready: 'Request cancelled.',
  registering: 'Request cancelled.',
  registered: 'Request cancelled.',
  error: 'Request cancelled.',
  cancelled: 'Request cancelled.',
}

export const PROOF_PREPARATION_POLICY_VERSION = 'harpocrates-proof-policy-v1' as const
export const CONCEALED_WITNESS_PLACEHOLDER = '[CONCEALED WITNESS]' as const

export type CanonicalPublicInputEntry = {
  name: string
  encoding: 'bn254_field_dec' | 'sha256_hex' | 'identifier'
  value: string
}

export type ConcealedWitnessEntry = {
  name: 'credential_secret' | 'nullifier_secret'
  displayValue: typeof CONCEALED_WITNESS_PLACEHOLDER
  configured: boolean
  validFieldScalar: boolean
}

export type ProofPreparationPreview =
  | {
      ok: true
      readOnly: true
      policyVersion: typeof PROOF_PREPARATION_POLICY_VERSION
      inputSchemaVersion: number
      tier: IdentityTier
      verifierScope: string
      epoch: number
      publicInputs: ReadonlyArray<CanonicalPublicInputEntry>
      concealedWitnesses: ReadonlyArray<ConcealedWitnessEntry>
      witnessReady: boolean
    }
  | {
      ok: false
      readOnly: true
      code: 'MISSING_EVIDENCE' | 'INVALID_PUBLIC_INPUT'
      policyVersion: typeof PROOF_PREPARATION_POLICY_VERSION
      inputSchemaVersion: number
      message: string
    }

const HEX_64_PATTERN = /^[0-9a-fA-F]{64}$/
const FIELD_SCALAR_PATTERN = /^(?:0|[1-9][0-9]*|0[xX][0-9a-fA-F]+)$/

function isValidFieldScalar(raw: string): boolean {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 80 || !FIELD_SCALAR_PATTERN.test(raw)) {
    return false
  }
  try {
    return BigInt(raw) < BN254_FIELD_MODULUS
  } catch {
    return false
  }
}

/**
 * Pure, read-only builder for canonical proof preparation inputs.
 * Never exposes private witness values and performs zero proving or chain submission.
 */
export function buildProofPreparationPreview(params: {
  proof: ProofPackage | null
  tier: IdentityTier
  credentialSeed?: string
  nullifierSeed?: string
  verifierScope?: string
  epoch?: number
}): ProofPreparationPreview {
  const {
    proof,
    tier,
    credentialSeed = '',
    nullifierSeed = '',
    verifierScope = '0',
    epoch = Math.floor(Date.now() / 86400000),
  } = params

  if (!proof) {
    return {
      ok: false,
      readOnly: true,
      code: 'MISSING_EVIDENCE',
      policyVersion: PROOF_PREPARATION_POLICY_VERSION,
      inputSchemaVersion: CIRCUIT_INPUT_SCHEMA_VERSION,
      message: 'Upload and embed evidence before previewing proof preparation.',
    }
  }

  if (
    !HEX_64_PATTERN.test(proof.videoHash) ||
    !HEX_64_PATTERN.test(proof.metadataHash) ||
    !HEX_64_PATTERN.test(proof.proofId) ||
    !isValidFieldScalar(verifierScope) ||
    !Number.isSafeInteger(epoch) ||
    epoch < 0
  ) {
    return {
      ok: false,
      readOnly: true,
      code: 'INVALID_PUBLIC_INPUT',
      policyVersion: PROOF_PREPARATION_POLICY_VERSION,
      inputSchemaVersion: CIRCUIT_INPUT_SCHEMA_VERSION,
      message: 'Prepared evidence digests or scope parameters cannot form canonical public inputs.',
    }
  }

  const normalizedScope = BigInt(verifierScope).toString(10)
  const videoHashHi = BigInt(`0x${proof.videoHash.slice(0, 32)}`).toString(10)
  const videoHashLo = BigInt(`0x${proof.videoHash.slice(32)}`).toString(10)

  const publicInputs: CanonicalPublicInputEntry[] =
    tier === 'silent'
      ? [
          { name: 'video_hash_hi', encoding: 'bn254_field_dec', value: videoHashHi },
          { name: 'video_hash_lo', encoding: 'bn254_field_dec', value: videoHashLo },
          { name: 'verifier_scope', encoding: 'bn254_field_dec', value: normalizedScope },
          { name: 'epoch', encoding: 'bn254_field_dec', value: String(epoch) },
          { name: 'metadata_hash', encoding: 'sha256_hex', value: proof.metadataHash.toLowerCase() },
          { name: 'proof_id', encoding: 'sha256_hex', value: proof.proofId.toLowerCase() },
        ]
      : [
          { name: 'tier', encoding: 'identifier', value: tier },
          { name: 'video_hash', encoding: 'sha256_hex', value: proof.videoHash.toLowerCase() },
          { name: 'metadata_hash', encoding: 'sha256_hex', value: proof.metadataHash.toLowerCase() },
          { name: 'proof_id', encoding: 'sha256_hex', value: proof.proofId.toLowerCase() },
        ]

  const credValid = isValidFieldScalar(credentialSeed)
  const nullValid = isValidFieldScalar(nullifierSeed)
  const concealedWitnesses: ConcealedWitnessEntry[] =
    tier === 'silent'
      ? [
          {
            name: 'credential_secret',
            displayValue: CONCEALED_WITNESS_PLACEHOLDER,
            configured: credentialSeed.length > 0,
            validFieldScalar: credValid,
          },
          {
            name: 'nullifier_secret',
            displayValue: CONCEALED_WITNESS_PLACEHOLDER,
            configured: nullifierSeed.length > 0,
            validFieldScalar: nullValid,
          },
        ]
      : []

  return {
    ok: true,
    readOnly: true,
    policyVersion: PROOF_PREPARATION_POLICY_VERSION,
    inputSchemaVersion: CIRCUIT_INPUT_SCHEMA_VERSION,
    tier,
    verifierScope: normalizedScope,
    epoch,
    publicInputs,
    concealedWitnesses,
    witnessReady: tier !== 'silent' || (credValid && nullValid),
  }
}

export type UseEvidenceReturn = {
  selectedTier: IdentityTier
  setSelectedTier: (tier: IdentityTier) => void
  selectedTierMeta: (typeof TIERS)[number]
  stage: Stage
  /** Byte-level progress of the current source-file hashing run (null when idle). */
  hashProgress: HashProgress | null
  file: File | null
  proof: ProofPackage | null
  processedVideoUrl: string
  credentialSeed: string
  setCredentialSeed: (v: string) => void
  nullifierSeed: string
  setNullifierSeed: (v: string) => void
  proofPreview?: ProofPreparationPreview
  isProofPreviewOpen?: boolean
  openProofPreview?: () => void
  closeProofPreview?: () => void
  message: string
  registration: RegisterProofResult | null
  networkMismatch: string | null
  isCancellable: boolean
  handleEvidence: (nextFile: File | null) => Promise<void>
  registerProof: (wallet: string) => Promise<void>
  cancelEvidence: () => void
  /** Cancel an in-flight Silent Witness proof generation (no-op if idle). */
  cancelProving: () => void
}

type PendingRegistration = {
  key: string
  proof: ProofPackage
  result: RegisterProofResult
  wallet: string
}

export function useEvidence(): UseEvidenceReturn {
  const [selectedTier, setSelectedTier] = useState<IdentityTier>('silent')
  const [stage, setStage] = useState<Stage>('idle')
  const [hashProgress, setHashProgress] = useState<HashProgress | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [proof, setProof] = useState<ProofPackage | null>(null)
  const [processedVideoUrl, setProcessedVideoUrl] = useState<string>('')
  const [credentialSeed, setCredentialSeed] = useState<string>('')
  const [nullifierSeed, setNullifierSeed] = useState<string>('')
  const [isProofPreviewOpen, setIsProofPreviewOpen] = useState<boolean>(false)
  const [message, setMessage] = useState<string>('Upload evidence to begin.')
  const [registration, setRegistration] = useState<RegisterProofResult | null>(null)
  const [networkMismatch, setNetworkMismatch] = useState<string | null>(null)
  // Keep retries safe: a completed proof/wallet pair must never be submitted twice.
  const registrationInFlightedRef = useRef<boolean>(false)
  const completedRegistrationRef = useRef<string | null>(null)
  const pendingPersistenceRef = useRef<PendingRegistration | null>(null)

  // Sequence guard + abort plumbing so stale uploads/proofs cannot clobber a
  // newer flow or a reset caused by cancellation.
  const seqRef = useRef<number>(0)
  const abortRef = useRef<AbortController | null>(null)
  const proofClientRef = useRef<ProofWorkerClient | null>(null)
  const proofRequestIdRef = useRef<string | null>(null)
  const stageRef = useRef<Stage>('idle')
  const proveAbortRef = useRef<AbortController | null>(null)
  const evidenceFlowAbortRef = useRef<AbortController | null>(null)
  const cachedFileHashRef = useRef<{
    file: File
    name: string
    size: number
    lastModified: number
    digest: string
  } | null>(null)

  useEffect(() => {
    stageRef.current = stage
  }, [stage])

  useEffect(() => {
    return () => {
      // Cancel any in-flight evidence flow (hashing → embedding) on unmount.
      evidenceFlowAbortRef.current?.abort()
      evidenceFlowAbortRef.current = null
      proveAbortRef.current?.abort()
      proveAbortRef.current = null
      proofRequestIdRef.current = null
      proofClientRef.current?.destroy()
      proofClientRef.current = null
    }
  }, [])

  const selectedTierMeta = useMemo(
    () => TIERS.find((t) => t.id === selectedTier) ?? TIERS[0],
    [selectedTier],
  )

  const proofPreview = useMemo(
    () =>
      buildProofPreparationPreview({
        proof,
        tier: selectedTier,
        credentialSeed,
        nullifierSeed,
      }),
    [proof, selectedTier, credentialSeed, nullifierSeed],
  )

  const isCancellable = stage === 'hashing' || stage === 'embedding' || stage === 'proving'

  function openProofPreview() {
    setIsProofPreviewOpen(true)
  }

  function closeProofPreview() {
    setIsProofPreviewOpen(false)
  }

  function resetFlow() {
    abortRef.current?.abort()
    abortRef.current = null
    seqRef.current += 1
    if (proofRequestIdRef.current && proofClientRef.current) {
      proofClientRef.current.cancel(proofRequestIdRef.current)
    }
    proofRequestIdRef.current = null
    proofClientRef.current?.destroy()
    proofClientRef.current = null
    if (processedVideoUrl) URL.revokeObjectURL(processedVideoUrl)
    setProcessedVideoUrl('')
    setProof(null)
    setFile(null)
    setRegistration(null)
  }

  function getProofClient(): ProofWorkerClient {
    if (!proofClientRef.current) {
      proofClientRef.current = new ProofWorkerClient()
    }
    return proofClientRef.current
  }

  function cancelProving() {
    const requestId = proofRequestIdRef.current
    proveAbortRef.current?.abort()
    if (requestId && proofClientRef.current) {
      proofClientRef.current.cancel(requestId)
    }
    proofRequestIdRef.current = null
  }

  async function handleEvidence(nextFile: File | null) {
    if (!nextFile) return

    evidenceFlowAbortRef.current?.abort()
    const controller = new AbortController()
    evidenceFlowAbortRef.current = controller
    const isCurrentFlow = () =>
      evidenceFlowAbortRef.current === controller && !controller.signal.aborted

    setFile(nextFile)

    const cached = cachedFileHashRef.current
    const isCacheHit =
      cached !== null &&
      cached.file === nextFile &&
      cached.name === nextFile.name &&
      cached.size === nextFile.size &&
      cached.lastModified === nextFile.lastModified

    if (!isCacheHit) {
      cachedFileHashRef.current = null
      setHashProgress({
        processedBytes: 0,
        totalBytes: nextFile.size,
        percentage: nextFile.size === 0 ? 100 : 0,
      })
      setStage('hashing')
      setMessage('Hashing video locally in the browser: 0%.')
    } else {
      setHashProgress({
        processedBytes: nextFile.size,
        totalBytes: nextFile.size,
        percentage: 100,
      })
    }

    try {
      let sourceHash: string
      if (isCacheHit) {
        sourceHash = cached.digest
      } else {
        sourceHash = await hashFileInWorker(
          nextFile,
          (progress) => {
            if (!isCurrentFlow()) return
            setHashProgress(progress)
            setMessage(
              `Hashing video locally in the browser: ${progress.percentage}% (${progress.processedBytes.toLocaleString('en-US')} / ${progress.totalBytes.toLocaleString('en-US')} bytes).`,
            )
          },
          controller.signal,
        )
        if (!isCurrentFlow()) return
        cachedFileHashRef.current = {
          file: nextFile,
          name: nextFile.name,
          size: nextFile.size,
          lastModified: nextFile.lastModified,
          digest: sourceHash,
        }
      }

      const { sha256 } = await import('../utils')
      const proofId = await sha256(`${sourceHash}:${crypto.randomUUID()}`)
      const timestamp = new Date().toISOString()
      if (!isCurrentFlow()) return

      setStage('embedding')
      setMessage('Embedding portable Harpocrates metadata into the video.')

      const { embedVideo } = await import('../services/evidenceService')
      if (!isCurrentFlow()) return
      const { embeddedBlob, embeddedHash, metadataHash } = await embedVideo(
        nextFile,
        selectedTier,
        sourceHash,
        proofId,
        timestamp,
        controller.signal,
      )
      if (!isCurrentFlow()) return

      if (processedVideoUrl) URL.revokeObjectURL(processedVideoUrl)
      setProcessedVideoUrl(URL.createObjectURL(embeddedBlob))
      setProof({
        fileName: `harpocrates-${nextFile.name.replace(/[^.]+$/, '')}.mp4`,
        sourceHash,
        videoHash: embeddedHash,
        metadataHash,
        proofId,
        timestamp,
        tier: selectedTier,
      })
      setStage('ready')
      setMessage('Embedded evidence package is ready for Stellar registration.')
    } catch (error) {
      if (!isCurrentFlow()) return
      setStage('error')
      setMessage(error instanceof Error ? error.message : 'Evidence processing failed.')
    } finally {
      if (evidenceFlowAbortRef.current === controller) {
        evidenceFlowAbortRef.current = null
      }
    }
  }

  async function registerProof(wallet: string) {
    if (!proof) return

    if (!CONTRACT_ID) {
      setMessage('Set VITE_HARPOCRATES_REGISTRY_ID after deploying the Soroban contract.')
      return
    }

    if (!wallet) {
      setMessage('Connect Freighter before registering evidence.')
      return
    }

    try {
      const { getWalletNetwork, CONTRACT_NETWORK_PASSPHRASE } = await import('../stellar')
      const { checkNetworkMatch } = await import('../networkGuard')
      const walletPassphrase = await getWalletNetwork()
      const check = checkNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)
      if (!check.ok) {
        setNetworkMismatch(`${check.reason} ${check.remediation}`)
        setMessage(check.reason)
        return
      }
      setNetworkMismatch(null)
    } catch {
      setMessage('Could not verify wallet network before submitting. Reconnect Freighter and try again.')
      return
    }

    const registrationKey = `${proof.proofId}:${wallet}`
    if (completedRegistrationRef.current === registrationKey) {
      setMessage('This proof has already been submitted by this wallet.')
      return
    }
    const pendingPersistence = pendingPersistenceRef.current
    if (pendingPersistence) {
      if (pendingPersistence.key !== registrationKey) {
        setMessage('A completed registration still needs to be saved. Please retry it first.')
        return
      }
      if (registrationInFlightedRef.current) {
        setMessage('Registration is already in progress. Please wait for its result.')
        return
      }
      registrationInFlightedRef.current = true
      setMessage('Saving the completed Stellar registration.')
      try {
        const { persistRegistration } = await import('../services/evidenceService')
        await persistRegistration(pendingPersistence.proof, pendingPersistence.result, wallet)
        pendingPersistenceRef.current = null
        completedRegistrationRef.current = registrationKey
        setRegistration(pendingPersistence.result)
        setStage('registered')
        setMessage(`Registration submitted with Stellar status: ${pendingPersistence.result.status}.`)
      } catch (error) {
        setStage('error')
        setMessage(error instanceof Error ? error.message : 'Could not save the Stellar registration.')
      } finally {
        registrationInFlightedRef.current = false
      }
      return
    }
    if (registrationInFlightedRef.current) {
      setMessage('Registration is already in progress. Please wait for its result.')
      return
    }
    registrationInFlightedRef.current = true

    setMessage(`Submitting ${selectedTierMeta.title} proof to Stellar Testnet.`)

    const currentSeq = seqRef.current
    try {
      const proofForRegistration =
        selectedTier === 'silent' && !proof.silentWitness
          ? await attachSilentWitnessProof(proof, currentSeq, abortRef.current?.signal)
          : proof
      if (seqRef.current !== currentSeq) return

      const { registerProofOnStellar } = await import('../stellar')
      const result = await registerProofOnStellar({
        contractId: CONTRACT_ID,
        publicKey: wallet,
        tier: proofForRegistration.tier,
        videoHash: proofForRegistration.videoHash,
        metadataHash: proofForRegistration.metadataHash,
        proofId: proofForRegistration.proofId,
        silentWitness: proofForRegistration.silentWitness
          ? {
              publicInputs: proofForRegistration.silentWitness.publicInputs,
              proof: proofForRegistration.silentWitness.proof,
            }
          : undefined,
      })
      pendingPersistenceRef.current = {
        key: registrationKey,
        proof: proofForRegistration,
        result,
        wallet,
      }
      const { persistRegistration } = await import('../services/evidenceService')
      await persistRegistration(proofForRegistration, result, wallet)
      pendingPersistenceRef.current = null
      completedRegistrationRef.current = registrationKey
      setRegistration(result)
      setStage('registered')
      setMessage(`Registration submitted with Stellar status: ${result.status}.`)
    } catch (error) {
      setStage('error')
      setMessage(error instanceof Error ? error.message : 'Stellar registration failed.')
    } finally {
      registrationInFlightedRef.current = false
    }
  }

  async function attachSilentWitnessProof(
    baseProof: ProofPackage,
    seq: number,
    signal?: AbortSignal,
  ): Promise<ProofPackage> {
    const client = getProofClient()
    const controller = new AbortController()
    proveAbortRef.current = controller
    if (signal) {
      if (signal.aborted) {
        controller.abort()
      } else {
        signal.addEventListener('abort', () => controller.abort(), { once: true })
      }
    }
    setStage('proving')
    setMessage('Generating Silent Witness ZK proof locally.')

    let activeRequestId = ''
    try {
      const generated = client.generate(
        {
          videoHash: baseProof.videoHash,
          credentialSecret: credentialSeed,
          nullifierSecret: nullifierSeed,
          inputSchemaVersion: 1,
          verifierScope: '0',
          epoch: Math.floor(Date.now() / 86400000),
        },
        () => {
          if (seqRef.current !== seq) return
        },
        controller.signal,
      )
      activeRequestId = generated.requestId
      proofRequestIdRef.current = activeRequestId
      const silentWitness: SilentWitnessProof = await generated.result
      if (seqRef.current !== seq) throw new Error('Stale proof result ignored.')
      return { ...baseProof, silentWitness }
    } catch (error) {
      if (error instanceof ProofWorkerError && error.code === 'CANCELLED') {
        throw new Error('Proof generation cancelled.', { cause: error })
      }
      throw error
    } finally {
      if (activeRequestId && proofRequestIdRef.current === activeRequestId) {
        proofRequestIdRef.current = null
      }
      if (proveAbortRef.current === controller) {
        proveAbortRef.current = null
      }
    }
  }

  function cancelEvidence() {
    const currentStage = stageRef.current
    if (currentStage !== 'hashing' && currentStage !== 'embedding' && currentStage !== 'proving') {
      return
    }
    evidenceFlowAbortRef.current?.abort()
    evidenceFlowAbortRef.current = null
    if (currentStage === 'proving') {
      cancelProving()
    }
    resetFlow()
    setHashProgress(null)
    setStage('cancelled')
    setMessage(CANCELLED_MESSAGES[currentStage])
  }

  return {
    selectedTier,
    setSelectedTier,
    selectedTierMeta,
    stage,
    hashProgress,
    file,
    proof,
    processedVideoUrl,
    credentialSeed,
    setCredentialSeed,
    nullifierSeed,
    setNullifierSeed,
    proofPreview,
    isProofPreviewOpen,
    openProofPreview,
    closeProofPreview,
    message,
    registration,
    networkMismatch,
    isCancellable,
    handleEvidence,
    registerProof,
    cancelEvidence,
    cancelProving,
  }
}