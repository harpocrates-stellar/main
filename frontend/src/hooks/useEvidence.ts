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
import { ApiClientError } from '../services/apiError'
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

export type ReviewedFileIdentity = {
  name: string
  size: number
  lastModified: number
  mimeType: string
  fingerprint: string
}

export type RecoverableEvidenceFailure = {
  operation: 'embed' | 'persist'
  message: string
  reviewedFileIdentity: ReviewedFileIdentity
}

export function computeReviewedFileIdentity(file: File): ReviewedFileIdentity {
  const safeName = file.name.split(/[/\\]/).pop() ?? 'evidence.mp4'
  const mimeType = file.type || 'application/octet-stream'
  const raw = `${safeName}|${file.size}|${file.lastModified}|${mimeType}`
  let h = 0x811c9dc5
  for (let i = 0; i < raw.length; i += 1) {
    h ^= raw.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return {
    name: safeName,
    size: file.size,
    lastModified: file.lastModified,
    mimeType,
    fingerprint: `rf-${(h >>> 0).toString(16).padStart(8, '0')}`,
  }
}

function fileIdentitiesEqual(a: ReviewedFileIdentity, b: ReviewedFileIdentity): boolean {
  return (
    a.fingerprint === b.fingerprint &&
    a.name === b.name &&
    a.size === b.size &&
    a.lastModified === b.lastModified &&
    a.mimeType === b.mimeType
  )
}

function isRecoverableApiFailure(error: unknown): boolean {
  if (error instanceof ApiClientError) {
    return error.retryable || error.status >= 500 || error.status === 429 || error.status === 0
  }
  if (error instanceof TypeError) return true
  if (error instanceof Error) {
    return /timeout|temporar|unavailable|network|failed to fetch|rate limit|503|502|504/i.test(
      error.message,
    )
  }
  return false
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
  evidenceNotes?: string
  setEvidenceNotes?: (v: string) => void
  recoverableFailure?: RecoverableEvidenceFailure | null
  message: string
  registration: RegisterProofResult | null
  networkMismatch: string | null
  isCancellable: boolean
  handleEvidence: (nextFile: File | null) => Promise<void>
  registerProof: (wallet: string) => Promise<void>
  retryRecoverableEvidence?: (wallet?: string) => Promise<void>
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
  const [evidenceNotes, setEvidenceNotesState] = useState<string>('')
  const [recoverableFailure, setRecoverableFailure] = useState<RecoverableEvidenceFailure | null>(
    null,
  )
  const [message, setMessage] = useState<string>('Upload evidence to begin.')
  const [registration, setRegistration] = useState<RegisterProofResult | null>(null)
  const [networkMismatch, setNetworkMismatch] = useState<string | null>(null)
  // Keep retries safe: a completed proof/wallet pair must never be submitted twice.
  const registrationInFlightedRef = useRef<boolean>(false)
  const completedRegistrationRef = useRef<string | null>(null)
  const pendingPersistenceRef = useRef<PendingRegistration | null>(null)
  const evidenceNotesRef = useRef<string>('')
  const notesRevisionRef = useRef<number>(0)
  const fileRef = useRef<File | null>(null)
  const recoverableFailureRef = useRef<RecoverableEvidenceFailure | null>(null)

  function updateFile(next: File | null) {
    fileRef.current = next
    setFile(next)
  }

  function updateRecoverableFailure(next: RecoverableEvidenceFailure | null) {
    recoverableFailureRef.current = next
    setRecoverableFailure(next)
  }

  function setEvidenceNotes(next: string) {
    notesRevisionRef.current += 1
    evidenceNotesRef.current = next
    setEvidenceNotesState(next)
  }

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

  const isCancellable = stage === 'hashing' || stage === 'embedding' || stage === 'proving'

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
    updateFile(null)
    updateRecoverableFailure(null)
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

    const nextIdentity = computeReviewedFileIdentity(nextFile)
    if (
      recoverableFailureRef.current &&
      !fileIdentitiesEqual(recoverableFailureRef.current.reviewedFileIdentity, nextIdentity)
    ) {
      updateRecoverableFailure(null)
    }

    const requestNotesRevision = notesRevisionRef.current
    const requestNotesSnapshot = evidenceNotesRef.current
    updateFile(nextFile)

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
      const embedOutcome =
        requestNotesSnapshot.trim().length > 0
          ? await embedVideo(
              nextFile,
              selectedTier,
              sourceHash,
              proofId,
              timestamp,
              controller.signal,
              requestNotesSnapshot,
            )
          : await embedVideo(
              nextFile,
              selectedTier,
              sourceHash,
              proofId,
              timestamp,
              controller.signal,
            )
      const { embeddedBlob, embeddedHash, metadataHash, serverNotes } = embedOutcome
      if (!isCurrentFlow()) return

      // Never overwrite user-entered or locally edited notes with stale server results.
      if (
        typeof serverNotes === 'string' &&
        notesRevisionRef.current === requestNotesRevision &&
        evidenceNotesRef.current.length === 0
      ) {
        evidenceNotesRef.current = serverNotes
        setEvidenceNotesState(serverNotes)
      }

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
      updateRecoverableFailure(null)
      setStage('ready')
      setMessage('Embedded evidence package is ready for Stellar registration.')
    } catch (error) {
      if (!isCurrentFlow()) return
      const errMsg = error instanceof Error ? error.message : 'Evidence processing failed.'
      if (isRecoverableApiFailure(error)) {
        updateRecoverableFailure({
          operation: 'embed',
          message: errMsg,
          reviewedFileIdentity: nextIdentity,
        })
      } else {
        updateRecoverableFailure(null)
      }
      setStage('error')
      setMessage(errMsg)
    } finally {
      if (evidenceFlowAbortRef.current === controller) {
        evidenceFlowAbortRef.current = null
      }
    }
  }

  async function retryRecoverableEvidence(wallet?: string): Promise<void> {
    const activeFailure = recoverableFailureRef.current
    if (!activeFailure) return
    const currentFile = fileRef.current
    if (
      !currentFile ||
      !fileIdentitiesEqual(
        computeReviewedFileIdentity(currentFile),
        activeFailure.reviewedFileIdentity,
      )
    ) {
      updateRecoverableFailure(null)
      setStage('error')
      setMessage(
        'Reviewed file identity changed since the failure. Re-select and review the file before retrying.',
      )
      return
    }
    if (activeFailure.operation === 'embed') {
      await handleEvidence(currentFile)
    } else {
      await registerProof(wallet ?? '')
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
        updateRecoverableFailure(null)
        setRegistration(pendingPersistence.result)
        setStage('registered')
        setMessage(`Registration submitted with Stellar status: ${pendingPersistence.result.status}.`)
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Could not save the Stellar registration.'
        if (fileRef.current && isRecoverableApiFailure(error)) {
          updateRecoverableFailure({
            operation: 'persist',
            message: errMsg,
            reviewedFileIdentity: computeReviewedFileIdentity(fileRef.current),
          })
        }
        setStage('error')
        setMessage(errMsg)
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
      updateRecoverableFailure(null)
      setRegistration(result)
      setStage('registered')
      setMessage(`Registration submitted with Stellar status: ${result.status}.`)
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Stellar registration failed.'
      if (pendingPersistenceRef.current && fileRef.current && isRecoverableApiFailure(error)) {
        updateRecoverableFailure({
          operation: 'persist',
          message: errMsg,
          reviewedFileIdentity: computeReviewedFileIdentity(fileRef.current),
        })
      }
      setStage('error')
      setMessage(errMsg)
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
    evidenceNotes,
    setEvidenceNotes,
    recoverableFailure,
    message,
    registration,
    networkMismatch,
    isCancellable,
    handleEvidence,
    registerProof,
    retryRecoverableEvidence,
    cancelEvidence,
    cancelProving,
  }
}