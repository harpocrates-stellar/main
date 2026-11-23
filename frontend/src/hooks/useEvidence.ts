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

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Building2, Fingerprint, KeyRound } from 'lucide-react'
import type {
  IdentityTier,
  ProofPackage,
  SilentWitnessProof,
  Stage,
  UploadAdmissionState,
  UploadErrorKind,
} from '../types'
import type { RegisterProofResult } from '../stellarTypes'
import type { HashProgress } from '../utils'
import {
  ProofWorkerClient,
  ProofWorkerError,
} from '../workers/proofWorkerClient'
import { hashFileInWorker } from '../workers/fileHashWorkerClient'
import { appConfig } from '../config'
import {
  buildProofPreparationPreview,
  PROOF_PREPARATION_VERIFIER_SCOPE,
  type ProofPreparationPreviewResult,
} from '../proofPreparationPreview'
import {
  classifyInterruptedSession,
  type InterruptedUploadSession,
} from '../interruptedUpload'

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
  },
]

const CONTRACT_ID = appConfig.harpocratesRegistryId

// Privacy-safe stable copy — never includes file names, hashes, or secrets.
export const EVIDENCE_REPLACED_MESSAGE =
  'Evidence file replaced. Previous proof, registration, and verification state were cleared; verify or register the newly selected file.'

const CANCELLED_MESSAGES: Record<Stage, string> = {
  idle: 'Request cancelled.',
  hashing: 'Upload cancelled.',
  embedding: 'Upload cancelled.',
  proving: 'Proof generation cancelled.',
  ready: 'Request cancelled.',
  registered: 'Request cancelled.',
  error: 'Request cancelled.',
  cancelled: 'Request cancelled.',
}

export type EvidenceReviewSnapshot = {
  /** Selected identity tier being registered. */
  tier: IdentityTier
  /** Human-readable tier title (e.g. "Silent Witness"). */
  tierTitle: string
  /** Human-readable tier label (e.g. "Anonymous Credential"). */
  tierLabel: string
  /** Canonical SHA-256 hex digest of the public registration statement. */
  statementDigest: string
  /** Human-readable Stellar network name (e.g. "Testnet"). */
  networkName: string
  /** Canonical Stellar network passphrase. */
  networkPassphrase: string
  /** Proof identifiers bound to this review snapshot. */
  proofId: string
  videoHash: string
  metadataHash: string
  sourceHash: string
}

/**
 * Compute a canonical, privacy-safe SHA-256 digest of the public registration
 * statement. Private seeds, witness proofs, and raw media are never included.
 */
export async function computeStatementDigest(input: {
  tier: IdentityTier
  videoHash: string
  metadataHash: string
  proofId: string
  networkPassphrase: string
}): Promise<string> {
  const { sha256 } = await import('../utils')
  const canonical = JSON.stringify({
    schema: 'harpocrates.evidence-review.v1',
    tier: input.tier,
    videoHash: input.videoHash,
    metadataHash: input.metadataHash,
    proofId: input.proofId,
    network: input.networkPassphrase,
  })
  return sha256(canonical)
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
  /** Original user-entered notes associated with this evidence. */
  evidenceNotes: string
  /** Update user-entered notes without clobbering by stale server responses. */
  setEvidenceNotes: (notes: string) => void
  message: string
  /** Read-only preview of the canonical proof inputs and policy version. */
  proofPreparation: ProofPreparationPreviewResult
  /** Sensitive export field keys explicitly acknowledged by the operator in this session. */
  acknowledgedSensitiveFields: string[]
  /** Record explicit operator acknowledgement for newly exposed sensitive export fields. */
  acknowledgeSensitiveFields: (keys: string[]) => void
  registration: RegisterProofResult | null
  networkMismatch: string | null
  /** Guided recovery state when the wallet network does not match the required contract network. */
  networkMismatchRecovery: NetworkMismatchRecoveryState | null
  isCancellable: boolean
  /** Active pre-registration review snapshot, or null when closed/invalidated. */
  review: EvidenceReviewSnapshot | null
  /** Privacy-safe reason explaining why a previously opened review was invalidated. */
  reviewInvalidatedReason: string | null
  openReview: () => Promise<void>
  closeReview: () => void
  handleEvidence: (nextFile: File | null) => Promise<void>
  /** Retry evidence processing tied to the reviewed file identity. */
  retryEvidence: () => Promise<void>
  registerProof: (wallet: string) => Promise<void>
  /** Re-validate the wallet network and selected evidence intent before allowing registration to resume. */
  revalidateNetworkMismatch: (wallet: string) => Promise<boolean>
  cancelEvidence: () => void
  /** Cancel an in-flight Silent Witness proof generation (no-op if idle). */
  cancelProving: () => void
  /**
   * Classification of the most-recently interrupted upload session.
   * `category === 'none'` means there is no interrupted session to show.
   */
  interruptedSession: InterruptedUploadSession
  /**
   * Re-submit the interrupted file through the full evidence pipeline.
   * No-op when `interruptedSession.category !== 'resumable'`.
   */
  resumeEvidence: () => Promise<void>
  /**
   * Clear the interrupted session without retrying.
   * Resets stage back to `'idle'` and forgets the interrupted file.
   */
  discardEvidence: () => void
}

type PendingRegistration = {
  key: string
  proof: ProofPackage
  result: RegisterProofResult
  wallet: string
}

type ReviewFingerprint = {
  file: File | null
  proofId: string
  tier: IdentityTier
  credentialSeed: string
  nullifierSeed: string
}

export function useEvidence(): UseEvidenceReturn {
  const [selectedTier, setSelectedTierState] = useState<IdentityTier>('silent')
  const [stage, setStage] = useState<Stage>('idle')
  const [hashProgress, setHashProgress] = useState<HashProgress | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [proof, setProof] = useState<ProofPackage | null>(null)
  const [processedVideoUrl, setProcessedVideoUrl] = useState<string>('')
  const [credentialSeed, setCredentialSeedState] = useState<string>('')
  const [nullifierSeed, setNullifierSeedState] = useState<string>('')
  const [message, setMessage] = useState<string>('Upload evidence to begin.')
  const [evidenceNotes, setEvidenceNotesState] = useState<string>('')
  const evidenceNotesRef = useRef<string>('')
  const notesEditSeqRef = useRef<number>(0)
  const reviewedFileRef = useRef<{
    file: File
    name: string
    size: number
    lastModified: number
  } | null>(null)
  const [registration, setRegistration] = useState<RegisterProofResult | null>(null)
  const [networkMismatch, setNetworkMismatch] = useState<string | null>(null)
  const [review, setReview] = useState<EvidenceReviewSnapshot | null>(null)
  const [reviewInvalidatedReason, setReviewInvalidatedReason] = useState<string | null>(null)
  // Keep retries safe: a completed proof/wallet pair must never be submitted twice.
  const registrationInFlightedRef = useRef<boolean>(false)
  const completedRegistrationRef = useRef<string | null>(null)
  const pendingPersistenceRef = useRef<PendingRegistration | null>(null)
  const processedVideoUrlRef = useRef<string>('')
  const hasSelectedEvidenceRef = useRef<boolean>(false)

  // Review state refs for synchronous invalidation and fail-closed registration checks.
  const reviewRef = useRef<EvidenceReviewSnapshot | null>(null)
  const reviewFingerprintRef = useRef<ReviewFingerprint | null>(null)
  const reviewSeqRef = useRef<number>(0)

  // Sequence guard + abort plumbing so stale uploads/proofs cannot clobber a
  // newer flow or a reset caused by cancellation.
  const seqRef = useRef<number>(0)
  const abortRef = useRef<AbortController | null>(null)
  const proofClientRef = useRef<ProofWorkerClient | null>(null)
  const proofRequestIdRef = useRef<string | null>(null)
  const stageRef = useRef<Stage>('idle')
  const proofRef = useRef<ProofPackage | null>(null)
  const selectedTierRef = useRef<IdentityTier>('silent')
  const proveAbortRef = useRef<AbortController | null>(null)
  const evidenceFlowAbortRef = useRef<AbortController | null>(null)
  const cachedFileHashRef = useRef<{
    file: File
    name: string
    size: number
    lastModified: number
    digest: string
  } | null>(null)

  // Interrupted-upload recovery: track the file and timestamp of the most
  // recently interrupted session so the RecoveryBanner can classify it.
  // Stored in state (not refs) so that updates trigger a re-render of the banner.
  const [interruptedFile, setInterruptedFile] = useState<File | null>(null)
  const [interruptedAt, setInterruptedAt] = useState<number | null>(null)

  useEffect(() => {
    stageRef.current = stage
  }, [stage])

  useEffect(() => {
    proofRef.current = proof
  }, [proof])

  useEffect(() => {
    selectedTierRef.current = selectedTier
  }, [selectedTier])

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

  // Read-only: derived from the evidence package and the proving policy alone.
  // It never touches seeds, loads a circuit, or submits anything.
  const proofPreparation = useMemo(
    () =>
      buildProofPreparationPreview({
        proof,
        tier: selectedTier,
        verifierScope: PROOF_PREPARATION_VERIFIER_SCOPE,
        epoch: silentWitnessEpoch(),
      }),
    [proof, selectedTier],
  )

  const isCancellable = stage === 'hashing' || stage === 'embedding' || stage === 'proving'

  function clearReviewState() {
    reviewSeqRef.current += 1
    reviewRef.current = null
    reviewFingerprintRef.current = null
    setReview(null)
    setReviewInvalidatedReason(null)
  }

  function invalidateReview(reason: string) {
    reviewSeqRef.current += 1
    const hadActiveReview = reviewRef.current !== null
    reviewRef.current = null
    reviewFingerprintRef.current = null
    setReview(null)
    if (hadActiveReview) {
      setReviewInvalidatedReason(reason)
      setMessage(reason)
    }
  }

  function setSelectedTier(nextTier: IdentityTier) {
    if (nextTier === selectedTier) return
    setSelectedTierState(nextTier)
    invalidateReview(
      'Review invalidated because the identity tier changed. Review again before registering.',
    )
  }

  function setCredentialSeed(value: string) {
    if (value === credentialSeed) return
    setCredentialSeedState(value)
    invalidateReview(
      'Review invalidated because proof parameters changed. Review again before registering.',
    )
  }

  function setNullifierSeed(value: string) {
    if (value === nullifierSeed) return
    setNullifierSeedState(value)
    invalidateReview(
      'Review invalidated because proof parameters changed. Review again before registering.',
    )
  }

  async function openReview() {
    if (!proof || isCancellable) return
    const reviewSeq = ++reviewSeqRef.current
    const fingerprint: ReviewFingerprint = {
      file,
      proofId: proof.proofId,
      tier: selectedTier,
      credentialSeed,
      nullifierSeed,
    }
    const { CONTRACT_NETWORK_PASSPHRASE } = await import('../stellar')
    const { networkName } = await import('../networkGuard')
    const statementDigest = await computeStatementDigest({
      tier: selectedTier,
      videoHash: proof.videoHash,
      metadataHash: proof.metadataHash,
      proofId: proof.proofId,
      networkPassphrase: CONTRACT_NETWORK_PASSPHRASE,
    })
    if (reviewSeqRef.current !== reviewSeq) return
    const snapshot: EvidenceReviewSnapshot = {
      tier: selectedTier,
      tierTitle: selectedTierMeta.title,
      tierLabel: selectedTierMeta.label,
      statementDigest,
      networkName: networkName(CONTRACT_NETWORK_PASSPHRASE),
      networkPassphrase: CONTRACT_NETWORK_PASSPHRASE,
      proofId: proof.proofId,
      videoHash: proof.videoHash,
      metadataHash: proof.metadataHash,
      sourceHash: proof.sourceHash,
    }
    reviewRef.current = snapshot
    reviewFingerprintRef.current = fingerprint
    setReview(snapshot)
    setReviewInvalidatedReason(null)
    setMessage('Review the evidence details below before registering on Stellar.')
  }

  function closeReview() {
    clearReviewState()
  }

  function resetFlow() {
    clearReviewState()
    abortRef.current?.abort()
    abortRef.current = null
    seqRef.current += 1
    if (proofRequestIdRef.current && proofClientRef.current) {
      proofClientRef.current.cancel(proofRequestIdRef.current)
    }
    proofRequestIdRef.current = null
    proofClientRef.current?.destroy()
    proofClientRef.current = null
    pendingPersistenceRef.current = null
    hasSelectedEvidenceRef.current = false
    clearProcessedVideoUrl()
    setProof(null)
    setFile(null)
    setRegistration(null)
    setAdmissionState(null)
    setUploadErrorKind('none')
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

  const setEvidenceNotes = useCallback((notes: string) => {
    notesEditSeqRef.current += 1
    evidenceNotesRef.current = notes
    setEvidenceNotesState(notes)
  }, [])

  async function handleEvidence(nextFile: File | null) {
    if (!nextFile) return

    if (reviewRef.current !== null) {
      invalidateReview(
        'Review invalidated because the source file changed. Review again before registering.',
      )
    } else {
      clearReviewState()
    }

    evidenceFlowAbortRef.current?.abort()
    const controller = new AbortController()
    evidenceFlowAbortRef.current = controller
    const isCurrentFlow = () =>
      evidenceFlowAbortRef.current === controller && !controller.signal.aborted

    // Clear stale proof, download URL, and registration state before processing
    // the replacement file so previous evidence state can never leak onto it.
    cancelProving()
    seqRef.current += 1
    pendingPersistenceRef.current = null
    clearProcessedVideoUrl()
    setProof(null)
    setRegistration(null)
    hasSelectedEvidenceRef.current = true
    setEvidenceChangeNotice(hadPriorEvidence ? EVIDENCE_REPLACED_MESSAGE : null)
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
            if (progress.percentage !== lastAnnouncedPercentageRef.current) {
              setMessage(`Hashing video locally in the browser: ${progress.percentage}% (${progress.processedBytes.toLocaleString()} / ${progress.totalBytes.toLocaleString()} bytes).`);
              lastAnnouncedPercentageRef.current = progress.percentage;
            }
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

      clearProcessedVideoUrl()
      const nextUrl = URL.createObjectURL(embeddedBlob)
      processedVideoUrlRef.current = nextUrl
      setProcessedVideoUrl(nextUrl)
      setProof({
        fileName: `harpocrates-${nextFile.name.replace(/[^.]+$/, '')}.mp4`,
        sourceHash,
        videoHash: embeddedHash,
        metadataHash,
        proofId,
        timestamp,
        tier: selectedTier,
        evidenceNotes: evidenceNotesRef.current || undefined,
      })
      setAdmissionState({
        status: 'admitted',
        reason: null,
        message: 'Upload admitted and processed successfully.',
        retryAfter: null,
        retryable: false,
        actionHint: 'none',
      })
      setUploadErrorKind('none')
      setStage('ready')
      setMessage('Embedded evidence package is ready for Stellar registration.')
    } catch (error) {
      if (!isCurrentFlow()) return
      // Capture the interrupted file so the recovery banner can classify the
      // session even when the interruption came from an error rather than
      // explicit cancellation.
      setInterruptedFile(nextFile)
      setInterruptedAt(Date.now())
      setStage('error')
      const errorMessage = error instanceof Error ? error.message : 'Evidence processing failed.'
      setMessage(errorMessage)

      if (isAdmissionError(error)) {
        const admissionReason = toAdmissionReason(error)
        const retryAfter = error instanceof ApiClientError ? error.retryAfter : null
        const actionHint =
          error instanceof ApiClientError ? (error.action as UploadAdmissionState['actionHint']) : 'retry'
        setUploadErrorKind('admission_rejected')
        setAdmissionState({
          status: 'rejected',
          reason: admissionReason,
          message: errorMessage,
          retryAfter,
          retryable: true,
          actionHint: actionHint ?? 'retry',
        })
      } else if (isInvalidEvidenceError(error)) {
        setUploadErrorKind('invalid_evidence')
        setAdmissionState(null)
      } else {
        setUploadErrorKind('unknown')
        setAdmissionState(null)
      }
    } finally {
      if (evidenceFlowAbortRef.current === controller) {
        evidenceFlowAbortRef.current = null
      }
    }
  }

  async function retryEvidence() {
    const reviewed = reviewedFileRef.current
    if (!reviewed || !reviewed.file) {
      return
    }
    // Keep the retry action strictly tied to the reviewed file identity
    if (
      file &&
      (file.name !== reviewed.name ||
        file.size !== reviewed.size ||
        file.lastModified !== reviewed.lastModified)
    ) {
      return
    }
    await handleEvidence(reviewed.file)
  }

  async function registerProof(wallet: string) {
    if (!proof) return

    const activeReview = reviewRef.current
    const fingerprint = reviewFingerprintRef.current
    const reviewMatchesCurrentState =
      activeReview !== null &&
      fingerprint !== null &&
      fingerprint.file === file &&
      fingerprint.proofId === proof.proofId &&
      fingerprint.tier === selectedTier &&
      fingerprint.credentialSeed === credentialSeed &&
      fingerprint.nullifierSeed === nullifierSeed

    if (!reviewMatchesCurrentState) {
      if (activeReview !== null) {
        invalidateReview(
          'Review invalidated because the source file or proof parameters changed. Review again before registering.',
        )
      } else {
        setMessage(
          reviewInvalidatedReason ?? 'Review the evidence package before registering.',
        )
      }
      return
    }

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
      const { checkNetworkMatch, networkName } = await import('../networkGuard')
      const walletPassphrase = await getWalletNetwork()
      const check = checkNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)
      if (!check.ok) {
        const requiredNetwork = networkName(CONTRACT_NETWORK_PASSPHRASE)
        const trimmedWallet = (walletPassphrase ?? '').trim()
        const currentWalletNetwork = trimmedWallet ? networkName(trimmedWallet) : 'Unavailable'
        setNetworkMismatch(`${check.reason} ${check.remediation}`)
        setNetworkMismatchRecovery({
          requiredNetwork,
          currentWalletNetwork,
          reason: check.reason,
          remediation: check.remediation,
          isValidating: false,
          intent: {
            proofId: proof.proofId,
            tier: selectedTier,
            videoHash: proof.videoHash,
          },
          validationError: null,
        })
        setMessage(check.reason)
        return
      }
      setNetworkMismatch(null)
      setNetworkMismatchRecovery(null)
    } catch {
      const { CONTRACT_NETWORK_PASSPHRASE } = await import('../stellar')
      const { networkName } = await import('../networkGuard')
      const requiredNetwork = networkName(CONTRACT_NETWORK_PASSPHRASE)
      const reason = 'Could not verify wallet network before submitting.'
      const remediation = `Reconnect Freighter on ${requiredNetwork}, then re-validate to resume.`
      setNetworkMismatch(`${reason} ${remediation}`)
      setNetworkMismatchRecovery({
        requiredNetwork,
        currentWalletNetwork: 'Unavailable',
        reason,
        remediation,
        isValidating: false,
        intent: {
          proofId: proof.proofId,
          tier: selectedTier,
          videoHash: proof.videoHash,
        },
        validationError: null,
      })
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
        setEvidenceChangeNotice(null)
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

    try {
      const proofForRegistration =
        selectedTier === 'silent' && !proof.silentWitness
          ? await attachSilentWitnessProof(proof, seqRef.current, abortRef.current?.signal)
          : proof
      if (seqRef.current !== seqRef.current) return

      const { registerProofOnStellar } = await import('../stellar')
      const result = await registerProofOnStellar({
        contractId: CONTRACT_ID,
        publicKey: wallet,
        proof: proofForRegistration,
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
      clearReviewState()
      setRegistration(result)
      setEvidenceChangeNotice(null)
      setStage('registered')
      setMessage(`Registration submitted with Stellar status: ${result.status}.`)
    } catch (error) {
      setStage('error')
      setMessage(error instanceof Error ? error.message : 'Stellar registration failed.')
    } finally {
      registrationInFlightedRef.current = false
    }
  }

  async function revalidateNetworkMismatch(wallet: string): Promise<boolean> {
    const activeProof = proofRef.current ?? proof
    const activeTier = selectedTierRef.current
    const seq = seqRef.current

    if (!wallet) {
      const validationError = 'Connect Freighter on the required network before resuming.'
      setNetworkMismatchRecovery((prev) =>
        prev ? { ...prev, isValidating: false, validationError } : prev,
      )
      setMessage(validationError)
      return false
    }

    if (!activeProof) {
      const validationError = 'Select and prepare an evidence file before resuming.'
      setNetworkMismatchRecovery((prev) =>
        prev ? { ...prev, isValidating: false, validationError } : prev,
      )
      setMessage(validationError)
      return false
    }

    if (activeProof.tier !== activeTier) {
      const validationError =
        'Selected identity tier changed since evidence preparation. Re-upload or switch back to the prepared tier before resuming.'
      setNetworkMismatchRecovery((prev) =>
        prev ? { ...prev, isValidating: false, validationError } : prev,
      )
      setMessage(validationError)
      return false
    }

    if (!CONTRACT_ID) {
      const validationError = 'Set VITE_HARPOCRATES_REGISTRY_ID after deploying the Soroban contract.'
      setNetworkMismatchRecovery((prev) =>
        prev ? { ...prev, isValidating: false, validationError } : prev,
      )
      setMessage(validationError)
      return false
    }

    setNetworkMismatchRecovery((prev) =>
      prev ? { ...prev, isValidating: true, validationError: null } : prev,
    )

    try {
      const { getWalletNetwork, CONTRACT_NETWORK_PASSPHRASE } = await import('../stellar')
      const { checkNetworkMatch, networkName } = await import('../networkGuard')
      const walletPassphrase = await getWalletNetwork()

      // Fail closed if the selected evidence intent changed while validation was in flight.
      const latestProof = proofRef.current
      if (
        seqRef.current !== seq ||
        !latestProof ||
        latestProof.proofId !== activeProof.proofId ||
        latestProof.videoHash !== activeProof.videoHash ||
        selectedTierRef.current !== activeTier
      ) {
        const validationError =
          'Selected evidence intent changed during network validation. Re-validate before resuming.'
        setNetworkMismatchRecovery((prev) =>
          prev ? { ...prev, isValidating: false, validationError } : prev,
        )
        setMessage(validationError)
        return false
      }

      const requiredNetwork = networkName(CONTRACT_NETWORK_PASSPHRASE)
      const trimmedWallet = (walletPassphrase ?? '').trim()
      const currentWalletNetwork = trimmedWallet ? networkName(trimmedWallet) : 'Unavailable'
      const check = checkNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)

      if (!check.ok) {
        setNetworkMismatch(`${check.reason} ${check.remediation}`)
        setNetworkMismatchRecovery({
          requiredNetwork,
          currentWalletNetwork,
          reason: check.reason,
          remediation: check.remediation,
          isValidating: false,
          intent: {
            proofId: activeProof.proofId,
            tier: activeTier,
            videoHash: activeProof.videoHash,
          },
          validationError: check.reason,
        })
        setMessage(check.reason)
        return false
      }

      setNetworkMismatch(null)
      setNetworkMismatchRecovery(null)
      setMessage(`Network validated on ${requiredNetwork}. Ready to resume registration.`)
      return true
    } catch {
      const validationError =
        'Could not verify wallet network. Unlock or reconnect Freighter and re-validate.'
      setNetworkMismatchRecovery((prev) =>
        prev
          ? {
              ...prev,
              currentWalletNetwork: 'Unavailable',
              isValidating: false,
              validationError,
            }
          : prev,
      )
      setMessage(validationError)
      return false
    }
  }

  async function attachSilentWitnessProof(
    baseProof: ProofPackage,
    seq: number,
    signal?: AbortSignal,
  ): Promise<ProofPackage> {
    const client = getProofClient()
    const requestId = crypto.randomUUID()
    proofRequestIdRef.current = requestId
    const controller = new AbortController()
    proveAbortRef.current = controller
    if (signal) {
      if (signal.aborted) controller.abort()
      else signal.addEventListener('abort', () => controller.abort())
    }

    setStage('proving')
    setMessage('Generating Silent Witness ZK proof locally.')

    try {
      const silentWitness: SilentWitnessProof = await client.generateProof({
        requestId,
        videoHash: baseProof.videoHash,
        credentialSecret: credentialSeed,
        nullifierSecret: nullifierSeed,
        inputSchemaVersion: CIRCUIT_INPUT_SCHEMA_VERSION,
        verifierScope: PROOF_PREPARATION_VERIFIER_SCOPE,
        epoch: silentWitnessEpoch(),
        signal: controller.signal,
        onProgress: () => {
          if (seqRef.current !== seq) return
        },
      })
      if (seqRef.current !== seq) throw new Error('Stale proof result ignored.')
      return { ...baseProof, silentWitness }
    } catch (error) {
      if (error instanceof ProofWorkerError && error.code === 'CANCELLED') {
        throw new Error('Proof generation cancelled.', { cause: error })
      }
      throw error
    } finally {
      if (proofRequestIdRef.current === requestId) {
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
    // Capture the interrupted file and timestamp before resetting state so the
    // recovery banner can classify the session after the user navigates away
    // and returns to the studio.
    setInterruptedFile(file)
    setInterruptedAt(Date.now())
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

  // ---------------------------------------------------------------------------
  // Interrupted-upload recovery
  // ---------------------------------------------------------------------------

  // Classify the current session on every render so the RecoveryBanner always
  // reflects the latest state without needing a separate subscription.
  const interruptedSession: InterruptedUploadSession = useMemo(
    () =>
      classifyInterruptedSession({
        stage,
        currentFile: file,
        interruptedFile,
        interruptedAt,
        errorMessage: stage === 'error' ? message : null,
      }),
    [stage, file, interruptedFile, interruptedAt, message],
  )

  /**
   * Re-submit the interrupted file through the full evidence pipeline.
   *
   * Guards:
   * - Only acts when the session is classified as 'resumable'.
   * - Prevents automatic retry when the user has picked a different source
   *   file (source-changed guard is enforced by classifyInterruptedSession).
   */
  async function resumeEvidence(): Promise<void> {
    if (interruptedSession.category !== 'resumable') return
    const fileToResume = interruptedFile
    if (!fileToResume) return
    // Clear the interrupted session before starting so a new interruption
    // during the resumed flow is tracked fresh.
    setInterruptedFile(null)
    setInterruptedAt(null)
    await handleEvidence(fileToResume)
  }

  /**
   * Clear the interrupted session and return to 'idle' without retrying.
   */
  function discardEvidence(): void {
    setInterruptedFile(null)
    setInterruptedAt(null)
    resetFlow()
    setHashProgress(null)
    setStage('idle')
    setMessage('Upload evidence to begin.')
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
    message,
    proofPreparation,
    acknowledgedSensitiveFields,
    acknowledgeSensitiveFields,
    registration,
    networkMismatch,
    networkMismatchRecovery,
    isCancellable,
    review,
    reviewInvalidatedReason,
    openReview,
    closeReview,
    handleEvidence,
    retryEvidence,
    registerProof,
    revalidateNetworkMismatch,
    cancelEvidence,
    cancelProving,
    interruptedSession,
    resumeEvidence,
    discardEvidence,
  }
}
