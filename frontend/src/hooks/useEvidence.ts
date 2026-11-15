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

/** Bounded percentage interval for screen-reader live-region progress milestones. */
export const PROGRESS_ANNOUNCEMENT_STEP_PERCENT = 25

/**
 * Normalizes a progress percentage to `[0, 100]` and buckets it down to the
 * nearest bounded milestone (default: 0, 25, 50, 75, 100).
 */
export function computeBoundedProgressMilestone(
  percentage: number,
  stepPercent: number = PROGRESS_ANNOUNCEMENT_STEP_PERCENT,
): number {
  const safeStep = Number.isFinite(stepPercent) && stepPercent > 0 ? Math.floor(stepPercent) : 25
  const clamped = Number.isFinite(percentage) ? Math.max(0, Math.min(100, Math.floor(percentage))) : 0
  if (clamped >= 100) return 100
  return Math.floor(clamped / safeStep) * safeStep
}

function sanitizeStudioAnnouncement(raw: string): string {
  return raw
    .replace(/\b[GC][A-Z2-7]{55}\b/g, '[address]')
    .replace(/\b[0-9a-f]{9,}\b/gi, '[redacted]')
    .replace(/(\/[\w.-]+){2,}/g, '[path]')
    .replace(/[A-Za-z]:\\[\S]+/g, '[path]')
    .trim()
}

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

export type TerminalAnnouncementKind = 'success' | 'cancelled' | 'failure'

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
  message: string
  /** Bounded, deduplicated, privacy-safe message for ARIA live regions. */
  liveAnnouncement?: string
  /** Ordered log of emitted live-region announcements within the active operation. */
  announcementHistory?: ReadonlyArray<string>
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
  const [message, setMessage] = useState<string>('Upload evidence to begin.')
  const [liveAnnouncement, setLiveAnnouncement] = useState<string>('')
  const [announcementHistory, setAnnouncementHistory] = useState<string[]>([])
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
  const liveAnnouncementRef = useRef<string>('')
  const announcementHistoryRef = useRef<string[]>([])
  const announcementTrackerRef = useRef<{
    lastPercentage: number | null
    lastMilestone: number | null
    terminalOutcome: TerminalAnnouncementKind | null
  }>({
    lastPercentage: null,
    lastMilestone: null,
    terminalOutcome: null,
  })
  const cachedFileHashRef = useRef<{
    file: File
    name: string
    size: number
    lastModified: number
    digest: string
  } | null>(null)

  function updateStage(next: Stage) {
    stageRef.current = next
    setStage(next)
  }

  function resetOperationAnnouncements() {
    announcementTrackerRef.current = {
      lastPercentage: null,
      lastMilestone: null,
      terminalOutcome: null,
    }
    announcementHistoryRef.current = []
    setAnnouncementHistory([])
  }

  function emitAnnouncement(raw: string, terminal?: TerminalAnnouncementKind) {
    const tracker = announcementTrackerRef.current
    if (terminal !== undefined) {
      if (tracker.terminalOutcome !== null) return
      tracker.terminalOutcome = terminal
    } else if (tracker.terminalOutcome !== null) {
      return
    }
    const sanitized = sanitizeStudioAnnouncement(raw)
    if (!sanitized || sanitized === liveAnnouncementRef.current) return
    liveAnnouncementRef.current = sanitized
    setLiveAnnouncement(sanitized)
    const nextHistory = [...announcementHistoryRef.current, sanitized].slice(-24)
    announcementHistoryRef.current = nextHistory
    setAnnouncementHistory(nextHistory)
  }

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

    resetOperationAnnouncements()
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
      const initialPct = nextFile.size === 0 ? 100 : 0
      setHashProgress({
        processedBytes: 0,
        totalBytes: nextFile.size,
        percentage: initialPct,
      })
      updateStage('hashing')
      setMessage('Hashing video locally in the browser: 0%.')
      announcementTrackerRef.current.lastPercentage = initialPct
      announcementTrackerRef.current.lastMilestone = computeBoundedProgressMilestone(initialPct)
      emitAnnouncement(`Hashing video: ${announcementTrackerRef.current.lastMilestone}% complete.`)
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
            const clampedPct = Number.isFinite(progress.percentage)
              ? Math.max(0, Math.min(100, Math.floor(progress.percentage)))
              : 0
            const tracker = announcementTrackerRef.current
            if (clampedPct === tracker.lastPercentage) return
            tracker.lastPercentage = clampedPct
            const milestone = computeBoundedProgressMilestone(clampedPct)
            if (milestone > (tracker.lastMilestone ?? -1)) {
              tracker.lastMilestone = milestone
              emitAnnouncement(`Hashing video: ${milestone}% complete.`)
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

      updateStage('embedding')
      setMessage('Embedding portable Harpocrates metadata into the video.')
      emitAnnouncement('Embedding portable Harpocrates metadata into the video.')

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
      updateStage('ready')
      const readyMsg = 'Embedded evidence package is ready for Stellar registration.'
      setMessage(readyMsg)
      emitAnnouncement(readyMsg, 'success')
    } catch (error) {
      if (!isCurrentFlow()) return
      updateStage('error')
      const errMsg = error instanceof Error ? error.message : 'Evidence processing failed.'
      setMessage(errMsg)
      emitAnnouncement(errMsg, 'failure')
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
      resetOperationAnnouncements()
      updateStage('registering')
      const savingMsg = 'Saving the completed Stellar registration.'
      setMessage(savingMsg)
      emitAnnouncement(savingMsg)
      try {
        const { persistRegistration } = await import('../services/evidenceService')
        await persistRegistration(pendingPersistence.proof, pendingPersistence.result, wallet)
        pendingPersistenceRef.current = null
        completedRegistrationRef.current = registrationKey
        setRegistration(pendingPersistence.result)
        updateStage('registered')
        const regMsg = `Registration submitted with Stellar status: ${pendingPersistence.result.status}.`
        setMessage(regMsg)
        emitAnnouncement(regMsg, 'success')
      } catch (error) {
        updateStage('error')
        const errMsg = error instanceof Error ? error.message : 'Could not save the Stellar registration.'
        setMessage(errMsg)
        emitAnnouncement(errMsg, 'failure')
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
    resetOperationAnnouncements()

    const submitMsg = `Submitting ${selectedTierMeta.title} proof to Stellar Testnet.`
    setMessage(submitMsg)
    emitAnnouncement(submitMsg)

    const currentSeq = seqRef.current
    try {
      const proofForRegistration =
        selectedTier === 'silent' && !proof.silentWitness
          ? await attachSilentWitnessProof(proof, currentSeq, abortRef.current?.signal)
          : proof
      if (seqRef.current !== currentSeq) return

      updateStage('registering')
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
      updateStage('registered')
      const regMsg = `Registration submitted with Stellar status: ${result.status}.`
      setMessage(regMsg)
      emitAnnouncement(regMsg, 'success')
    } catch (error) {
      if (seqRef.current !== currentSeq || stageRef.current === 'cancelled') return
      updateStage('error')
      const errMsg = error instanceof Error ? error.message : 'Stellar registration failed.'
      setMessage(errMsg)
      emitAnnouncement(errMsg, 'failure')
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
    updateStage('proving')
    const proveMsg = 'Generating Silent Witness ZK proof locally.'
    setMessage(proveMsg)
    emitAnnouncement(proveMsg)

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
    updateStage('cancelled')
    const cancelledMsg = CANCELLED_MESSAGES[currentStage]
    setMessage(cancelledMsg)
    emitAnnouncement(cancelledMsg, 'cancelled')
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
    message,
    liveAnnouncement,
    announcementHistory,
    registration,
    networkMismatch,
    isCancellable,
    handleEvidence,
    registerProof,
    cancelEvidence,
    cancelProving,
  }
}