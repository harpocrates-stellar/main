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
import { CIRCUIT_INPUT_SCHEMA_VERSION, silentWitnessEpoch } from '../circuitInputSchema'
import {
  buildProofPreparationPreview,
  PROOF_PREPARATION_VERIFIER_SCOPE,
  type ProofPreparationPreviewResult,
} from '../proofPreparationPreview'

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
  registered: 'Request cancelled.',
  error: 'Request cancelled.',
  cancelled: 'Request cancelled.',
}

export type NetworkMismatchRecoveryState = {
  /** Human-readable name of the network required by the deployed contract (e.g. "Testnet"). */
  requiredNetwork: string
  /** Human-readable name of the wallet's currently reported network (e.g. "Mainnet"), or "Unavailable". */
  currentWalletNetwork: string
  /** Non-identifying explanation of the mismatch. */
  reason: string
  /** Actionable remediation guidance for switching networks. */
  remediation: string
  /** True while a fresh network and evidence-intent validation is in progress. */
  isValidating: boolean
  /** Snapshot of the evidence intent active when the mismatch was detected. */
  intent: {
    proofId: string
    tier: IdentityTier
    videoHash: string
  } | null
  /** Optional privacy-safe error message from the most recent re-validation attempt. */
  validationError: string | null
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
  handleEvidence: (nextFile: File | null) => Promise<void>
  registerProof: (wallet: string) => Promise<void>
  /** Re-validate the wallet network and selected evidence intent before allowing registration to resume. */
  revalidateNetworkMismatch: (wallet: string) => Promise<boolean>
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
  const [registration, setRegistration] = useState<RegisterProofResult | null>(null)
  const [networkMismatch, setNetworkMismatch] = useState<string | null>(null)
  const [networkMismatchRecovery, setNetworkMismatchRecovery] =
    useState<NetworkMismatchRecoveryState | null>(null)
  const [acknowledgedSensitiveFields, setAcknowledgedSensitiveFields] = useState<string[]>([])
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
    setNetworkMismatch(null)
    setNetworkMismatchRecovery(null)
    setAcknowledgedSensitiveFields([])
  }

  function acknowledgeSensitiveFields(keys: string[]) {
    if (!keys.length) return
    setAcknowledgedSensitiveFields((prev) => {
      const merged = new Set(prev)
      for (const key of keys) {
        if (typeof key === 'string' && key.length > 0) {
          merged.add(key)
        }
      }
      return Array.from(merged)
    })
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
              `Hashing video locally in the browser: ${progress.percentage}% (${progress.processedBytes.toLocaleString()} / ${progress.totalBytes.toLocaleString()} bytes).`,
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
        throw new Error('Proof generation cancelled.')
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
    message,
    proofPreparation,
    acknowledgedSensitiveFields,
    acknowledgeSensitiveFields,
    registration,
    networkMismatch,
    networkMismatchRecovery,
    isCancellable,
    handleEvidence,
    registerProof,
    revalidateNetworkMismatch,
    cancelEvidence,
    cancelProving,
  }
}
