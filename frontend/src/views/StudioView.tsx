import { useMemo, useRef, useState } from 'react'
import { BadgeCheck, CheckCircle2, Loader2, Upload, XCircle } from 'lucide-react'
import type { UseEvidenceReturn } from '../hooks/useEvidence'
import { EVIDENCE_REPLACED_MESSAGE, TIERS } from '../hooks/useEvidence'
import type { UseVerificationReturn } from '../hooks/useVerification'
import { ChainProofPanel } from '../components/ChainProofPanel'
import { EventList } from '../components/EventList'
import { ShareVerificationLink } from '../components/ShareVerificationLink'
import { VerifierSetStatusPanel } from '../components/VerifierSetStatusPanel'
import { shortHash } from '../utils'
import { useA11yStage } from '../hooks/useA11y'
import ProvenanceCard from '../provenance/ProvenanceCard'
import type { ProvenanceRecord } from '../provenance/provenanceModel'
import { RedactionPreview } from '../components/RedactionPreview'
import { CONTRACT_NETWORK_PASSPHRASE } from '../stellar'
import type { VerificationShareLinkInput } from '../verificationShareLink'

const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

type Props = {
  wallet: string
  evidence: UseEvidenceReturn
  verification: UseVerificationReturn
  provenanceRecord: ProvenanceRecord | null
}

export function StudioView({ wallet, evidence, verification, provenanceRecord }: Props) {
  const {
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
    evidenceChangeNotice = null,
    clearEvidenceChangeNotice,
    registration,
    networkMismatch,
    isCancellable,
    handleEvidence,
    registerProof,
    cancelEvidence,
    cancelProving,
  } = evidence

  const {
    verifyHash,
    verifyResult,
    events,
    chainProof,
    status: verifyStatus,
    verifyEvidence,
    loadEvents,
    clear: clearVerification,
  } = verification

  const [verificationCleared, setVerificationCleared] = useState(false)
  const [verificationClearedNotice, setVerificationClearedNotice] = useState<string | null>(null)
  const [clearedRegistrationHash, setClearedRegistrationHash] = useState<string | null>(null)

  const effectiveVerifyHash = verificationCleared ? '' : verifyHash
  const effectiveVerifyResult = verificationCleared ? '' : verifyResult
  const effectiveChainProof = verificationCleared ? null : chainProof
  const effectiveEvents = verificationCleared ? [] : events
  const effectiveProvenanceRecord =
    verificationCleared && provenanceRecord?.ledger.status !== null ? null : provenanceRecord

  const hasFreshRegistration =
    stage === 'registered' &&
    Boolean(registration?.hash) &&
    registration?.hash !== clearedRegistrationHash

  const stateChangeExplanation = hasFreshRegistration
    ? null
    : (verificationClearedNotice ?? evidenceChangeNotice ?? null)

  const { statusLabel, isBusy } = useA11yStage(stage)
  const isProving = stage === 'proving'
  const revocationProofId =
    effectiveEvents.find((event) => event.video_hash === effectiveVerifyHash && event.proof_id)?.proof_id ?? null

  const studioInputRef = useRef<HTMLInputElement | null>(null)

  function handleStudioFileChange(nextFile: File | null) {
    if (!nextFile) return

    const hadVerificationState = Boolean(
      !verificationCleared &&
        (verifyHash || verifyResult || chainProof || events.length > 0 || verifyStatus !== 'idle'),
    )
    const hadPriorEvidence = Boolean(file || proof || registration)

    if (hadVerificationState) {
      clearVerification()
      setVerificationCleared(true)
      setClearedRegistrationHash(registration?.hash ?? null)
      setVerificationClearedNotice(EVIDENCE_REPLACED_MESSAGE)
    } else if (hadPriorEvidence) {
      setClearedRegistrationHash(registration?.hash ?? null)
      setVerificationClearedNotice(EVIDENCE_REPLACED_MESSAGE)
    } else {
      setClearedRegistrationHash(null)
      setVerificationClearedNotice(null)
    }

    void handleEvidence(nextFile)
  }

  function handleQuickVerifyChange(nextFile: File | null) {
    if (nextFile) {
      setVerificationCleared(false)
      setClearedRegistrationHash(null)
      setVerificationClearedNotice(null)
      clearEvidenceChangeNotice?.()
    }
    void verifyEvidence(nextFile, wallet || undefined)
  }

  const shareLinkInput = useMemo((): VerificationShareLinkInput | null => {
    if (!proof?.videoHash || !proof.proofId || !proof.metadataHash || !CONTRACT_ID) return null
    return {
      videoHash: proof.videoHash,
      proofId: proof.proofId,
      metadataHash: proof.metadataHash,
      network: CONTRACT_NETWORK_PASSPHRASE,
      contractId: CONTRACT_ID,
      transactionRef: registration?.hash || undefined,
      tier: proof.tier,
    }
  }, [proof, registration?.hash])

  return (
    <section className="workspace app-page" id="studio" aria-busy={isBusy || undefined} aria-label="Evidence Studio workspace">
      <div className="studio">
        <header className="page-header">
          <h2 id="studio-heading" tabIndex={-1}>Evidence Studio</h2>
          <p role="status" aria-live="polite" aria-atomic="true">{message}</p>
          <div className="sr-only" aria-live="polite" aria-atomic="true">{statusLabel}</div>
        </header>

        {networkMismatch ? (
          <div className="network-mismatch-banner" role="alert">
            <span className="network-mismatch-icon" aria-hidden="true">⚠</span>
            <span>{networkMismatch}</span>
          </div>
        ) : null}

        {stateChangeExplanation ? (
          <div
            className="studio-state-notice"
            role="status"
            aria-live="polite"
            aria-atomic="true"
            data-testid="studio-evidence-change-notice"
          >
            <p>{stateChangeExplanation}</p>
          </div>
        ) : null}

        {/* Dropzone — keyboard: Tab focuses the label, Enter/Space opens the file picker */}
        <label
          className="dropzone"
          role="button"
          tabIndex={0}
          aria-label={file ? `Evidence file: ${file.name}. Press Enter or Space to choose a different file` : 'Drop or choose a video file. Press Enter or Space to open file picker'}
          aria-disabled={isBusy}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              if (!isBusy) studioInputRef.current?.click()
            }
          }}
        >
          <Upload size={20} aria-hidden="true" />
          <span aria-hidden="true">{file ? file.name : 'Drop or choose a video file'}</span>
          <input
            ref={studioInputRef}
            type="file"
            accept="video/*"
            tabIndex={-1}
            aria-hidden="true"
            onChange={(event) => handleStudioFileChange(event.target.files?.[0] ?? null)}
          />
        </label>

        {stage === 'hashing' && hashProgress ? (
          <div className="hash-progress">
            <div className="hash-progress-row">
              <Loader2 size={14} className="spin" aria-hidden="true" />
              <span>
                Hashing {hashProgress.percentage}% ({hashProgress.processedBytes.toLocaleString()} /{' '}
                {hashProgress.totalBytes.toLocaleString()} bytes)
              </span>
            </div>
            <progress
              value={hashProgress.processedBytes}
              max={Math.max(hashProgress.totalBytes, 1)}
              aria-label="File hashing progress"
            />
          </div>
        ) : null}

        <div className="tier-tabs" role="group" aria-label="Identity tier">
          {TIERS.map((tier) => {
            const Icon = tier.icon
            return (
              <button
                className={tier.id === selectedTier ? 'tier-tab active' : 'tier-tab'}
                aria-pressed={tier.id === selectedTier}
                key={tier.id}
                type="button"
                onClick={() => setSelectedTier(tier.id)}
              >
                <Icon size={14} aria-hidden="true" />
                {tier.title}
              </button>
            )
          })}
        </div>

        {selectedTier === 'silent' ? (
          <div className="secret-grid">
            <label>
              <span>Credential Seed</span>
              <input
                type="password"
                value={credentialSeed}
                onChange={(event) => setCredentialSeed(event.target.value)}
                autoComplete="off"
              />
            </label>
            <label>
              <span>Nullifier Seed</span>
              <input
                type="password"
                value={nullifierSeed}
                onChange={(event) => setNullifierSeed(event.target.value)}
                autoComplete="off"
              />
            </label>
          </div>
        ) : null}

        {isCancellable ? (
          <div className="verify-actions" role="group" aria-label="Evidence studio actions">
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={cancelEvidence}
              aria-label={stage === 'proving' ? 'Cancel proof generation' : 'Cancel upload'}
            >
              <XCircle size={14} aria-hidden="true" />
              {stage === 'proving' ? 'Cancel proof' : 'Cancel upload'}
            </button>
          </div>
        ) : null}

        <dl className="data-list" aria-label="Evidence data">
          <div>
            <dt>Source Hash</dt>
            <dd>{shortHash(proof?.sourceHash ?? '')}</dd>
          </div>
          <div>
            <dt>Video Hash</dt>
            <dd>{shortHash(proof?.videoHash ?? '')}</dd>
          </div>
          <div>
            <dt>Metadata Hash</dt>
            <dd>{shortHash(proof?.metadataHash ?? '')}</dd>
          </div>
          <div>
            <dt>Proof ID</dt>
            <dd>{shortHash(proof?.proofId ?? '')}</dd>
          </div>
          <div>
            <dt>Tier</dt>
            <dd>{selectedTierMeta.title}</dd>
          </div>
          <div>
            <dt>Nullifier</dt>
            <dd>{shortHash(proof?.silentWitness?.nullifier ?? '')}</dd>
          </div>
          <div>
            <dt>Credential Root</dt>
            <dd>{shortHash(proof?.silentWitness?.credentialRoot ?? '')}</dd>
          </div>
          <div>
            <dt>Stellar Tx</dt>
            <dd>{shortHash(registration?.hash ?? '')}</dd>
          </div>
          <div>
            <dt>Tx Status</dt>
            <dd>{registration?.status ?? 'Not submitted'}</dd>
          </div>
        </dl>

        <RedactionPreview
          proof={proof}
          secrets={{
            credentialSeed: credentialSeed || undefined,
            nullifierSeed: nullifierSeed || undefined,
            mediaObjectUrl: processedVideoUrl || undefined,
          }}
        />

        {processedVideoUrl ? (
          <a
            className="download-link"
            href={processedVideoUrl}
            download={proof?.fileName ?? 'harpocrates-evidence.mp4'}
            aria-label={`Download ${proof?.fileName ?? 'evidence video'}`}
          >
            Download embedded evidence video
          </a>
        ) : null}

        <div className="action-row" style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <button
            className="primary-action"
            type="button"
            disabled={!proof || !!networkMismatch || isBusy}
            aria-busy={isBusy || undefined}
            onClick={() => void registerProof(wallet)}
          >
            {isBusy ? (
              <Loader2 className="spin" size={18} aria-hidden="true" />
            ) : (
              <BadgeCheck size={18} aria-hidden="true" />
            )}
            Register proof
          </button>

          {isProving ? (
            <button
              className="secondary-action"
              type="button"
              onClick={() => cancelProving()}
              aria-label="Cancel proof generation"
            >
              <XCircle size={18} aria-hidden="true" />
              Cancel proving
            </button>
          ) : null}
        </div>

        <ShareVerificationLink input={shareLinkInput} />
      </div>

      <aside className="side-rail">
        <div className="rail-block">
          <h3>{selectedTierMeta.title}</h3>
          <p>{selectedTierMeta.description}</p>
        </div>

        <div className="rail-block">
          <h3>Quick Verify</h3>
          <label className="verify-input">
            <input
              type="file"
              accept="video/*"
              onChange={(event) => handleQuickVerifyChange(event.target.files?.[0] ?? null)}
            />
            <span>Choose received video</span>
          </label>
          <div className="verify-result">
            {effectiveVerifyResult && verifyStatus === 'success' ? (
              <CheckCircle2 size={14} aria-hidden="true" />
            ) : null}
            <p>{effectiveVerifyResult || 'No verification run yet.'}</p>
          </div>
          <code>{shortHash(effectiveVerifyHash)}</code>
        </div>

        <div className="rail-block">
          <h3>Chain Registry</h3>
          <ChainProofPanel
            chainProof={effectiveChainProof}
            proofId={revocationProofId}
            sourceAddress={wallet || undefined}
          />
          <h4 style={{ marginTop: '1rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Verifier Set Status</h4>
          <VerifierSetStatusPanel />
          {effectiveProvenanceRecord ? <ProvenanceCard provenance={effectiveProvenanceRecord} /> : null}
        </div>

        <div className="rail-block">
          <h3>Events</h3>
          <EventList events={effectiveEvents} onRefresh={() => void loadEvents()} />
        </div>
      </aside>
    </section>
  )
}
