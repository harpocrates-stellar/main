import { useEffect, useMemo, useRef, useState } from 'react'
import { BadgeCheck, CheckCircle2, Loader2, Upload, XCircle } from 'lucide-react'
import type { UseEvidenceReturn } from '../hooks/useEvidence'
import { TIERS } from '../hooks/useEvidence'
import type { UseVerificationReturn } from '../hooks/useVerification'
import { ChainProofPanel } from '../components/ChainProofPanel'
import { EventList } from '../components/EventList'
import { ShareVerificationLink } from '../components/ShareVerificationLink'
import { VerifierSetStatusPanel } from '../components/VerifierSetStatusPanel'
import { shortHash } from '../utils'
import { useA11yStage } from '../hooks/useA11y'
import { PROOF_STAGE_SEQUENCE, proofStageLabel, proofStageStatus } from '../proofStage'
import ProvenanceCard from '../provenance/ProvenanceCard'
import type { ProvenanceRecord } from '../provenance/provenanceModel'
import { RedactionPreview } from '../components/RedactionPreview'
import {
  CONTRACT_NETWORK_PASSPHRASE,
  DELEGATION_SCOPE_REGISTER_SEAL,
  DELEGATION_SCOPE_REGISTER_SOURCE,
  getDelegation,
  isDelegationActive,
} from '../stellar'
import type { VerificationShareLinkInput } from '../verificationShareLink'

const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''
const STELLAR_STRKEY = /^[GC][A-Z2-7]{55}$/

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
    registration,
    networkMismatch,
    isCancellable,
    handleEvidence,
    registerProof,
    cancelEvidence,
    cancelProving,
  } = evidence

  const { verifyHash, verifyResult, events, chainProof, verifyEvidence, loadEvents } = verification

  const { statusLabel, isBusy } = useA11yStage(stage)
  const isProving = stage === 'proving'
  const revocationProofId =
    events.find((event) => event.video_hash === verifyHash && event.proof_id)?.proof_id ?? null

  const studioInputRef = useRef<HTMLInputElement | null>(null)

  const [grantorAddress, setGrantorAddress] = useState('')
  const [delegationStatus, setDelegationStatus] = useState<
    'idle' | 'checking' | 'active' | 'expired' | 'wrong_scope' | 'missing' | 'invalid_address' | 'self_delegation' | 'error'
  >('idle')
  const [delegationExpiry, setDelegationExpiry] = useState<number | null>(null)
  const [delegationError, setDelegationError] = useState<string | null>(null)

  const trimmedGrantor = grantorAddress.trim()

  useEffect(() => {
    if (selectedTier === 'silent' || !trimmedGrantor) {
      setDelegationStatus('idle')
      setDelegationExpiry(null)
      setDelegationError(null)
      return
    }

    if (!STELLAR_STRKEY.test(trimmedGrantor)) {
      setDelegationStatus('invalid_address')
      setDelegationExpiry(null)
      setDelegationError('Grantor address must be a valid 56-character Stellar address (starting with G or C).')
      return
    }

    if (wallet && trimmedGrantor.toUpperCase() === wallet.toUpperCase()) {
      setDelegationStatus('self_delegation')
      setDelegationExpiry(null)
      setDelegationError('Grantor cannot be your own wallet address. Use direct registration instead.')
      return
    }

    let isMounted = true
    const requiredScope =
      selectedTier === 'seal'
        ? DELEGATION_SCOPE_REGISTER_SEAL
        : DELEGATION_SCOPE_REGISTER_SOURCE

    setDelegationStatus('checking')
    setDelegationError(null)

    async function checkDelegation() {
      try {
        const [active, record] = await Promise.all([
          isDelegationActive(CONTRACT_ID, trimmedGrantor, wallet, requiredScope),
          getDelegation(CONTRACT_ID, trimmedGrantor, wallet),
        ])

        if (!isMounted) return

        if (!record) {
          setDelegationStatus('missing')
          setDelegationExpiry(null)
          return
        }

        setDelegationExpiry(record.expiresAt)

        if (active) {
          setDelegationStatus('active')
        } else {
          const nowSeconds = Math.floor(Date.now() / 1000)
          if (record.expiresAt <= nowSeconds) {
            setDelegationStatus('expired')
          } else if ((record.scope & requiredScope) !== requiredScope) {
            setDelegationStatus('wrong_scope')
          } else {
            setDelegationStatus('missing')
          }
        }
      } catch (err) {
        if (!isMounted) return
        setDelegationStatus('error')
        setDelegationError(err instanceof Error ? err.message : 'Error checking delegation.')
      }
    }

    void checkDelegation()

    return () => {
      isMounted = false
    }
  }, [trimmedGrantor, wallet, selectedTier])

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

        {/* Dropzone — keyboard: Tab focuses the label, Enter/Space opens the file picker */}
        <label
          className="dropzone"
          role="button"
          tabIndex={0}
          aria-label={file ? `Evidence file: ${file.name}. Press Enter or Space to choose a different file` : 'Drop or choose a video file. Press Enter or Space to open file picker'}
          aria-disabled={isBusy}
          htmlFor="studio-evidence-input"
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              if (!isBusy) studioInputRef.current?.click()
            }
          }}
        >
          <Upload size={20} aria-hidden="true" />
          <span aria-hidden="true">{file ? file.name : 'Drop or choose a video file'}</span>
        </label>
        <input
          ref={studioInputRef}
          id="studio-evidence-input"
          type="file"
          accept="video/*"
          tabIndex={-1}
          aria-hidden="true"
          onChange={(event) => void handleEvidence(event.target.files?.[0] ?? null)}
        />

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
        ) : (
          <div className="delegation-box" style={{ margin: '0 0 20px', padding: '14px', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '8px', background: 'rgba(255, 255, 255, 0.02)' }}>
            <label style={{ display: 'grid', gap: '7px' }}>
              <span style={{ color: 'rgba(255, 255, 255, 0.6)', fontFamily: 'var(--mono)', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Grantor Address (Optional – Delegated Registration)
              </span>
              <input
                type="text"
                placeholder="G... or C... (leave empty for direct registration)"
                value={grantorAddress}
                onChange={(e) => setGrantorAddress(e.target.value)}
                style={{
                  width: '100%',
                  minHeight: '38px',
                  padding: '0 12px',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  background: 'rgba(18, 18, 20, 0.7)',
                  fontFamily: 'var(--mono)',
                  fontSize: '12px',
                  outline: 'none',
                }}
              />
            </label>
            {trimmedGrantor ? (
              <div style={{ marginTop: '10px', fontSize: '12px', lineHeight: 1.5 }}>
                <p style={{ margin: '0 0 6px', color: 'rgba(255, 255, 255, 0.7)' }}>
                  Attribution: The registered proof will be attributed to grantor{' '}
                  <strong style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{trimmedGrantor}</strong>.
                  Your wallet acts as the authorized delegate.
                </p>
                {delegationStatus === 'checking' ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'rgba(255, 255, 255, 0.5)' }}>
                    <Loader2 size={12} className="spin" aria-hidden="true" />
                    <span>Checking delegation status...</span>
                  </div>
                ) : null}
                {delegationStatus === 'active' ? (
                  <p role="status" style={{ margin: 0, color: '#4ade80' }}>
                    Active delegation verified. Expiry: {delegationExpiry ? new Date(delegationExpiry * 1000).toISOString() : 'Never'}
                  </p>
                ) : null}
                {delegationStatus === 'expired' ? (
                  <p role="alert" style={{ margin: 0, color: '#f87171' }}>
                    Delegation has expired ({delegationExpiry ? new Date(delegationExpiry * 1000).toISOString() : 'Expired'}). Submission blocked.
                  </p>
                ) : null}
                {delegationStatus === 'wrong_scope' ? (
                  <p role="alert" style={{ margin: 0, color: '#f87171' }}>
                    Delegation does not grant permission for {selectedTier === 'seal' ? 'Public Seal' : 'Consistent Source'} registration.
                  </p>
                ) : null}
                {delegationStatus === 'missing' ? (
                  <p role="alert" style={{ margin: 0, color: '#f87171' }}>
                    No delegation grant found from this grantor to your wallet.
                  </p>
                ) : null}
                {delegationStatus === 'invalid_address' ? (
                  <p role="alert" style={{ margin: 0, color: '#f87171' }}>
                    Grantor address must be a valid 56-character Stellar address (starting with G or C).
                  </p>
                ) : null}
                {delegationStatus === 'self_delegation' ? (
                  <p role="alert" style={{ margin: 0, color: '#f87171' }}>
                    Grantor cannot be your own wallet address. Use direct registration instead.
                  </p>
                ) : null}
                {delegationStatus === 'error' ? (
                  <p role="alert" style={{ margin: 0, color: '#f87171' }}>
                    {delegationError || 'Could not verify delegation with the registry.'}
                  </p>
                ) : null}
              </div>
            ) : null}
          </div>
        )}

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
          {trimmedGrantor && selectedTier !== 'silent' ? (
            <div>
              <dt>Grantor</dt>
              <dd title={trimmedGrantor}>{shortHash(trimmedGrantor)}</dd>
            </div>
          ) : null}
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
            disabled={!proof || !!networkMismatch || isBusy || (selectedTier !== 'silent' && Boolean(trimmedGrantor) && delegationStatus !== 'active')}
            aria-busy={isBusy || undefined}
            onClick={() => void registerProof(wallet, selectedTier !== 'silent' && trimmedGrantor ? trimmedGrantor : undefined)}
          >
            {isBusy ? (
              <Loader2 className="spin" size={18} aria-hidden="true" />
            ) : (
              <BadgeCheck size={18} aria-hidden="true" />
            )}
            {selectedTier !== 'silent' && trimmedGrantor ? 'Register proof (delegated)' : 'Register proof'}
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
              onChange={(event) =>
                void verifyEvidence(event.target.files?.[0] ?? null, wallet || undefined)
              }
            />
            <span>Choose received video</span>
          </label>
          <div className="verify-result">
            <CheckCircle2 size={14} aria-hidden="true" />
            <p>{verifyResult || 'No verification run yet.'}</p>
          </div>
          <code>{shortHash(verifyHash)}</code>
        </div>

        <div className="rail-block">
          <h3>Chain Registry</h3>
          <ChainProofPanel
            chainProof={chainProof}
            proofId={revocationProofId}
            sourceAddress={wallet || undefined}
          />
          <h4 style={{ marginTop: '1rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Verifier Set Status</h4>
          <VerifierSetStatusPanel />
          {provenanceRecord ? <ProvenanceCard provenance={provenanceRecord} /> : null}
        </div>

        <div className="rail-block">
          <h3>Events</h3>
          <EventList events={events} onRefresh={() => void loadEvents()} />
        </div>
      </aside>
    </section>
  )
}
