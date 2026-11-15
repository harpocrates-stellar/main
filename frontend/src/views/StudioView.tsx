import { useMemo, useRef, useState } from 'react'
import { BadgeCheck, CheckCircle2, Loader2, Upload, XCircle } from 'lucide-react'
import type { SensitiveExportFieldKey, UseEvidenceReturn } from '../hooks/useEvidence'
import { buildExportPrivacySummary, TIERS } from '../hooks/useEvidence'
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
    acknowledgedExportFields,
    acknowledgeExportFields,
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
  const [fallbackAckFields, setFallbackAckFields] = useState<SensitiveExportFieldKey[]>([])
  const [checkedAckSignature, setCheckedAckSignature] = useState<string>('')

  const effectiveAckFields = acknowledgedExportFields ?? fallbackAckFields

  const exportPrivacySummary = useMemo(
    () =>
      buildExportPrivacySummary({
        proof,
        registration,
        wallet,
        contractId: CONTRACT_ID,
        networkPassphrase: CONTRACT_NETWORK_PASSPHRASE,
        acknowledgedKeys: effectiveAckFields,
      }),
    [proof, registration, wallet, effectiveAckFields],
  )

  const newlyExposedSignature =
    exportPrivacySummary?.newlyExposedFields.map((field) => field.key).join(',') ?? ''
  const isAckChecked =
    newlyExposedSignature !== '' && checkedAckSignature === newlyExposedSignature

  function handleConfirmExportDisclosure() {
    if (!exportPrivacySummary || !isAckChecked) return
    const keys = exportPrivacySummary.newlyExposedFields.map((field) => field.key)
    if (acknowledgeExportFields) {
      acknowledgeExportFields(keys)
    } else {
      setFallbackAckFields((prev) => Array.from(new Set([...prev, ...keys])))
    }
    setCheckedAckSignature('')
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

        {/* Dropzone — keyboard: Tab focuses the label, Enter/Space opens the file picker */}
        <label
          htmlFor="studio-evidence-input"
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
          <output aria-hidden="true">{file ? file.name : 'Drop or choose a video file'}</output>
        </label>
        <input
          id="studio-evidence-input"
          ref={studioInputRef}
          type="file"
          accept="video/*"
          tabIndex={-1}
          aria-hidden="true"
          style={{ display: 'none' }}
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

        {exportPrivacySummary ? (
          <div
            className="rail-block"
            role="region"
            aria-labelledby="export-privacy-summary-heading"
            data-requires-ack={exportPrivacySummary.requiresAcknowledgement ? 'true' : 'false'}
          >
            <h3 id="export-privacy-summary-heading">Export privacy summary</h3>
            <p>
              Review the metadata classes and public identifiers included in exported evidence
              artifacts before downloading or sharing.
            </p>
            <h4 style={{ marginTop: '0.75rem', fontSize: '0.85rem' }}>Included metadata classes</h4>
            <ul aria-label="Included metadata classes">
              {exportPrivacySummary.metadataClasses.map((cls) => (
                <li key={cls.id} data-metadata-class={cls.id}>
                  <strong>{cls.label}:</strong> {cls.description}
                </li>
              ))}
            </ul>

            <h4 style={{ marginTop: '0.75rem', fontSize: '0.85rem' }}>Public identifiers</h4>
            <dl className="data-list" aria-label="Exported public identifiers">
              {exportPrivacySummary.publicIdentifiers.map((identifier) => (
                <div key={identifier.key}>
                  <dt>{identifier.label}</dt>
                  <dd>{identifier.value}</dd>
                </div>
              ))}
            </dl>

            {exportPrivacySummary.sensitiveFields.length === 0 ? (
              <p role="status">
                No sensitive attribution or capture-timing fields are exposed. Explicit
                acknowledgement is not required.
              </p>
            ) : (
              <div>
                <h4 style={{ marginTop: '0.75rem', fontSize: '0.85rem' }}>
                  Sensitive disclosure fields
                </h4>
                <ul aria-label="Sensitive disclosure fields">
                  {exportPrivacySummary.sensitiveFields.map((field) => (
                    <li
                      key={field.key}
                      data-sensitive-key={field.key}
                      data-newly-exposed={field.newlyExposed ? 'true' : 'false'}
                    >
                      <strong>{field.label}</strong> (
                      {field.newlyExposed ? 'Newly exposed' : 'Previously acknowledged'}):{' '}
                      {field.reason}
                    </li>
                  ))}
                </ul>

                {exportPrivacySummary.requiresAcknowledgement ? (
                  <div style={{ marginTop: '0.75rem' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <input
                        type="checkbox"
                        checked={isAckChecked}
                        onChange={(event) =>
                          setCheckedAckSignature(
                            event.target.checked ? newlyExposedSignature : '',
                          )
                        }
                      />
                      <span>
                        I acknowledge exporting newly exposed sensitive fields:{' '}
                        {exportPrivacySummary.newlyExposedFields
                          .map((field) => field.label)
                          .join(', ')}
                      </span>
                    </label>
                    <div style={{ marginTop: '0.5rem' }}>
                      <button
                        type="button"
                        className="hero-secondary verify-action-btn"
                        disabled={!isAckChecked}
                        onClick={handleConfirmExportDisclosure}
                      >
                        Confirm export disclosure
                      </button>
                    </div>
                  </div>
                ) : (
                  <p role="status">
                    All sensitive fields in this export have already been acknowledged.
                  </p>
                )}
              </div>
            )}
          </div>
        ) : null}

        {processedVideoUrl ? (
          exportPrivacySummary && !exportPrivacySummary.canExport ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              disabled
              aria-label={`Download ${proof?.fileName ?? 'evidence video'} (requires sensitive field acknowledgement)`}
            >
              Download embedded evidence video (acknowledge newly exposed fields first)
            </button>
          ) : (
            <a
              className="download-link"
              href={processedVideoUrl}
              download={proof?.fileName ?? 'harpocrates-evidence.mp4'}
              aria-label={`Download ${proof?.fileName ?? 'evidence video'}`}
            >
              Download embedded evidence video
            </a>
          )
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

          {isProving && !isCancellable ? (
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

        <ShareVerificationLink
          input={exportPrivacySummary && !exportPrivacySummary.canExport ? null : shareLinkInput}
        />
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
