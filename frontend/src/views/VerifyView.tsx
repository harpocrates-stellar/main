import { useEffect, useMemo, useRef, useState } from 'react'
import { CheckCircle2, Copy, Download, Eye, FileText, Loader2, RefreshCw, Upload, WifiOff, XCircle } from 'lucide-react'
import type { UseVerificationReturn } from '../hooks/useVerification'
import { useIssuerTrust } from '../hooks/useIssuerTrust'
import { explainVerificationTrust } from '../services/verificationFlow'
import { ChainProofPanel } from '../components/ChainProofPanel'
import { DisputePanel } from '../components/DisputePanel'
import { EventList } from '../components/EventList'
import { ReceiptComparisonView } from '../components/ReceiptComparisonView'
import { ShareVerificationLink } from '../components/ShareVerificationLink'
import { VerifierSetStatusPanel } from '../components/VerifierSetStatusPanel'
import VerificationTimeline from '../components/VerificationTimeline'
import { VerificationResultTabs } from '../components/VerificationResultTabs'
import { resolveVerifiedStatementIdentity } from '../services/verificationFlow'
import { shortHash } from '../utils'
import ProvenanceCard from '../provenance/ProvenanceCard'
import type { ProvenanceRecord } from '../provenance/provenanceModel'
import { CONTRACT_NETWORK_PASSPHRASE } from '../stellar'
import type { VerificationShareLinkInput } from '../verificationShareLink'
import { tryParseManifest } from '../batchVerifier'
import {
  buildVerificationExportPreview,
  serializeVerificationExportPreview,
  type VerificationExportPreview,
} from '../services/verificationFlow'

const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''
const MAX_MANIFEST_SIZE_BYTES = 64 * 1024 // 64 KB cap

function dimensionStateLabel(state: TrustDimensionState): string {
  switch (state) {
    case 'verified':
      return 'Verified'
    case 'failed':
      return 'Failed'
    case 'unverified':
      return 'Unverified'
    case 'not_applicable':
      return 'Not applicable'
  }
}

type Props = {
  wallet: string
  networkMismatch?: string | null
  verification: UseVerificationReturn
  provenanceRecord: ProvenanceRecord | null
}

function statusLabel(status: UseVerificationReturn['status'], offline: boolean): string {
  switch (status) {
    case 'validating': return 'Validating file…'
    case 'hashing': return 'Hashing evidence…'
    case 'verifying': return offline ? 'Inspecting evidence locally…' : 'Inspecting evidence…'
    case 'success': return 'Verification complete.'
    case 'error': return 'Verification did not confirm this artifact.'
    case 'cancelled': return 'Verification cancelled.'
    default: return 'No verification run yet.'
  }
}

export function VerifyView({ wallet, networkMismatch, verification, provenanceRecord }: Props) {
  const {
    verifyHash,
    verifyResult,
    events,
    chainProof,
    status,
    errorCode,
    isVerifying,
    offline,
    setOffline,
    verifyEvidence,
    loadEvents,
    loadSharedVerification,
    cancel,
    retry,
    clear,
  } = verification

  const inputRef = useRef<HTMLInputElement | null>(null)
  const manifestInputRef = useRef<HTMLInputElement | null>(null)
  const selectionRevisionRef = useRef(createVerificationRevisionGuard())
  const [videoHashInput, setVideoHashInput] = useState('')
  const [proofIdInput, setProofIdInput] = useState('')
  const [manifestError, setManifestError] = useState<string | null>(null)
  const [exportPreview, setExportPreview] = useState<VerificationExportPreview | null>(null)
  const [exportFeedback, setExportFeedback] = useState<string | null>(null)

  const [prevVerifyHash, setPrevVerifyHash] = useState(verifyHash)
  if (verifyHash !== prevVerifyHash) {
    setPrevVerifyHash(verifyHash)
    if (verifyHash) {
      setVideoHashInput(verifyHash)
      setProofIdInput('')
    }
  }

  const handleManifestFile = async (file: File) => {
    const revision = selectionRevisionRef.current.next()
    if (file.size > MAX_MANIFEST_SIZE_BYTES) {
      setManifestError(`Manifest file exceeds the 64 KB size limit (${(file.size / 1024).toFixed(1)} KB).`)
      return
    }

    const manifest = await tryParseManifest(file)
    if (!selectionRevisionRef.current.isCurrent(revision)) {
      return
    }
    if (!manifest) {
      setManifestError('Invalid or malformed proof manifest JSON.')
      return
    }

    setManifestError(null)
    setVideoHashInput(manifest.videoHash)
    setProofIdInput(manifest.proofId ?? '')

    // Start chain verification
    if (typeof loadSharedVerification === 'function') {
      void loadSharedVerification({
        protocol: 'harpocrates-verification-link',
        version: 1,
        videoHash: manifest.videoHash,
        proofId: manifest.proofId,
        metadataHash: manifest.metadataHash,
        network: manifest.network || CONTRACT_NETWORK_PASSPHRASE,
        contractId: manifest.contractId || CONTRACT_ID,
        transactionRef: manifest.transactionRef || undefined,
        tier: manifest.tier,
      })
    }
  }

  const handleManualSubmit = async () => {
    const vHash = videoHashInput.trim()
    const pId = proofIdInput.trim()
    if (!vHash) return
    selectionRevisionRef.current.invalidate()
    setManifestError(null)
    if (typeof loadSharedVerification === 'function') {
      void loadSharedVerification({
        protocol: 'harpocrates-verification-link',
        version: 1,
        videoHash: vHash,
        proofId: pId,
        metadataHash: '',
        network: CONTRACT_NETWORK_PASSPHRASE,
        contractId: CONTRACT_ID,
      })
    }
  }

  const statementIdentity = useMemo(() => {
    return resolveVerifiedStatementIdentity({
      verifyHash,
      videoHashInput,
      proofIdInput,
      events,
      chainProof,
    })
  }, [verifyHash, videoHashInput, proofIdInput, events, chainProof])

  const revocationProofId =
    statementIdentity.proofId ??
    events.find((event) => event.video_hash === (videoHashInput || verifyHash) && event.proof_id)?.proof_id ??
    proofIdInput ??
    null

  const isError = status === 'error'
  const isCancelled = status === 'cancelled'
  const showRetry = isError && !manifestError && !!errorCode && errorCode !== 'CANCELLED' && errorCode !== 'REVOKED_EVIDENCE' && errorCode !== 'EXPIRED_EVIDENCE'
  // Revoked/expired are terminal trust decisions, retry still allowed but we keep it available via retry button
  const effectiveRetry = isError || isCancelled
  const canPreviewExport =
    !isVerifying &&
    status !== 'idle' &&
    Boolean(verifyHash || verifyResult || videoHashInput.trim())

  const handleOpenExportPreview = () => {
    if (!canPreviewExport) return
    const activeHash = (videoHashInput || verifyHash).trim()
    const metadataHash = chainProof?.metadataHash ?? provenanceRecord?.metadata.metadataHash ?? null
    const snapshot = buildVerificationExportPreview({
      videoHash: activeHash,
      proofId: proofIdInput.trim() || revocationProofId,
      metadataHash,
      status,
      summary: manifestError || verifyResult || statusLabel(status, offline),
      errorCode: manifestError ? null : errorCode,
      offline,
      events,
      chainProof,
      contractId: CONTRACT_ID || null,
      network: provenanceRecord?.network.passphrase || CONTRACT_NETWORK_PASSPHRASE,
    })
    setExportPreview(snapshot)
    setExportFeedback(null)
  }

  const handleDownloadExport = () => {
    if (!exportPreview) return
    const json = serializeVerificationExportPreview(exportPreview)
    const blob = new Blob([json], { type: 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    const hashSuffix = exportPreview.includedFields.videoHash
      ? exportPreview.includedFields.videoHash.slice(0, 12)
      : 'result'
    anchor.href = url
    anchor.download = `verification-result-${hashSuffix}.json`
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
    setExportFeedback('Downloaded exact reviewed snapshot.')
  }

  const handleCopyExport = async () => {
    if (!exportPreview) return
    const json = serializeVerificationExportPreview(exportPreview)
    try {
      await navigator.clipboard.writeText(json)
      setExportFeedback('Copied exact reviewed snapshot JSON.')
    } catch {
      setExportFeedback('Could not copy to clipboard.')
    }
  }

  const shareLinkInput = useMemo((): VerificationShareLinkInput | null => {
    const activeHash = statementIdentity.statementDigest || videoHashInput || verifyHash
    if (status !== 'success' || !activeHash || !CONTRACT_ID) return null
    const matchedEvent =
      statementIdentity.matchingEvents[0] ??
      events.find((event) => event.proof_id && event.video_hash === activeHash) ??
      events.find((event) => !!event.proof_id)
    const proofId = statementIdentity.proofId ?? matchedEvent?.proof_id ?? proofIdInput ?? null
    const metadataHash =
      statementIdentity.metadataHash ??
      chainProof?.metadataHash ??
      provenanceRecord?.metadata.metadataHash ??
      null
    if (!proofId || !metadataHash) return null
    const tierRaw = matchedEvent?.tier
    const tier =
      tierRaw === 'silent' || tierRaw === 'source' || tierRaw === 'seal' ? tierRaw : undefined
    return {
      videoHash: activeHash,
      proofId,
      metadataHash,
      network: provenanceRecord?.network.passphrase || CONTRACT_NETWORK_PASSPHRASE,
      contractId: CONTRACT_ID,
      transactionRef: provenanceRecord?.ledger.transactionHash || matchedEvent?.tx_hash || undefined,
      tier,
    }
  }, [status, statementIdentity, videoHashInput, verifyHash, events, proofIdInput, chainProof, provenanceRecord])

  return (
    <section className="workspace app-page verify-page" id="verify">
      <div className="studio verify-studio">
        <header className="page-header">
          <h2 id="verify-heading" tabIndex={-1}>Verify Artifact</h2>
          <p>Inspect a received video against embedded metadata and the Stellar registry.</p>
        </header>

        {networkMismatch ? (
          <div className="network-mismatch-banner" role="alert" aria-live="assertive" aria-atomic="true">
            <span className="network-mismatch-icon" aria-hidden="true">⚠</span>
            <span>{networkMismatch}</span>
          </div>
        ) : null}

        {manifestError ? (
          <div className="network-mismatch-banner manifest-error-banner" role="alert" aria-live="assertive" aria-atomic="true">
            <span className="network-mismatch-icon" aria-hidden="true">⚠</span>
            <span>{manifestError}</span>
          </div>
        ) : null}

        {/* Dropzone — keyboard: Tab focuses the label, Enter/Space opens the file picker */}
        <label
          className="dropzone"
          role="button"
          tabIndex={isVerifying ? -1 : 0}
          aria-label={isVerifying ? statusLabel(status, offline) : 'Drop or choose a received video. Press Enter or Space to open file picker'}
          aria-busy={isVerifying}
          aria-disabled={isVerifying}
          htmlFor="verify-video-input"
          // ensure dropzone is a large touch target on mobile
          style={{ minHeight: 140 }}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ' ') && !isVerifying) {
              e.preventDefault()
              inputRef.current?.click()
            }
          }}
          onDragOver={(e) => {
            e.preventDefault()
          }}
          onDrop={(e) => {
            e.preventDefault()
            const f = e.dataTransfer.files?.[0] ?? null
            if (f) {
              if (f.name.endsWith('.json') || f.type === 'application/json') {
                void handleManifestFile(f)
              } else {
                selectionRevisionRef.current.invalidate()
                void verifyEvidence(f, wallet || undefined)
              }
            }
          }}
        >
          {isVerifying ? (
            <Loader2 size={20} className="spin" aria-hidden="true" />
          ) : (
            <Upload size={20} aria-hidden="true" />
          )}
          <span aria-hidden="true">{isVerifying ? statusLabel(status, offline) : 'Drop or choose a received video'}</span>
          <span className="muted" aria-hidden="true" style={{ fontSize: 11, textAlign: 'center', overflowWrap: 'anywhere' }}>
            MP4, WebM, or MOV · up to 100 MB
          </span>
        </label>
        <input
          ref={inputRef}
          id="verify-video-input"
          type="file"
          accept="video/*"
          tabIndex={-1}
          aria-hidden="true"
          disabled={isVerifying}
          onChange={(event) => {
            const f = event.target.files?.[0] ?? null
            void verifyEvidence(f, wallet || undefined)
            // allow re-selecting the same file
            event.target.value = ''
          }}
        />

        {/* Manifest Dropzone — keyboard: Tab focuses label, Enter/Space opens manifest file picker */}
        <label
          className="dropzone manifest-dropzone"
          role="button"
          tabIndex={isVerifying ? -1 : 0}
          aria-label={isVerifying ? 'Manifest upload disabled during verification' : 'Proof manifest JSON upload. Press Enter or Space to open file picker'}
          aria-busy={isVerifying}
          aria-disabled={isVerifying}
          htmlFor="verify-manifest-input"
          style={{ minHeight: 100 }}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ' ') && !isVerifying) {
              e.preventDefault()
              manifestInputRef.current?.click()
            }
          }}
          onDragOver={(e) => {
            e.preventDefault()
          }}
          onDrop={(e) => {
            e.preventDefault()
            const f = e.dataTransfer.files?.[0] ?? null
            if (f) void handleManifestFile(f)
          }}
        >
          {isVerifying ? (
            <Loader2 size={20} className="spin" aria-hidden="true" />
          ) : (
            <FileText size={20} aria-hidden="true" />
          )}
          <span aria-hidden="true">{isVerifying ? 'Verification in progress…' : 'Drop or choose a proof manifest JSON'}</span>
          <span className="muted" aria-hidden="true" style={{ fontSize: 11, textAlign: 'center', overflowWrap: 'anywhere' }}>
            Portable manifest receipt · max 64 KB
          </span>
        </label>
        <input
          ref={manifestInputRef}
          id="verify-manifest-input"
          type="file"
          accept=".json,application/json"
          tabIndex={-1}
          aria-label="Drop or choose a proof manifest JSON"
          disabled={isVerifying}
          onChange={(event) => {
            const f = event.target.files?.[0] ?? null
            if (f) void handleManifestFile(f)
            event.target.value = ''
          }}
        />

        {/* Verification form — prefilled by manifest or manual typing */}
        <form
          className="manifest-verify-form"
          aria-label="Manifest verification form"
          onSubmit={(e) => {
            e.preventDefault()
            void handleManualSubmit()
          }}
        >
          <div className="form-group">
            <label htmlFor="verify-video-hash">Video Hash</label>
            <input
              id="verify-video-hash"
              type="text"
              name="videoHash"
              value={videoHashInput}
              onChange={(e) => {
                selectionRevisionRef.current.invalidate()
                setVideoHashInput(e.target.value)
                setManifestError(null)
              }}
              placeholder="Prefilled by manifest or enter 64-char hex video hash"
              disabled={isVerifying}
              aria-label="Video Hash"
            />
          </div>
          <div className="form-group">
            <label htmlFor="verify-proof-id">Proof ID</label>
            <input
              id="verify-proof-id"
              type="text"
              name="proofId"
              value={proofIdInput}
              onChange={(e) => {
                selectionRevisionRef.current.invalidate()
                setProofIdInput(e.target.value)
                setManifestError(null)
              }}
              placeholder="Prefilled by manifest or enter proof ID"
              disabled={isVerifying}
              aria-label="Proof ID"
            />
          </div>
          <button
            type="submit"
            className="hero-secondary"
            disabled={isVerifying || !videoHashInput.trim()}
          >
            Verify On-Chain
          </button>
        </form>

        {/* Verification mode — offline runs entirely in the browser, online uses backend + registry */}
        <div className="verify-mode" role="group" aria-label="Verification mode">
          <button
            type="button"
            className={`mode-toggle ${offline ? 'active' : ''}`}
            aria-pressed={offline}
            disabled={isVerifying}
            onClick={() => setOffline(!offline)}
          >
            <WifiOff size={14} aria-hidden="true" />
            <span>Offline local check</span>
          </button>
          <p className="muted" style={{ fontSize: 11 }}>
            {offline
              ? 'Runs fully local: hashes, extracts, and validates the embedded envelope in this browser with no network calls. It never yields a confirmed trust decision and produces no shareable verification link.'
              : 'Runs against the backend API, the NeonDB event feed, and the Stellar registry.'}
          </p>
        </div>

        {/* Progress / status live region — always present so mobile screen readers observe changes */}
        <div
          className="verify-progress"
          role="status"
          aria-live="polite"
          aria-atomic="true"
          aria-busy={isVerifying}
        >
          {isVerifying ? (
            <div className="verify-progress-row">
              <Loader2 size={14} className="spin" aria-hidden="true" />
              <span>{statusLabel(status, offline)}</span>
            </div>
          ) : null}
        </div>

        <div
          className={`verify-result large ${isError || manifestError ? 'verify-error' : ''} ${isCancelled ? 'verify-cancelled' : ''} ${isStaleSuccess ? 'verify-stale' : ''}`}
          data-stale-result={isStaleSuccess ? 'true' : undefined}
          role={isError ? 'alert' : 'status'}
          aria-live={isError ? 'assertive' : 'polite'}
          aria-atomic="true"
        >
          {isError || manifestError ? (
            <XCircle size={14} aria-hidden="true" />
          ) : isStaleSuccess ? (
            <RefreshCw size={14} aria-hidden="true" />
          ) : (
            <CheckCircle2 size={14} aria-hidden="true" />
          )}
          <div style={{ minWidth: 0, flex: 1 }}>
            <p style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
              {manifestError || staleResultMessage || verifyResult || statusLabel(status, offline)}
            </p>
            {errorCode && !manifestError ? (
              <p className="muted" style={{ marginTop: 4, fontSize: 11 }}>
                Code: {errorCode}
              </p>
            ) : null}
          </div>
        </div>

        {showTrustDimensions ? (
          <section
            className="trust-dimensions"
            aria-label="Verification trust dimensions"
            data-overall-verdict={trustModel.overall}
          >
            <h3 style={{ fontSize: '0.85rem', marginBottom: 6 }}>Trust Dimensions</h3>
            {trustModel.hasFailure ? (
              <p className="muted" style={{ fontSize: 11, marginBottom: 8 }}>
                One or more trust dimensions failed; successful dimensions do not override failures.
              </p>
            ) : null}
            <ul className="trust-dimensions-list" style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: 6 }}>
              {Object.values(trustModel.dimensions).map((dim) => (
                <li
                  key={dim.key}
                  data-dimension={dim.key}
                  data-state={dim.state}
                  style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 8, fontSize: 12 }}
                >
                  <div>
                    <strong>{dim.label}</strong>
                    <span className="muted" style={{ display: 'block', fontSize: 11 }}>
                      {dim.summary}
                    </span>
                  </div>
                  <span className={`trust-dimension-state trust-dimension-${dim.state}`}>
                    {dimensionStateLabel(dim.state)}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <VerificationTimeline
          status={status}
          verifyHash={verifyHash}
          events={events}
          chainProof={chainProof}
          errorCode={errorCode}
          offline={offline}
        />

        {/* Action row — reachable on mobile, adequate touch targets */}
        <div className="verify-actions" role="group" aria-label="Verification actions">
          {isVerifying ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={() => {
                selectionRevisionRef.current.invalidate()
                cancel()
              }}
              aria-label="Cancel verification"
            >
              Cancel
            </button>
          ) : null}
          {effectiveRetry ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={() => void retry()}
              aria-label="Retry verification"
            >
              <RefreshCw size={14} aria-hidden="true" />
              <span>Retry</span>
            </button>
          ) : null}
          {!isVerifying && (verifyHash || verifyResult || videoHashInput || proofIdInput || manifestError) ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={() => {
                selectionRevisionRef.current.invalidate()
                setVideoHashInput('')
                setProofIdInput('')
                setManifestError(null)
                setExportPreview(null)
                setExportFeedback(null)
                clear()
              }}
              aria-label="Clear verification result"
            >
              Clear
            </button>
          ) : null}
          {canPreviewExport ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={handleOpenExportPreview}
              aria-label="Preview verification export"
            >
              <Eye size={14} aria-hidden="true" />
              <span>Preview Export</span>
            </button>
          ) : null}
          {/* Hidden retry helper for tests / keyboard users */}
          {showRetry ? null : null}
        </div>

        {offline ? (
          <p className="muted" style={{ fontSize: 11 }} role="status">
            Offline mode produces no shareable verification link and no on-chain receipt.
          </p>
        ) : (
          <ShareVerificationLink input={shareLinkInput} />
        )}

        {exportPreview ? (
          <section className="export-preview-panel" aria-label="Verification export preview">
            <div className="export-preview-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
              <h3 style={{ margin: 0, fontSize: '0.95rem' }}>Export Preview</h3>
              <button
                type="button"
                className="hero-secondary"
                onClick={() => {
                  setExportPreview(null)
                  setExportFeedback(null)
                }}
                aria-label="Close export preview"
              >
                Close
              </button>
            </div>
            <p className="muted" style={{ fontSize: 11, marginTop: 4 }}>
              Exports this exact reviewed snapshot without refreshing on-chain or backend trust context.
            </p>

            <div className="export-preview-section" style={{ marginTop: 10 }}>
              <h4 style={{ margin: '0 0 4px', fontSize: '0.8rem' }}>Freshness</h4>
              <dl className="data-list">
                <div>
                  <dt>Freshness State</dt>
                  <dd>{exportPreview.freshness.state}</dd>
                </div>
                <div>
                  <dt>Snapshot Captured</dt>
                  <dd>{exportPreview.freshness.capturedAt}</dd>
                </div>
                <div>
                  <dt>Chain Record Created</dt>
                  <dd>{exportPreview.freshness.chainRecordCreatedAt ?? 'Not loaded'}</dd>
                </div>
                <div>
                  <dt>Latest Backend Event</dt>
                  <dd>{exportPreview.freshness.latestEventAt ?? 'None'}</dd>
                </div>
              </dl>
            </div>

            <div className="export-preview-section" style={{ marginTop: 10 }}>
              <h4 style={{ margin: '0 0 4px', fontSize: '0.8rem' }}>Included Fields</h4>
              <dl className="data-list">
                <div>
                  <dt>Video Hash</dt>
                  <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all', textAlign: 'right' }}>
                    {exportPreview.includedFields.videoHash || 'None'}
                  </dd>
                </div>
                <div>
                  <dt>Proof ID</dt>
                  <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all', textAlign: 'right' }}>
                    {exportPreview.includedFields.proofId ?? 'Unresolved'}
                  </dd>
                </div>
                <div>
                  <dt>Metadata Hash</dt>
                  <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all', textAlign: 'right' }}>
                    {exportPreview.includedFields.metadataHash ?? 'Unresolved'}
                  </dd>
                </div>
                <div>
                  <dt>Mode</dt>
                  <dd>{exportPreview.includedFields.mode}</dd>
                </div>
                <div>
                  <dt>Status</dt>
                  <dd>{exportPreview.includedFields.status}</dd>
                </div>
                <div>
                  <dt>Chain Status</dt>
                  <dd>{exportPreview.includedFields.chainStatus}</dd>
                </div>
                <div>
                  <dt>Identity Tier</dt>
                  <dd>{exportPreview.includedFields.tier ?? 'Unresolved'}</dd>
                </div>
                <div>
                  <dt>Matching Events</dt>
                  <dd>{exportPreview.includedFields.eventCount}</dd>
                </div>
                <div>
                  <dt>Network</dt>
                  <dd>{exportPreview.includedFields.network}</dd>
                </div>
                {exportPreview.includedFields.errorCode ? (
                  <div>
                    <dt>Error Code</dt>
                    <dd>{exportPreview.includedFields.errorCode}</dd>
                  </div>
                ) : null}
              </dl>
            </div>

            <div className="export-preview-section" style={{ marginTop: 10 }}>
              <h4 style={{ margin: '0 0 4px', fontSize: '0.8rem' }}>Unresolved Checks</h4>
              {exportPreview.unresolvedChecks.length === 0 ? (
                <p className="muted" style={{ fontSize: 11 }}>All checks resolved.</p>
              ) : (
                <ul className="export-unresolved-list" style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>
                  {exportPreview.unresolvedChecks.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              )}
            </div>

            <div className="verify-actions" role="group" aria-label="Export actions" style={{ marginTop: 12 }}>
              <button
                type="button"
                className="hero-secondary verify-action-btn"
                onClick={handleDownloadExport}
                aria-label="Download reviewed verification JSON"
              >
                <Download size={14} aria-hidden="true" />
                <span>Download JSON</span>
              </button>
              <button
                type="button"
                className="hero-secondary verify-action-btn"
                onClick={() => void handleCopyExport()}
                aria-label="Copy reviewed verification JSON"
              >
                <Copy size={14} aria-hidden="true" />
                <span>Copy JSON</span>
              </button>
            </div>

            {exportFeedback ? (
              <p className="muted" role="status" aria-live="polite" style={{ fontSize: 11, marginTop: 6 }}>
                {exportFeedback}
              </p>
            ) : null}
          </section>
        ) : null}

        <dl className="data-list">
          <div>
            <dt>Received Hash</dt>
            <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all', textAlign: 'right' }}>{shortHash(statementIdentity.statementDigest || videoHashInput || verifyHash)}</dd>
          </div>
          <div>
            <dt>Proof ID</dt>
            <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all', textAlign: 'right' }}>{shortHash(statementIdentity.proofId || proofIdInput || revocationProofId || '')}</dd>
          </div>
          <div>
            <dt>Chain Status</dt>
            <dd>{offline ? 'Not checked (offline)' : chainProof ? (chainProof.status === 2 ? 'Revoked' : chainProof.status === 3 ? 'Expired' : 'Confirmed') : 'Not loaded'}</dd>
          </div>
          <div>
            <dt>Wallet</dt>
            <dd>{wallet ? `${wallet.slice(0, 5)}…${wallet.slice(-4)}` : 'Not connected'}</dd>
          </div>
        </dl>

        <div style={{ marginTop: '1rem' }}>
          <button
            type="button"
            className="hero-secondary"
            aria-expanded={showComparison}
            onClick={() => setShowComparison((prev) => !prev)}
          >
            <ArrowLeftRight size={14} aria-hidden="true" />
            <span>{showComparison ? 'Hide receipt comparison' : 'Compare two receipts'}</span>
          </button>
          {showComparison ? (
            <ReceiptComparisonView
              initialLeft={initialComparison?.left ?? null}
              initialRight={initialComparison?.right ?? null}
            />
          ) : null}
        </div>
      </div>

      <aside className="side-rail">
        <div className="rail-block">
          <h3>Chain Registry</h3>
          {offline ? (
            <p className="muted" style={{ fontSize: 11 }} role="status">
              On-chain status was not checked in offline mode. No trust decision was made.
            </p>
          ) : (
            <>
              <ChainProofPanel
                chainProof={chainProof}
                proofId={revocationProofId}
                sourceAddress={wallet || undefined}
                issuerTrust={issuerTrust}
              />
              <DisputePanel
                proofId={revocationProofId}
                wallet={wallet}
                networkMismatch={networkMismatch}
                offline={offline}
                chainProof={chainProof}
              />
              <h4 style={{ marginTop: '1rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Verifier Set Status</h4>
              <VerifierSetStatusPanel />
            </>
          )}
          {provenanceRecord ? <ProvenanceCard provenance={provenanceRecord} /> : null}
        </div>

        <div className="rail-block">
          <h3>Events</h3>
          {offline ? (
            <p className="muted" style={{ fontSize: 11 }} role="status">
              NeonDB events were not queried in offline mode.
            </p>
          ) : (
            <EventList events={events} onRefresh={() => void loadEvents()} />
          )}
        </div>
      </aside>
    </section>
  )
}
