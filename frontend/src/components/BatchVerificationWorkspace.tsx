import { useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  FileCheck,
  FileCode,
  Filter,
  Play,
  RefreshCw,
  Search,
  Sliders,
  StopCircle,
  Trash2,
  Upload,
  XCircle,
} from 'lucide-react'
import {
  BatchVerifier,
  type BatchItemResult,
  type BatchOutcome,
  type BatchPreflightReport,
  type BatchProgress,
  type BatchSummary,
  formatBytes,
} from '../batchVerifier'
import {
  exportBatchCSV,
  exportBatchJSON,
  exportPreflightReportCSV,
  exportPreflightReportJSON,
  exportReceiptCollection,
} from '../batchExport'

type Props = {
  apiBase: string
  contractId: string
  wallet?: string
}

type FilterType = 'all' | 'confirmed' | 'revoked' | 'unconfirmed' | 'duplicate' | 'error' | 'manifest' | 'cancelled'

export default function BatchVerificationWorkspace({ apiBase, contractId, wallet }: Props) {
  const [verifier] = useState(() => new BatchVerifier({ apiBase, contractId, wallet }))
  const [items, setItems] = useState<BatchItemResult[]>([])
  const [preflight, setPreflight] = useState<BatchPreflightReport | null>(null)
  const [progress, setProgress] = useState<BatchProgress | null>(null)
  const [summary, setSummary] = useState<BatchSummary | null>(null)
  const [isRunning, setIsRunning] = useState(false)
  const [selectedFilter, setSelectedFilter] = useState<FilterType>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [detailItem, setDetailItem] = useState<BatchItemResult | null>(null)
  const [showConfig, setShowConfig] = useState(false)
  const [exportPrivacyProfile, setExportPrivacyProfile] = useState<ExportPrivacyProfile>('public')

  // Config settings
  const [concurrency, setConcurrency] = useState(3)
  const [maxFileMb, setMaxFileMb] = useState(100)
  const [maxTotalMb, setMaxTotalMb] = useState(500)

  // File drag state
  const [isDragging, setIsDragging] = useState(false)

  // Ref for programmatic keyboard-triggered file picker
  const batchInputRef = useRef<HTMLInputElement | null>(null)
  const dropzoneRef = useRef<HTMLLabelElement | null>(null)

  const handleFilesAdded = (files: FileList | File[]) => {
    const fileArray = Array.from(files)
    if (fileArray.length === 0) return

    // Update config on verifier
    verifier.updateConfig({
      maxConcurrency: concurrency,
      maxFileSizeBytes: maxFileMb * 1024 * 1024,
      maxTotalSizeBytes: maxTotalMb * 1024 * 1024,
      apiBase,
      contractId,
      wallet,
    })

    // Execute preflight report before expensive verification
    const report = verifier.runPreflight(fileArray)
    setPreflight(report)

    const unsupMap = new Map(report.unsupported.map((u) => [u.index, u]))
    const dupMap = new Map(report.duplicates.map((d) => [d.index, d]))
    const overMap = new Map(report.oversized.map((o) => [o.index, o]))

    const initialItems = fileArray.map((file, idx) => {
      let status: BatchOutcome = 'pending'
      let message = 'Queued for verification.'
      let duplicateOf: string | null = null
      let failureReason: string | null = null

      if (unsupMap.has(idx)) {
        status = 'unsupported'
        message = unsupMap.get(idx)!.reason
        failureReason = message
      } else if (dupMap.has(idx)) {
        status = 'duplicate'
        duplicateOf = dupMap.get(idx)!.duplicateOf
        message = dupMap.get(idx)!.reason
        failureReason = message
      } else if (overMap.has(idx)) {
        status = 'oversized'
        message = overMap.get(idx)!.reason
        failureReason = message
      }

      return {
        id: `item-${idx}-${Date.now()}`,
        file,
        fileName: file.name,
        fileSizeBytes: file.size,
        status,
        videoHash: null,
        metadataHash: null,
        sourceHash: null,
        tier: null,
        chainStatus: null,
        message,
        events: [],
        chainProof: null,
        duplicateOf,
        manifest: null,
        durationMs: null,
        failureReason,
      }
    })

    setItems(initialItems)
    setProgress({
      totalFiles: fileArray.length,
      completedFiles: 0,
      processedBytes: 0,
      totalBytes: report.totalBytes,
      activeCount: 0,
      isCancelled: false,
      isDone: false,
    })
    setSummary(null)
  }

  useEffect(() => {
    const el = dropzoneRef.current
    if (!el) return
    const listener = (e: Event) => {
      const files = (e.target as unknown as { files?: FileList | File[] })?.files || (e as unknown as { files?: FileList | File[] }).files
      if (files && files.length > 0) {
        handleFilesAdded(files)
      }
    }
    el.addEventListener('change', listener)
    return () => el.removeEventListener('change', listener)
  })

  const startBatch = async () => {
    if (items.length === 0 || isRunning) return

    setIsRunning(true)
    const filesToRun = items.map((i) => i.file)

    verifier.updateConfig({
      maxConcurrency: concurrency,
      maxFileSizeBytes: maxFileMb * 1024 * 1024,
      maxTotalSizeBytes: maxTotalMb * 1024 * 1024,
      apiBase,
      contractId,
      wallet,
    })

    try {
      const res = await verifier.runBatch(filesToRun, (prog, currentItems) => {
        setProgress(prog)
        setItems(currentItems)
      })
      setSummary(res.summary)
      setPreflight(res.preflight)
    } finally {
      setIsRunning(false)
    }
  }

  const cancelBatch = () => {
    verifier.cancel()
    setIsRunning(false)
  }

  const clearBatch = () => {
    if (isRunning) cancelBatch()
    setItems([])
    setProgress(null)
    setSummary(null)
    setPreflight(null)
    setDetailItem(null)
  }

  const retryFailed = async () => {
    const failedFiles = items
      .filter((i) => i.status === 'error' || i.status === 'malformed' || i.status === 'cancelled')
      .map((i) => i.file)

    if (failedFiles.length === 0) return

    setIsRunning(true)
    try {
      await verifier.runBatch(failedFiles, (prog, currentItems) => {
        setProgress(prog)
        setItems((prev) => {
          const updatedMap = new Map(currentItems.map((ci) => [ci.fileName, ci]))
          return prev.map((item) => updatedMap.get(item.fileName) || item)
        })
      })
    } finally {
      setIsRunning(false)
    }
  }

  // Filtered Items
  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      // Filter tab check
      if (selectedFilter === 'confirmed' && item.status !== 'confirmed') return false
      if (selectedFilter === 'revoked' && item.status !== 'revoked') return false
      if (
        selectedFilter === 'unconfirmed' &&
        item.status !== 'metadata-only' &&
        item.status !== 'database-only'
      )
        return false
      if (selectedFilter === 'duplicate' && item.status !== 'duplicate') return false
      if (
        selectedFilter === 'error' &&
        item.status !== 'error' &&
        item.status !== 'malformed' &&
        item.status !== 'oversized' &&
        item.status !== 'unsupported'
      )
        return false
      if (selectedFilter === 'manifest' && item.status !== 'manifest-valid') return false
      if (selectedFilter === 'cancelled' && item.status !== 'cancelled') return false

      // Search query check
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const matchName = item.fileName.toLowerCase().includes(q)
        const matchHash = item.videoHash ? item.videoHash.toLowerCase().includes(q) : false
        if (!matchName && !matchHash) return false
      }

      return true
    })
  }, [items, selectedFilter, searchQuery])

  // Download export helper
  const triggerDownload = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const exportJSON = () => triggerDownload(exportBatchJSON(items, preflight), 'harpocrates-batch-report.json', 'application/json')
  const exportCSV = () => triggerDownload(exportBatchCSV(items), 'harpocrates-batch-report.csv', 'text/csv')
  const exportReceipts = () =>
    triggerDownload(exportReceiptCollection(items), 'harpocrates-receipt-collection.json', 'application/json')
  const exportPreflightJSON = () =>
    preflight && triggerDownload(exportPreflightReportJSON(preflight), 'harpocrates-preflight-report.json', 'application/json')
  const exportPreflightCSV = () =>
    preflight && triggerDownload(exportPreflightReportCSV(preflight), 'harpocrates-preflight-report.csv', 'text/csv')

  const announcementText = useMemo(() => {
    if (!progress) return 'Workspace idle.'
    if (progress.isCancelled) return 'Batch verification cancelled.'
    if (progress.isDone) return `Batch complete. Processed ${progress.completedFiles} files.`
    return `Processing batch: ${progress.completedFiles} of ${progress.totalFiles} files verified.`
  }, [progress])

  return (
    <div className="batch-workspace" role="region" aria-label="Evidence Batch Verification Workspace">
      <div className="sr-only" aria-live="polite">
        {announcementText}
      </div>

      <header className="page-header">
        <div>
          <h2>Evidence Batch Verification Workspace</h2>
          <p>Verify large volumes of evidence with bounded browser memory, cancellation, and duplicate detection.</p>
        </div>
        <button
          className={`icon-button ${showConfig ? 'active' : ''}`}
          type="button"
          onClick={() => setShowConfig(!showConfig)}
          title="Toggle Pool Settings"
          aria-expanded={showConfig}
        >
          <Sliders size={18} aria-hidden="true" />
          <span>Pool Settings</span>
        </button>
      </header>

      {/* Config Settings Panel */}
      {showConfig ? (
        <section className="config-card" aria-label="Worker pool settings">
          <div className="config-grid">
            <label className="config-field">
              <span>Concurrency (Workers: 1-8)</span>
              <input
                type="number"
                min={1}
                max={8}
                value={concurrency}
                onChange={(e) => setConcurrency(Math.max(1, Math.min(8, Number(e.target.value))))}
                disabled={isRunning}
              />
            </label>
            <label className="config-field">
              <span>Max Per-File Limit (MB)</span>
              <input
                type="number"
                min={1}
                max={500}
                value={maxFileMb}
                onChange={(e) => setMaxFileMb(Math.max(1, Number(e.target.value)))}
                disabled={isRunning}
              />
            </label>
            <label className="config-field">
              <span>Max Total Batch Limit (MB)</span>
              <input
                type="number"
                min={10}
                max={2000}
                value={maxTotalMb}
                onChange={(e) => setMaxTotalMb(Math.max(10, Number(e.target.value)))}
                disabled={isRunning}
              />
            </label>
          </div>
          <p className="config-hint">
            Workers operate within memory-bounded 4MB slices. Media content is cleared immediately after hashing.
          </p>
        </section>
      ) : null}

      {/* Dropzone & Actions Bar */}
      <section className="batch-actions-panel">
        {/* Keyboard: Tab focuses label, Enter/Space opens file picker. Drag-and-drop also supported. */}
        {/* The input is a sibling, not a descendant: an interactive control nested in role="button" is a WCAG 4.1.2 violation. */}
        <label
          ref={dropzoneRef}
          className={`batch-dropzone ${isDragging ? 'dragging' : ''} ${items.length > 0 ? 'compact' : ''}`}
          role="button"
          tabIndex={isRunning ? -1 : 0}
          aria-label="Drop evidence files or standalone JSON receipts. Press Enter or Space to open file picker"
          aria-disabled={isRunning}
          htmlFor="batch-evidence-input"
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ' ') && !isRunning) {
              e.preventDefault()
              batchInputRef.current?.click()
            }
          }}
          onDragOver={(e) => {
            e.preventDefault()
            setIsDragging(true)
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e) => {
            e.preventDefault()
            setIsDragging(false)
            if (e.dataTransfer.files) handleFilesAdded(e.dataTransfer.files)
          }}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
            if (e.target.files) handleFilesAdded(e.target.files)
          }}
        >
          <Upload size={24} aria-hidden="true" />
          <div aria-hidden="true">
            <strong>Drop evidence files or standalone JSON receipts</strong>
            <span>Supports MP4, MOV, WEBM, and .json proof manifests</span>
          </div>
        </label>
        <input
          ref={batchInputRef}
          id="batch-evidence-input"
          type="file"
          multiple
          accept="video/*,.json,application/json"
          tabIndex={-1}
          aria-hidden="true"
          onChange={(e) => {
            if (e.target.files) handleFilesAdded(e.target.files)
          }}
          disabled={isRunning}
        />

        {items.length > 0 ? (
          <div className="controls-row">
            {!isRunning ? (
              <button className="hero-primary" type="button" onClick={() => void startBatch()}>
                <Play size={16} aria-hidden="true" />
                <span>Verify Batch ({items.length})</span>
              </button>
            ) : (
              <button className="hero-secondary danger" type="button" onClick={cancelBatch}>
                <StopCircle size={16} aria-hidden="true" />
                <span>Cancel Processing</span>
              </button>
            )}

            <button
              className="icon-button"
              type="button"
              onClick={retryFailed}
              disabled={isRunning || !items.some((i) => i.status === 'error' || i.status === 'malformed')}
              title="Retry Failed Items"
            >
              <RefreshCw size={16} aria-hidden="true" />
              <span>Retry Failed</span>
            </button>

            <button className="icon-button" type="button" onClick={clearBatch} disabled={isRunning} title="Clear Batch">
              <Trash2 size={16} aria-hidden="true" />
              <span>Clear Workspace</span>
            </button>

            <div className="export-group">
              <label className="export-privacy-selector" htmlFor="batch-export-privacy-profile">
                <span className="sr-only">Export privacy profile</span>
                <select
                  id="batch-export-privacy-profile"
                  aria-label="Export privacy profile"
                  value={exportPrivacyProfile}
                  onChange={(e) => setExportPrivacyProfile(e.target.value as ExportPrivacyProfile)}
                  disabled={items.length === 0 || isRunning}
                  title={EXPORT_PRIVACY_PROFILES[exportPrivacyProfile].description}
                >
                  <option value="public">{EXPORT_PRIVACY_PROFILES.public.label}</option>
                  <option value="owner-only">{EXPORT_PRIVACY_PROFILES['owner-only'].label}</option>
                </select>
              </label>
              <button
                className="icon-button secondary"
                type="button"
                onClick={exportJSON}
                disabled={items.length === 0 || isRunning}
                title={`Export JSON Report (${EXPORT_PRIVACY_PROFILES[exportPrivacyProfile].label})`}
              >
                <Download size={16} aria-hidden="true" />
                <span>JSON</span>
              </button>
              <button
                className="icon-button secondary"
                type="button"
                onClick={exportCSV}
                disabled={items.length === 0 || isRunning}
                title={`Export CSV Report (${EXPORT_PRIVACY_PROFILES[exportPrivacyProfile].label})`}
              >
                <Download size={16} aria-hidden="true" />
                <span>CSV</span>
              </button>
              <button
                className="icon-button secondary"
                type="button"
                onClick={exportReceipts}
                disabled={items.length === 0 || isRunning}
                title="Export Receipt Collection"
              >
                <FileCheck size={16} aria-hidden="true" />
                <span>Receipts</span>
              </button>
              {preflight ? (
                <>
                  <button
                    className="icon-button secondary"
                    type="button"
                    onClick={exportPreflightJSON}
                    disabled={isRunning}
                    title="Export Preflight JSON"
                  >
                    <Download size={16} aria-hidden="true" />
                    <span>Preflight JSON</span>
                  </button>
                  <button
                    className="icon-button secondary"
                    type="button"
                    onClick={exportPreflightCSV}
                    disabled={isRunning}
                    title="Export Preflight CSV"
                  >
                    <Download size={16} aria-hidden="true" />
                    <span>Preflight CSV</span>
                  </button>
                </>
              ) : null}
            </div>
          </div>
        ) : null}
      </section>

      {/* Batch Preflight Report Section */}
      {preflight ? (
        <section
          className="preflight-report-panel"
          aria-label="Batch Preflight Report"
          style={{
            margin: '1.25rem 0',
            padding: '1.25rem',
            borderRadius: '8px',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            background: 'rgba(255, 255, 255, 0.03)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: '1rem',
              flexWrap: 'wrap',
              gap: '0.75rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FileCheck
                size={20}
                aria-hidden="true"
                style={{ color: preflight.hasIssues ? '#f59e0b' : '#10b981' }}
              />
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Batch Preflight Report</h3>
            </div>
            <span
              style={{
                fontSize: '0.85rem',
                padding: '0.2rem 0.6rem',
                borderRadius: '4px',
                background: preflight.hasIssues ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                color: preflight.hasIssues ? '#f59e0b' : '#10b981',
                fontWeight: 500,
              }}
            >
              {preflight.hasIssues ? 'Issues Detected' : 'Preflight Passed'}
            </span>
          </div>

          <div
            className="metrics-banner"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
              gap: '0.75rem',
              margin: '0.5rem 0 1rem',
            }}
          >
            <div className="metric-card">
              <span>Total Bytes</span>
              <strong>{formatBytes(preflight.totalBytes)}</strong>
            </div>
            <div className="metric-card">
              <span>Total Inputs</span>
              <strong>{preflight.totalFiles}</strong>
            </div>
            <div className={`metric-card ${preflight.duplicateCount > 0 ? 'purple' : ''}`}>
              <span>Duplicate Inputs</span>
              <strong>{preflight.duplicateCount}</strong>
            </div>
            <div className={`metric-card ${preflight.unsupportedCount > 0 ? 'danger' : ''}`}>
              <span>Unsupported Formats</span>
              <strong>{preflight.unsupportedCount}</strong>
            </div>
            <div className="metric-card success">
              <span>Valid to Verify</span>
              <strong>{preflight.validCount}</strong>
            </div>
          </div>

          {preflight.hasIssues ? (
            <div
              className="preflight-alert"
              role="alert"
              style={{
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                color: '#f59e0b',
                fontSize: '0.9rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                <AlertTriangle size={16} aria-hidden="true" />
                <strong>Preflight Notice:</strong>
                <span>
                  {preflight.duplicateCount > 0 && `${preflight.duplicateCount} duplicate input(s) `}
                  {preflight.duplicateCount > 0 && preflight.unsupportedCount > 0 && 'and '}
                  {preflight.unsupportedCount > 0 && `${preflight.unsupportedCount} unsupported format(s) `}
                  detected. No hashing or proving will occur on these items.
                </span>
              </div>
              <ul style={{ margin: '0.35rem 0 0 1.5rem', padding: 0, fontSize: '0.85rem' }}>
                {preflight.unsupported.map((u) => (
                  <li key={u.fileName}>
                    <code>{u.fileName}</code> ({formatBytes(u.fileSizeBytes)}): {u.reason}
                  </li>
                ))}
                {preflight.duplicates.map((d) => (
                  <li key={d.fileName}>
                    <code>{d.fileName}</code> ({formatBytes(d.fileSizeBytes)}): {d.reason}
                  </li>
                ))}
                {preflight.oversized.map((o) => (
                  <li key={o.fileName}>
                    <code>{o.fileName}</code> ({formatBytes(o.fileSizeBytes)}): {o.reason}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: '#10b981' }}>
              ✓ All {preflight.totalFiles} inputs passed preflight format and uniqueness checks ({formatBytes(preflight.totalBytes)}). Ready for verification.
            </p>
          )}
        </section>
      ) : null}

      {/* Aggregate Metrics Bar */}
      {progress ? (
        <section className="metrics-banner" aria-label="Batch progress metrics">
          <div className="metric-card">
            <span>Total Files</span>
            <strong>{progress.totalFiles}</strong>
          </div>
          <div className="metric-card success">
            <span>Confirmed</span>
            <strong>{summary?.confirmed ?? items.filter((i) => i.status === 'confirmed').length}</strong>
          </div>
          <div className="metric-card danger">
            <span>Revoked</span>
            <strong>{summary?.revoked ?? items.filter((i) => i.status === 'revoked').length}</strong>
          </div>
          <div className="metric-card warning">
            <span>Unconfirmed</span>
            <strong>{summary?.unconfirmed ?? items.filter((i) => i.status === 'metadata-only' || i.status === 'database-only').length}</strong>
          </div>
          <div className="metric-card purple">
            <span>Duplicates</span>
            <strong>{summary?.duplicates ?? items.filter((i) => i.status === 'duplicate').length}</strong>
          </div>
          <div className="metric-card error">
            <span>Errors/Oversized</span>
            <strong>{summary?.errors ?? items.filter((i) => i.status === 'error' || i.status === 'malformed' || i.status === 'oversized').length}</strong>
          </div>

          <div className="progress-bar-wrapper">
            <div className="progress-label">
              <span>{isRunning ? `Processing (${progress.completedFiles}/${progress.totalFiles})` : 'Batch Finished'}</span>
              <span>{Math.round((progress.completedFiles / progress.totalFiles) * 100)}%</span>
            </div>
            <progress
              value={progress.completedFiles}
              max={progress.totalFiles}
              aria-label="Batch verification progress"
            />
          </div>
        </section>
      ) : null}

      {/* Filter and Search Controls */}
      {items.length > 0 ? (
        <section className="table-controls-bar">
          <div className="filter-tabs" role="group" aria-label="Filter results">
            <button
              className={`tab-btn ${selectedFilter === 'all' ? 'active' : ''}`}
              type="button"
              onClick={() => setSelectedFilter('all')}
            >
              All ({items.length})
            </button>
            <button
              className={`tab-btn ${selectedFilter === 'confirmed' ? 'active' : ''}`}
              type="button"
              onClick={() => setSelectedFilter('confirmed')}
            >
              Confirmed ({items.filter((i) => i.status === 'confirmed').length})
            </button>
            <button
              className={`tab-btn ${selectedFilter === 'revoked' ? 'active' : ''}`}
              type="button"
              onClick={() => setSelectedFilter('revoked')}
            >
              Revoked ({items.filter((i) => i.status === 'revoked').length})
            </button>
            <button
              className={`tab-btn ${selectedFilter === 'unconfirmed' ? 'active' : ''}`}
              type="button"
              onClick={() => setSelectedFilter('unconfirmed')}
            >
              Unconfirmed ({items.filter((i) => i.status === 'metadata-only' || i.status === 'database-only').length})
            </button>
            <button
              className={`tab-btn ${selectedFilter === 'duplicate' ? 'active' : ''}`}
              type="button"
              onClick={() => setSelectedFilter('duplicate')}
            >
              Duplicates ({items.filter((i) => i.status === 'duplicate').length})
            </button>
            <button
              className={`tab-btn ${selectedFilter === 'error' ? 'active' : ''}`}
              type="button"
              onClick={() => setSelectedFilter('error')}
            >
              Errors ({items.filter((i) => i.status === 'error' || i.status === 'malformed' || i.status === 'oversized' || i.status === 'unsupported').length})
            </button>
          </div>

          <div className="search-box">
            <Search size={16} aria-hidden="true" />
            <input
              type="text"
              placeholder="Search filename or hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search results by filename or hash"
            />
          </div>
        </section>
      ) : null}

      {/* Results Table */}
      {filteredItems.length > 0 ? (
        <div className="table-responsive">
          <table className="batch-table" aria-label="Batch verification results table">
            <thead>
              <tr>
                <th scope="col">Status</th>
                <th scope="col">File Name</th>
                <th scope="col">Size</th>
                <th scope="col">Commitment / Hash</th>
                <th scope="col">Message / Outcome</th>
                <th scope="col">Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredItems.map((item) => (
                <tr key={item.id} className={`status-row ${item.status}`}>
                  <td>
                    <StatusBadge status={item.status} />
                  </td>
                  <td>
                    <span className="file-name-cell" title={item.fileName}>
                      {item.fileName}
                    </span>
                  </td>
                  <td className="muted">{(item.fileSizeBytes / (1024 * 1024)).toFixed(2)} MB</td>
                  <td>
                    <code className="hash-code">
                      {item.videoHash ? `${item.videoHash.slice(0, 10)}...${item.videoHash.slice(-8)}` : '—'}
                    </code>
                  </td>
                  <td className="message-cell">{item.message}</td>
                  <td>
                    <button
                      className="table-action-btn"
                      type="button"
                      onClick={() => setDetailItem(item)}
                      title="View Details"
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : items.length > 0 ? (
        <div className="empty-filter-state">
          <Filter size={24} aria-hidden="true" />
          <p>No batch items match the selected filter or search query.</p>
        </div>
      ) : null}

      {/* Item Detail Modal / Drawer */}
      {detailItem ? (
        <div className="modal-backdrop" onClick={() => setDetailItem(null)} role="dialog" aria-modal="true">
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <header className="modal-header">
              <h3>{detailItem.fileName}</h3>
              <button className="icon-button" type="button" onClick={() => setDetailItem(null)}>
                <XCircle size={18} aria-hidden="true" />
              </button>
            </header>
            <div className="modal-body">
              <dl className="detail-list">
                <div>
                  <dt>Status</dt>
                  <dd>
                    <StatusBadge status={detailItem.status} />
                  </dd>
                </div>
                <div>
                  <dt>File Size</dt>
                  <dd>{(detailItem.fileSizeBytes / (1024 * 1024)).toFixed(2)} MB ({detailItem.fileSizeBytes} bytes)</dd>
                </div>
                <div>
                  <dt>Video Hash Commitment</dt>
                  <dd>
                    <code>{detailItem.videoHash || 'Not generated'}</code>
                  </dd>
                </div>
                {detailItem.metadataHash ? (
                  <div>
                    <dt>Metadata Hash</dt>
                    <dd>
                      <code>{detailItem.metadataHash}</code>
                    </dd>
                  </div>
                ) : null}
                {detailItem.tier ? (
                  <div>
                    <dt>Identity Tier</dt>
                    <dd>{detailItem.tier}</dd>
                  </div>
                ) : null}
                {detailItem.duplicateOf ? (
                  <div>
                    <dt>Duplicate Of</dt>
                    <dd>{detailItem.duplicateOf}</dd>
                  </div>
                ) : null}
                <div>
                  <dt>Explanation</dt>
                  <dd>{detailItem.message}</dd>
                </div>
                {detailItem.failureReason ? (
                  <div className="failure-box">
                    <dt>Failure Reason</dt>
                    <dd>{detailItem.failureReason}</dd>
                  </div>
                ) : null}
              </dl>

              {detailItem.chainProof ? (
                <div className="modal-section">
                  <h4>Soroban Chain Registry Record</h4>
                  <pre>{JSON.stringify(detailItem.chainProof, null, 2)}</pre>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}

function StatusBadge({ status }: { status: BatchOutcome }) {
  switch (status) {
    case 'confirmed':
      return (
        <span className="badge badge-confirmed">
          <CheckCircle2 size={12} aria-hidden="true" /> Confirmed
        </span>
      )
    case 'revoked':
      return (
        <span className="badge badge-revoked">
          <XCircle size={12} aria-hidden="true" /> Revoked
        </span>
      )
    case 'metadata-only':
    case 'database-only':
      return (
        <span className="badge badge-unconfirmed">
          <AlertTriangle size={12} aria-hidden="true" /> Unconfirmed
        </span>
      )
    case 'manifest-valid':
      return (
        <span className="badge badge-manifest">
          <FileCode size={12} aria-hidden="true" /> Manifest Valid
        </span>
      )
    case 'duplicate':
      return (
        <span className="badge badge-duplicate">
          <Copy size={12} aria-hidden="true" /> Duplicate
        </span>
      )
    case 'unsupported':
      return (
        <span className="badge badge-error">
          <AlertCircle size={12} aria-hidden="true" /> Unsupported
        </span>
      )
    case 'oversized':
    case 'malformed':
    case 'manifest-invalid':
    case 'error':
      return (
        <span className="badge badge-error">
          <AlertCircle size={12} aria-hidden="true" /> {status}
        </span>
      )
    case 'cancelled':
      return (
        <span className="badge badge-cancelled">
          <StopCircle size={12} aria-hidden="true" /> Cancelled
        </span>
      )
    case 'hashing':
    case 'processing':
      return (
        <span className="badge badge-processing">
          <RefreshCw size={12} className="spin" aria-hidden="true" /> {status}
        </span>
      )
    default:
      return <span className="badge badge-pending">Pending</span>
  }
}
