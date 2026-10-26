import React, { useCallback, useEffect, useMemo, useState, useRef } from 'react'
import { Copy, Check, Loader2, AlertCircle, RefreshCw } from 'lucide-react'
import { getIssuerRecord, getIssuerRotation, isIssuerVerifiable } from '../harpocratesRegistry'
import { IssuerTrustBadge } from '../provenance/IssuerTrustBadge'
import { resolveIssuerTrust, type IssuerTrust } from '../provenance/issuerTrust'
import { VirtualizedList } from '../lib/virtualized-list'
import type { LineageNode, VirtualizationConfig } from '../types/lineage'
import type { IssuerDirectoryEntry } from '../types/issuerDirectory'
import { appConfig } from '../config'
import './IssuersView.css'

interface IssuersViewProps {
  contractId?: string
  apiBase?: string
}

const VIRTUALIZATION_THRESHOLD = 50
const ROW_HEIGHT = 68
const CONTAINER_HEIGHT = 500

const VIRT_CONFIG: VirtualizationConfig = {
  containerHeight: CONTAINER_HEIGHT,
  itemHeight: ROW_HEIGHT,
  overscanCount: 5,
  threshold: VIRTUALIZATION_THRESHOLD,
}

export function IssuersView({
  contractId = appConfig.harpocratesRegistryId,
  apiBase = appConfig.apiBase,
}: IssuersViewProps) {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [issuers, setIssuers] = useState<IssuerDirectoryEntry[]>([])
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [filterQuery, setFilterQuery] = useState('')
  const [scrollTop, setScrollTop] = useState(0)

  const copyTimeoutRef = useRef<number | null>(null)

  const handleCopy = useCallback((text: string, key: string) => {
    if (copyTimeoutRef.current) {
      window.clearTimeout(copyTimeoutRef.current)
    }
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text).catch(() => {})
    }
    setCopiedKey(key)
    copyTimeoutRef.current = window.setTimeout(() => {
      setCopiedKey(null)
    }, 2000)
  }, [])

  const loadIssuers = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      let addresses: string[] = []

      const envIssuers =
        import.meta.env.VITE_KNOWN_ISSUERS ||
        import.meta.env.VITE_ISSUERS ||
        ''

      if (envIssuers) {
        addresses = envIssuers
          .split(/[\s,]+/)
          .map((s: string) => s.trim())
          .filter(Boolean)
      } else if (apiBase) {
        try {
          const res = await fetch(`${apiBase}/v1/issuers`, {
            headers: { Accept: 'application/json' },
          })
          if (res.ok) {
            const data = await res.json()
            if (Array.isArray(data)) {
              addresses = data
                .map((item: any) => (typeof item === 'string' ? item : item?.address || item?.issuer || ''))
                .filter(Boolean)
            } else if (Array.isArray(data?.issuers)) {
              addresses = data.issuers
                .map((item: any) => (typeof item === 'string' ? item : item?.address || item?.issuer || ''))
                .filter(Boolean)
            }
          }
        } catch {
          // Backend fetch is best effort
        }
      }

      addresses = Array.from(new Set(addresses))

      const entries: IssuerDirectoryEntry[] = await Promise.all(
        addresses.map(async (address): Promise<IssuerDirectoryEntry> => {
          let record = null
          let rotation = null
          let isVerifiable = false

          if (contractId) {
            const [recRes, rotRes, verRes] = await Promise.allSettled([
              getIssuerRecord(contractId, address),
              getIssuerRotation(contractId, address),
              isIssuerVerifiable(contractId, address),
            ])

            if (recRes.status === 'rejected') {
              throw recRes.reason
            }
            if (rotRes.status === 'rejected') {
              throw rotRes.reason
            }
            if (verRes.status === 'rejected') {
              throw verRes.reason
            }

            record = recRes.value
            rotation = rotRes.value
            isVerifiable = verRes.value
          }

          const trustState: IssuerTrust = resolveIssuerTrust({
            issuer: address,
            lookup: record
              ? { kind: record.active ? 'active' : 'inactive' }
              : { kind: 'missing' },
          })

          let issuerState: 'active' | 'rotating' | 'revoked' = 'revoked'
          if (record?.active) {
            issuerState = 'active'
          } else if (rotation && isVerifiable) {
            issuerState = 'rotating'
          } else if (rotation) {
            issuerState = 'revoked'
          } else if (record && !record.active) {
            issuerState = 'revoked'
          }

          let graceWindowEnd: string | null = null
          if (rotation?.graceExpiresAt) {
            graceWindowEnd = new Date(rotation.graceExpiresAt * 1000).toISOString()
          }

          return {
            address,
            metadataHash: record?.metadataHash ?? null,
            active: Boolean(record?.active),
            isVerifiable,
            rotation,
            issuerState,
            trustState: trustState.state,
            graceWindowEnd,
          }
        })
      )

      setIssuers(entries)
    } catch (err: any) {
      setError(err?.message || 'Failed to load issuers directory')
    } finally {
      setLoading(false)
    }
  }, [contractId, apiBase])

  useEffect(() => {
    loadIssuers()
    return () => {
      if (copyTimeoutRef.current) {
        window.clearTimeout(copyTimeoutRef.current)
      }
    }
  }, [loadIssuers])

  const filteredIssuers = useMemo(() => {
    if (!filterQuery.trim()) return issuers
    const q = filterQuery.toLowerCase()
    return issuers.filter(
      (entry) =>
        entry.address.toLowerCase().includes(q) ||
        (entry.metadataHash && entry.metadataHash.toLowerCase().includes(q)) ||
        entry.issuerState.toLowerCase().includes(q)
    )
  }, [issuers, filterQuery])

  // Virtualization adapter
  const pseudoNodes: LineageNode[] = useMemo(() => {
    return filteredIssuers.map((item, idx) => ({
      id: item.address,
      type: 'contract' as const,
      label: item.address,
      metadata: item,
      timestamp: idx,
      status: item.active ? 'active' : 'revoked',
      childrenIds: [],
    }))
  }, [filteredIssuers])

  const virtualized = useMemo(() => {
    const vlist = new VirtualizedList(VIRT_CONFIG, pseudoNodes)
    vlist.updateScroll(scrollTop)
    return vlist
  }, [pseudoNodes, scrollTop])

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop)
  }

  const renderRow = (item: IssuerDirectoryEntry) => {
    const trust: IssuerTrust = resolveIssuerTrust({
      issuer: item.address,
      lookup: item.active ? { kind: 'active' } : { kind: 'inactive' },
    })

    const shortAddress = `${item.address.slice(0, 6)}...${item.address.slice(-6)}`
    const shortHash = item.metadataHash
      ? `${item.metadataHash.slice(0, 8)}...${item.metadataHash.slice(-8)}`
      : 'None'

    const addrCopyKey = `addr-${item.address}`
    const hashCopyKey = `hash-${item.address}`

    return (
      <tr key={item.address} data-testid={`issuer-row-${item.address}`}>
        <td>
          <div className="issuer-cell-with-copy">
            <span className="issuer-code" title={item.address}>
              {shortAddress}
            </span>
            <button
              type="button"
              className="issuer-copy-btn"
              onClick={() => handleCopy(item.address, addrCopyKey)}
              aria-label={`Copy address for ${item.address}`}
              title="Copy address"
            >
              {copiedKey === addrCopyKey ? (
                <Check size={14} aria-hidden="true" />
              ) : (
                <Copy size={14} aria-hidden="true" />
              )}
            </button>
          </div>
        </td>
        <td>
          <span className={`issuer-state-pill ${item.issuerState}`}>
            {item.issuerState}
          </span>
        </td>
        <td>
          <IssuerTrustBadge trust={trust} showIssuer={false} />
        </td>
        <td>
          <div className="issuer-cell-with-copy">
            <span className="issuer-code" title={item.metadataHash || ''}>
              {shortHash}
            </span>
            {item.metadataHash && (
              <button
                type="button"
                className="issuer-copy-btn"
                onClick={() => handleCopy(item.metadataHash!, hashCopyKey)}
                aria-label={`Copy metadata hash for ${item.address}`}
                title="Copy metadata hash"
              >
                {copiedKey === hashCopyKey ? (
                  <Check size={14} aria-hidden="true" />
                ) : (
                  <Copy size={14} aria-hidden="true" />
                )}
              </button>
            )}
          </div>
        </td>
        <td>
          <span className="issuer-grace">
            {item.graceWindowEnd ? new Date(item.graceWindowEnd).toLocaleDateString() : '—'}
          </span>
        </td>
      </tr>
    )
  }

  return (
    <section
      className="issuers-view workspace app-page"
      aria-labelledby="issuers-heading"
      aria-busy={loading}
    >
      <div className="issuers-header">
        <h2 id="issuers-heading" tabIndex={-1}>
          Issuer Directory
        </h2>
        <p>Browse institutional issuers, trust status, rotation grace windows, and metadata.</p>
      </div>

      <div role="status" aria-live="polite" className="sr-only">
        {copiedKey ? 'Copied to clipboard' : ''}
      </div>

      {loading && (
        <div className="issuers-status-box issuers-loading" role="status" aria-label="Loading issuer directory">
          <Loader2 size={32} className="issuers-spinner" aria-hidden="true" />
          <p>Loading issuer directory…</p>
        </div>
      )}

      {!loading && error && (
        <div className="issuers-status-box issuers-error" role="alert">
          <AlertCircle size={32} aria-hidden="true" style={{ marginBottom: '0.5rem' }} />
          <p>{error}</p>
          <button
            type="button"
            className="issuers-retry-btn"
            onClick={loadIssuers}
          >
            <RefreshCw size={14} aria-hidden="true" style={{ marginRight: '0.4rem', verticalAlign: 'middle' }} />
            Retry
          </button>
        </div>
      )}

      {!loading && !error && issuers.length === 0 && (
        <div className="issuers-status-box issuers-empty" role="region" aria-label="Empty issuers directory">
          <p>No issuers configured.</p>
        </div>
      )}

      {!loading && !error && issuers.length > 0 && (
        <>
          <div className="issuers-controls">
            <input
              type="search"
              aria-label="Filter issuers"
              placeholder="Filter by address, metadata hash, or state…"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              className="issuers-search-input"
            />
            <div className="issuers-count">
              Showing {filteredIssuers.length} of {issuers.length} issuers
            </div>
          </div>

          <div
            className={`issuers-table-container ${virtualized.shouldVirtualize ? 'issuers-virtual-scroll' : ''}`}
            style={virtualized.shouldVirtualize ? { height: `${CONTAINER_HEIGHT}px` } : undefined}
            onScroll={virtualized.shouldVirtualize ? handleScroll : undefined}
          >
            <table className="issuers-table" aria-label="Issuers directory">
              <thead>
                <tr>
                  <th scope="col">Issuer Address</th>
                  <th scope="col">Status</th>
                  <th scope="col">Trust Standing</th>
                  <th scope="col">Metadata Hash</th>
                  <th scope="col">Grace Window End</th>
                </tr>
              </thead>
              <tbody>
                {virtualized.shouldVirtualize ? (
                  <>
                    <tr style={{ height: `${virtualized.offsetY}px` }} aria-hidden="true">
                      <td colSpan={5} style={{ padding: 0, border: 0 }} />
                    </tr>
                    {virtualized.visibleItems.map((node) => {
                      const entry = filteredIssuers.find((i) => i.address === node.id)
                      return entry ? renderRow(entry) : null
                    })}
                    <tr
                      style={{
                        height: `${Math.max(
                          0,
                          virtualized.totalHeight - virtualized.offsetY - virtualized.visibleItems.length * ROW_HEIGHT
                        )}px`,
                      }}
                      aria-hidden="true"
                    >
                      <td colSpan={5} style={{ padding: 0, border: 0 }} />
                    </tr>
                  </>
                ) : (
                  filteredIssuers.map(renderRow)
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  )
}
export default IssuersView
