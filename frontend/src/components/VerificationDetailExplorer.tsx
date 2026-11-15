import React, { useId, useMemo, useRef, useState } from 'react'
import {
  buildVerificationDetailExplorerModel,
  type VerificationDetailExplorerInput,
  type VerificationDetailSectionId,
} from '../services/verificationFlow'

export interface VerificationDetailExplorerProps extends VerificationDetailExplorerInput {
  defaultExpanded?: readonly VerificationDetailSectionId[]
}

export function VerificationDetailExplorer({
  status,
  offline,
  verifyHash,
  proofId,
  metadataHash,
  events,
  chainProof,
  errorCode,
  defaultExpanded = ['public-input-checks'],
}: VerificationDetailExplorerProps) {
  const baseId = useId()
  const headingId = `${baseId}-heading`
  const [expandedIds, setExpandedIds] = useState<ReadonlySet<VerificationDetailSectionId>>(
    () => new Set(defaultExpanded),
  )
  const triggerRefs = useRef<Array<HTMLButtonElement | null>>([])

  const model = useMemo(
    () =>
      buildVerificationDetailExplorerModel({
        status,
        offline,
        verifyHash,
        proofId,
        metadataHash,
        events,
        chainProof,
        errorCode,
      }),
    [status, offline, verifyHash, proofId, metadataHash, events, chainProof, errorCode],
  )

  const toggleSection = (sectionId: VerificationDetailSectionId) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(sectionId)) {
        next.delete(sectionId)
      } else {
        next.add(sectionId)
      }
      return next
    })
  }

  const moveFocusToHeader = (index: number) => {
    const count = model.sections.length
    const wrapped = ((index % count) + count) % count
    triggerRefs.current[wrapped]?.focus()
  }

  const handleHeaderKeyDown = (
    event: React.KeyboardEvent<HTMLButtonElement>,
    index: number,
  ) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      moveFocusToHeader(index + 1)
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      moveFocusToHeader(index - 1)
    } else if (event.key === 'Home') {
      event.preventDefault()
      moveFocusToHeader(0)
    } else if (event.key === 'End') {
      event.preventDefault()
      moveFocusToHeader(model.sections.length - 1)
    }
  }

  return (
    <section
      className="verification-detail-explorer"
      aria-labelledby={headingId}
    >
      <h3 id={headingId}>Verification detail explorer</h3>
      {model.sections.map((section, index) => {
        const isExpanded = expandedIds.has(section.id)
        const triggerId = `${baseId}-${section.id}-trigger`
        const panelId = `${baseId}-${section.id}-panel`

        return (
          <div
            key={section.id}
            className={`detail-explorer-section detail-explorer-section--${section.state}`}
          >
            <h4>
              <button
                ref={(el) => {
                  triggerRefs.current[index] = el
                }}
                type="button"
                id={triggerId}
                className="detail-explorer-trigger"
                aria-expanded={isExpanded}
                aria-controls={panelId}
                onClick={() => toggleSection(section.id)}
                onKeyDown={(e) => handleHeaderKeyDown(e, index)}
              >
                <span>{section.heading}</span>
                <span> — {section.summary}</span>
              </button>
            </h4>
            <div
              id={panelId}
              role="region"
              aria-labelledby={triggerId}
              hidden={!isExpanded}
            >
              <dl className="data-list">
                {section.rows.map((row) => (
                  <div key={row.label}>
                    <dt>{row.label}</dt>
                    <dd>{row.value}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
        )
      })}
    </section>
  )
}
