import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ExportPrivacySummary } from './ExportPrivacySummary'
import { buildExportPrivacySummary } from '../exportPrivacySummary'
import type { ProofPackage } from '../types'

const baseProof: ProofPackage = {
  fileName: 'harpocrates-synthetic.mp4',
  sourceHash: 'a'.repeat(64),
  videoHash: 'b'.repeat(64),
  metadataHash: 'c'.repeat(64),
  proofId: 'd'.repeat(64),
  timestamp: '2026-01-01T00:00:00.000Z',
  tier: 'silent',
}

describe('ExportPrivacySummary', () => {
  it('renders metadata classes and public identifiers without an acknowledgement checkbox when no sensitive fields are newly exposed', () => {
    const summary = buildExportPrivacySummary({ proof: baseProof })
    render(<ExportPrivacySummary summary={summary} />)

    const region = screen.getByRole('region', { name: 'Export privacy summary' })
    expect(region).toHaveTextContent('Ready to export')
    expect(region).toHaveTextContent('Container & file metadata')
    expect(region).toHaveTextContent('Cryptographic digests')
    expect(region).toHaveTextContent('Proof ID')
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })

  it('requires explicit acknowledgement for newly exposed sensitive fields and invokes callback on check', async () => {
    const user = userEvent.setup()
    const onAck = vi.fn()
    const summary = buildExportPrivacySummary({
      proof: { ...baseProof, tier: 'source' },
      wallet: 'GSOURCEACCOUNT1234567890',
    })

    render(<ExportPrivacySummary summary={summary} onAcknowledgeSensitiveFields={onAck} />)

    expect(screen.getByText('Acknowledgement required')).toBeInTheDocument()
    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).not.toBeChecked()

    await user.click(checkbox)
    expect(onAck).toHaveBeenCalledTimes(1)
    expect(onAck).toHaveBeenCalledWith(['publicIdentity'])
  })

  it('renders empty and fail-closed error states', () => {
    const { rerender } = render(
      <ExportPrivacySummary summary={buildExportPrivacySummary({ proof: null })} />,
    )
    expect(screen.getByRole('status')).toHaveTextContent(
      'Generate evidence to review included metadata before exporting.',
    )

    rerender(
      <ExportPrivacySummary
        summary={buildExportPrivacySummary({
          proof: { ...baseProof, tier: 'invalid' as unknown as ProofPackage['tier'] },
        })}
      />,
    )
    const alert = screen.getByRole('alert')
    expect(alert).toHaveAttribute('data-error-code', 'UNSUPPORTED_TIER')
  })
})
