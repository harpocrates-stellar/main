import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import VerificationTimeline from './VerificationTimeline'

const baseProps = {
  verifyHash: '',
  events: [],
  chainProof: null,
  errorCode: null,
} as const

describe('VerificationTimeline', () => {
  it('shows the initial pending path without exposing evidence values', () => {
    render(<VerificationTimeline {...baseProps} status="idle" />)

    expect(screen.getByRole('heading', { name: 'Verification timeline' })).toBeInTheDocument()
    expect(screen.getAllByText('Pending')).toHaveLength(5)
    expect(screen.getByText('No raw evidence')).toBeInTheDocument()
  })

  it('shows completed corroboration stages for a successful verification', () => {
    render(
      <VerificationTimeline
        status="success"
        verifyHash={'a'.repeat(64)}
        events={[{
          id: 1,
          event_type: 'registered',
          file_name: null,
          video_hash: null,
          proof_id: null,
          tier: 'silent',
          created_at: '2026-01-01T00:00:00Z',
        }]}
        chainProof={{
          videoHash: 'b'.repeat(64),
          metadataHash: 'c'.repeat(64),
          tier: 1,
          status: 1,
          createdAt: '2026-01-01T00:00:00Z',
          source: null,
          issuer: null,
        }}
        errorCode={null}
      />,
    )

    expect(screen.getAllByText('Complete')).toHaveLength(5)
    expect(screen.getByText('1 matching record returned.')).toBeInTheDocument()
  })

  it('renders stable failure states for revoked evidence', () => {
    render(
      <VerificationTimeline
        status="error"
        {...baseProps}
        chainProof={{
          videoHash: 'b'.repeat(64),
          metadataHash: 'c'.repeat(64),
          tier: 1,
          status: 2,
          createdAt: '2026-01-01T00:00:00Z',
          source: null,
          issuer: null,
        }}
        errorCode="REVOKED_EVIDENCE"
      />,
    )

    expect(screen.getAllByText('Not confirmed').length).toBeGreaterThan(0)
    expect(screen.getByText('The chain record is not trusted for this run.')).toBeInTheDocument()
    expect(screen.getByText('No trust decision was made.')).toBeInTheDocument()
  })

  it('shows observation sources, ledger bounds, and aligned status for fresh corroboration', () => {
    const nowMs = Date.parse('2026-06-01T12:00:00Z')
    render(
      <VerificationTimeline
        status="success"
        verifyHash={'a'.repeat(64)}
        nowMs={nowMs}
        events={[{
          id: 1,
          event_type: 'registered',
          file_name: null,
          video_hash: 'a'.repeat(64),
          proof_id: 'd'.repeat(64),
          tier: 'silent',
          created_at: '2026-06-01T11:30:00Z',
          time_attestation: {
            version: 1,
            protocol: 'harpocrates-time',
            evidenceDigest: 'a'.repeat(64),
            stellarAnchors: [{
              ledgerSequence: 5120,
              ledgerTimestamp: Math.floor(nowMs / 1000) - 1800,
              transactionHash: 'e'.repeat(64),
              networkPassphrase: 'Test SDF Network ; September 2015',
            }],
            rfc3161Anchors: [],
          },
        }]}
        chainProof={{
          videoHash: 'a'.repeat(64),
          metadataHash: 'c'.repeat(64),
          tier: 1,
          status: 1,
          createdAt: '2026-06-01T11:30:00Z',
          expiresAt: 0,
          source: null,
          issuer: null,
        }}
        errorCode={null}
      />,
    )

    expect(screen.getByText('Sources aligned')).toBeInTheDocument()
    expect(screen.getByText('Source: Backend (NeonDB)')).toBeInTheDocument()
    expect(screen.getByText('Source: Soroban Registry')).toBeInTheDocument()
    expect(screen.getAllByText(/Ledger #5120 · No expiry bound/).length).toBeGreaterThan(0)
  })

  it('distinguishes stale evidence from contradictory observations without replacing the 5 stages', () => {
    const nowMs = Date.parse('2026-06-01T12:00:00Z')
    const { rerender } = render(
      <VerificationTimeline
        status="error"
        verifyHash={'a'.repeat(64)}
        nowMs={nowMs}
        events={[{
          id: 1,
          event_type: 'registered',
          file_name: null,
          video_hash: 'a'.repeat(64),
          proof_id: null,
          tier: 'silent',
          created_at: '2026-06-01T11:00:00Z',
        }]}
        chainProof={{
          videoHash: 'a'.repeat(64),
          metadataHash: 'c'.repeat(64),
          tier: 1,
          status: 3,
          createdAt: '2026-05-01T00:00:00Z',
          expiresAt: Math.floor(nowMs / 1000) - 3600,
          source: null,
          issuer: null,
        }}
        errorCode="EXPIRED_EVIDENCE"
      />,
    )

    expect(screen.getByText('Stale evidence')).toBeInTheDocument()
    expect(screen.queryByText('Source disagreement')).not.toBeInTheDocument()
    expect(screen.getAllByRole('listitem')).toHaveLength(5)

    rerender(
      <VerificationTimeline
        status="success"
        verifyHash={'a'.repeat(64)}
        nowMs={nowMs}
        events={[{
          id: 1,
          event_type: 'registered',
          file_name: null,
          video_hash: 'a'.repeat(64),
          proof_id: null,
          tier: 'seal',
          created_at: '2026-06-01T11:00:00Z',
        }]}
        chainProof={{
          videoHash: 'a'.repeat(64),
          metadataHash: 'c'.repeat(64),
          tier: 1,
          status: 1,
          createdAt: '2026-06-01T11:00:00Z',
          expiresAt: 0,
          source: null,
          issuer: null,
        }}
        errorCode={null}
      />,
    )

    expect(screen.getByText('Source disagreement')).toBeInTheDocument()
    expect(screen.queryByText('Stale evidence')).not.toBeInTheDocument()
    expect(screen.getAllByRole('listitem')).toHaveLength(5)
  })
})
