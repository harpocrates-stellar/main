import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { ProofPackage } from '../types'
import { REDACTED_PLACEHOLDER } from '../redactionPreview'
import { RedactionPreview } from './RedactionPreview'

function sampleProof(): ProofPackage {
  return {
    fileName: 'demo.mp4',
    sourceHash: '11'.repeat(32),
    videoHash: '22'.repeat(32),
    metadataHash: '33'.repeat(32),
    proofId: '44'.repeat(32),
    timestamp: '2026-09-21T12:00:00.000Z',
    tier: 'silent',
    silentWitness: {
      credentialRoot: 'aa'.repeat(32),
      nullifier: 'bb'.repeat(32),
      proof: 'deadbeef'.repeat(32),
      publicInputs: 'cafebabe'.repeat(22),
      proofBytes: 256,
      publicInputBytes: 176,
    },
  }
}

describe('RedactionPreview', () => {
  it('prompts when no evidence is ready', () => {
    render(<RedactionPreview proof={null} />)
    expect(screen.getByText(/Generate evidence to preview/i)).toBeInTheDocument()
  })

  it('renders disclosed fingerprints and redacted witness rows', () => {
    render(
      <RedactionPreview
        proof={sampleProof()}
        secrets={{
          credentialSeed: 'seed-should-never-render',
          nullifierSeed: 'nullifier-should-never-render',
        }}
      />,
    )

    expect(screen.getByRole('region', { name: /privacy-safe redaction preview/i })).toBeInTheDocument()
    expect(screen.getByText('demo.mp4')).toBeInTheDocument()
    expect(screen.getAllByText(REDACTED_PLACEHOLDER).length).toBeGreaterThan(0)
    expect(screen.queryByText('seed-should-never-render')).not.toBeInTheDocument()
    expect(screen.queryByText('nullifier-should-never-render')).not.toBeInTheDocument()
    expect(screen.queryByText('deadbeef'.repeat(4))).not.toBeInTheDocument()
  })

  it('surfaces a stable alert for unsupported tiers', () => {
    const bad = { ...sampleProof(), tier: 'nope' as ProofPackage['tier'] }
    render(<RedactionPreview proof={bad} />)
    const alert = screen.getByRole('alert')
    expect(alert).toHaveAttribute('data-error-code', 'UNSUPPORTED_TIER')
    expect(alert).toHaveTextContent(/not supported/i)
  })
})
