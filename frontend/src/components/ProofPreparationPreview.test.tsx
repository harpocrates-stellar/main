import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { ProofPreparationPreview } from './ProofPreparationPreview'
import {
  buildProofPreparationPreview,
  PROOF_PREPARATION_POLICY_ID,
  PROOF_PREPARATION_POLICY_VERSION,
} from '../proofPreparationPreview'
import { REDACTED_PLACEHOLDER } from '../redactionPreview'
import type { ProofPackage } from '../types'

const VIDEO_HASH = `${'11'.repeat(16)}${'22'.repeat(16)}`

const proof: ProofPackage = {
  fileName: 'harpocrates-clip.mp4',
  sourceHash: 'a'.repeat(64),
  videoHash: VIDEO_HASH,
  metadataHash: 'c'.repeat(64),
  proofId: 'd'.repeat(64),
  timestamp: '2026-01-01T00:00:00.000Z',
  tier: 'silent',
}

describe('ProofPreparationPreview', () => {
  it('shows the policy version and canonical public inputs as a read-only panel', () => {
    const preparation = buildProofPreparationPreview({
      proof,
      tier: 'silent',
      verifierScope: '0',
      epoch: 20_000,
    })
    expect(preparation.ok).toBe(true)
    if (!preparation.ok) return

    render(<ProofPreparationPreview preparation={preparation} />)

    const region = screen.getByRole('region', {
      name: 'Read-only proof preparation preview',
    })
    expect(within(region).getByText(PROOF_PREPARATION_POLICY_ID)).toBeInTheDocument()
    expect(within(region).getByText(String(PROOF_PREPARATION_POLICY_VERSION))).toBeInTheDocument()
    expect(region).toHaveTextContent(BigInt(`0x${'11'.repeat(16)}`).toString(10))
    expect(region).toHaveTextContent(BigInt(`0x${'22'.repeat(16)}`).toString(10))
    expect(region).toHaveTextContent('20000')
    expect(within(region).getAllByText(REDACTED_PLACEHOLDER)).toHaveLength(2)
    expect(within(region).queryAllByRole('button')).toHaveLength(0)
    expect(region).toHaveTextContent(/nothing is proven or submitted from this preview/i)
  })

  it('renders the empty state before evidence exists', () => {
    const preparation = buildProofPreparationPreview({ proof: null, tier: 'silent' })

    render(<ProofPreparationPreview preparation={preparation} />)

    expect(screen.getByRole('status')).toHaveTextContent(
      'Generate evidence to preview the canonical public inputs.',
    )
  })

  it('surfaces a stable error code when public inputs cannot be canonicalized', () => {
    const preparation = buildProofPreparationPreview({
      proof: { ...proof, videoHash: 'not-a-hash' },
      tier: 'silent',
    })

    const { container } = render(<ProofPreparationPreview preparation={preparation} />)

    const alert = screen.getByRole('alert')
    expect(alert).toHaveAttribute('data-error-code', 'INVALID_PUBLIC_INPUTS')
    expect(alert).toHaveTextContent('Canonical proof inputs are unavailable for this evidence.')
    expect(container.textContent).not.toContain('not-a-hash')
  })
})
