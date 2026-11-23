import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { VerificationDetailExplorer } from './VerificationDetailExplorer'
import type { VerificationDetails } from '../services/verificationFlow'

const MOCK_DETAILS: VerificationDetails = {
  publicInputChecks: [
    {
      id: 'video-hash',
      name: 'Video Hash Encoding',
      status: 'passed',
      summary: 'Canonical 32-byte SHA-256 evidence fingerprint',
      value: 'a'.repeat(64),
      detail: 'Fingerprint verified.',
    },
    {
      id: 'metadata-envelope',
      name: 'Harpocrates Metadata Envelope',
      status: 'passed',
      summary: 'Embedded metadata detected',
    },
    {
      id: 'metadata-binding',
      name: 'Metadata Hash Commitment Binding',
      status: 'failed',
      summary: 'Metadata mismatch detected',
      value: 'b'.repeat(64),
    },
  ],
  chainObservations: [
    {
      id: 'chain-status',
      label: 'Registry Status',
      value: 'Revoked',
      status: 'failed',
      detail: 'On-chain proof was revoked.',
    },
    {
      id: 'chain-tier',
      label: 'Identity Tier',
      value: 'Silent (Tier 1)',
      status: 'passed',
    },
  ],
  trustReasons: [
    {
      id: 'primary-decision',
      title: 'Revoked Evidence Record',
      status: 'failed',
      description: 'The chain record for this artifact has been revoked. Do not trust it as valid evidence.',
    },
    {
      id: 'fingerprint-integrity',
      title: 'Cryptographic Fingerprint Integrity',
      status: 'passed',
      description: 'Fingerprint conforms to canonical SHA-256 formatting.',
    },
  ],
}

describe('VerificationDetailExplorer – Accessibility & Headings', () => {
  it('renders meaningful heading hierarchy (h3 explorer title and h4 section titles)', () => {
    render(<VerificationDetailExplorer details={MOCK_DETAILS} />)

    const mainHeading = screen.getByRole('heading', { level: 3, name: /verification detail explorer/i })
    expect(mainHeading).toBeInTheDocument()

    const sectionHeadings = screen.getAllByRole('heading', { level: 4 })
    expect(sectionHeadings.length).toBe(3)
    expect(sectionHeadings[0]).toHaveTextContent(/public-input checks/i)
    expect(sectionHeadings[1]).toHaveTextContent(/chain observations/i)
    expect(sectionHeadings[2]).toHaveTextContent(/trust reasons/i)
  })

  it('section buttons have proper aria-expanded and aria-controls attributes', () => {
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={true} />)

    const publicBtn = screen.getByRole('button', { name: /public-input checks/i })
    expect(publicBtn).toHaveAttribute('aria-expanded', 'true')
    expect(publicBtn).toHaveAttribute('aria-controls')

    const obsBtn = screen.getByRole('button', { name: /chain observations/i })
    expect(obsBtn).toHaveAttribute('aria-expanded', 'true')
    expect(obsBtn).toHaveAttribute('aria-controls')

    const reasonsBtn = screen.getByRole('button', { name: /trust reasons/i })
    expect(reasonsBtn).toHaveAttribute('aria-expanded', 'true')
    expect(reasonsBtn).toHaveAttribute('aria-controls')
  })

  it('panels have role="region" and are labelled by their section button headers', () => {
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={true} />)

    // 1 outer landmark section + 3 expandable panels
    const regions = screen.getAllByRole('region')
    expect(regions.length).toBe(4)

    const publicBtn = screen.getByRole('button', { name: /public-input checks/i })
    const publicRegion = regions.find((r) => r.getAttribute('aria-labelledby') === publicBtn.id)
    expect(publicRegion).toBeDefined()
    expect(publicRegion).not.toHaveAttribute('hidden')
  })
})

describe('VerificationDetailExplorer – Keyboard Interaction & Focus Order', () => {
  it('toggles section open and closed when clicking the section button', async () => {
    const user = userEvent.setup()
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={true} />)

    const publicBtn = screen.getByRole('button', { name: /public-input checks/i })
    expect(publicBtn).toHaveAttribute('aria-expanded', 'true')

    await user.click(publicBtn)
    expect(publicBtn).toHaveAttribute('aria-expanded', 'false')

    const panel = document.getElementById(publicBtn.getAttribute('aria-controls')!)
    expect(panel).toHaveAttribute('hidden')

    await user.click(publicBtn)
    expect(publicBtn).toHaveAttribute('aria-expanded', 'true')
    expect(panel).not.toHaveAttribute('hidden')
  })

  it('toggles section using keyboard Enter key', () => {
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={false} />)

    const obsBtn = screen.getByRole('button', { name: /chain observations/i })
    expect(obsBtn).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(obsBtn)
    expect(obsBtn).toHaveAttribute('aria-expanded', 'true')
  })

  it('toggles section using keyboard Space key', () => {
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={false} />)

    const reasonsBtn = screen.getByRole('button', { name: /trust reasons/i })
    expect(reasonsBtn).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(reasonsBtn)
    expect(reasonsBtn).toHaveAttribute('aria-expanded', 'true')
  })

  it('toggles all sections via the Expand All / Collapse All control', async () => {
    const user = userEvent.setup()
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={true} />)

    const toggleAllBtn = screen.getByRole('button', { name: /collapse all/i })
    await user.click(toggleAllBtn)

    expect(screen.getByRole('button', { name: /public-input checks/i })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.getByRole('button', { name: /chain observations/i })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.getByRole('button', { name: /trust reasons/i })).toHaveAttribute('aria-expanded', 'false')

    const expandAllBtn = screen.getByRole('button', { name: /expand all/i })
    await user.click(expandAllBtn)

    expect(screen.getByRole('button', { name: /public-input checks/i })).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('button', { name: /chain observations/i })).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('button', { name: /trust reasons/i })).toHaveAttribute('aria-expanded', 'true')
  })

  it('preserves logical focus order when navigating with keyboard', async () => {
    const user = userEvent.setup()
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={true} />)

    const toggleAllBtn = screen.getByRole('button', { name: /collapse all/i })
    const publicBtn = screen.getByRole('button', { name: /public-input checks/i })
    const obsBtn = screen.getByRole('button', { name: /chain observations/i })
    const reasonsBtn = screen.getByRole('button', { name: /trust reasons/i })

    // Tab through buttons
    await user.tab()
    expect(toggleAllBtn).toHaveFocus()

    await user.tab()
    expect(publicBtn).toHaveFocus()

    await user.tab()
    expect(obsBtn).toHaveFocus()

    await user.tab()
    expect(reasonsBtn).toHaveFocus()
  })
})

describe('VerificationDetailExplorer – Content & Boundary Conditions', () => {
  it('displays public input checks with pass/fail badges and values', () => {
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={true} />)

    expect(screen.getByText('Video Hash Encoding')).toBeInTheDocument()
    expect(screen.getByText('Canonical 32-byte SHA-256 evidence fingerprint')).toBeInTheDocument()
    expect(screen.getByText('Metadata mismatch detected')).toBeInTheDocument()
  })

  it('displays chain observations with formatted labels and values', () => {
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={true} />)

    expect(screen.getByText('Registry Status')).toBeInTheDocument()
    expect(screen.getByText('Revoked')).toBeInTheDocument()
    expect(screen.getByText('Identity Tier')).toBeInTheDocument()
    expect(screen.getByText('Silent (Tier 1)')).toBeInTheDocument()
  })

  it('displays trust reasons explaining why artifact was not confirmed', () => {
    render(<VerificationDetailExplorer details={MOCK_DETAILS} defaultExpanded={true} />)

    expect(screen.getByText('Revoked Evidence Record')).toBeInTheDocument()
    expect(screen.getByText(/the chain record for this artifact has been revoked/i)).toBeInTheDocument()
  })

  it('handles empty details gracefully without breaking', () => {
    const emptyDetails: VerificationDetails = {
      publicInputChecks: [],
      chainObservations: [],
      trustReasons: [],
    }

    render(<VerificationDetailExplorer details={emptyDetails} defaultExpanded={true} />)

    expect(screen.getByText(/no public-input checks available/i)).toBeInTheDocument()
    expect(screen.getByText(/no chain observations recorded/i)).toBeInTheDocument()
    expect(screen.getByText(/no trust reasons provided/i)).toBeInTheDocument()
  })
})
