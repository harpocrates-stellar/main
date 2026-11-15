import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'
import { expectNoA11yViolations, runAxe } from '../test/axeA11y'

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Future Network ; October 2022',
  getProofByVideoHash: vi.fn(),
  WatchWalletChanges: vi.fn(),
  connectFreighter: vi.fn(),
  getWalletNetwork: vi.fn(),
}))

vi.mock('../components/ChainProofPanel', () => ({
  ChainProofPanel: () => <div data-testid="chain-proof-panel" />,
  formatProofExpiry: () => 'Never',
}))

vi.mock('../components/VerifierSetStatusPanel', () => ({
  VerifierSetStatusPanel: () => <div data-testid="verifier-set-status-panel" />,
}))

vi.mock('../provenance/ProvenanceCard', () => ({
  default: () => <div data-testid="provenance-card" />,
}))

function makeVerification(
  overrides: Partial<UseVerificationReturn> = {},
): UseVerificationReturn {
  return {
    verifyHash: '',
    verifyResult: '',
    events: [],
    chainProof: null,
    status: 'idle',
    errorCode: null,
    isVerifying: false,
    offline: false,
    setOffline: vi.fn(),
    verifyEvidence: vi.fn(),
    loadEvents: vi.fn(),
    loadSharedVerification: vi.fn(),
    cancel: vi.fn(),
    retry: vi.fn(),
    clear: vi.fn(),
    ...overrides,
  }
}

describe('VerifyView keyboard-accessible verification detail explorer (#1143)', () => {
  it('exposes public-input checks, chain observations, and trust reasons in expandable sections with logical keyboard navigation and meaningful headings', async () => {
    const user = userEvent.setup()
    const verification = makeVerification({
      status: 'success',
      verifyHash: 'a'.repeat(64),
      verifyResult:
        'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
      events: [
        {
          id: 101,
          event_type: 'registered',
          file_name: 'private-raw-filename-must-not-leak.mp4',
          video_hash: 'a'.repeat(64),
          proof_id: 'b'.repeat(64),
          tier: 'silent',
          created_at: '2026-10-01T00:00:00Z',
        },
      ],
      chainProof: {
        videoHash: 'a'.repeat(64),
        metadataHash: 'c'.repeat(64),
        proofId: 'b'.repeat(64),
        tier: 0,
        status: 1,
        createdAt: '2026-10-01T00:00:00Z',
        expiresAt: 0,
        source: null,
        issuer: null,
      },
    })

    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={verification}
        provenanceRecord={null}
      />,
    )

    const explorerRegion = screen
      .getByRole('heading', { level: 3, name: 'Verification detail explorer' })
      .closest('section')!
    expect(explorerRegion).not.toBeNull()

    // Meaningful h4 headings in logical order inside the h3 explorer section
    const sectionHeadings = within(explorerRegion).getAllByRole('heading', { level: 4 })
    expect(sectionHeadings.map((h) => h.textContent)).toEqual([
      expect.stringContaining('Public-input checks'),
      expect.stringContaining('Chain observations'),
      expect.stringContaining('Trust reasons'),
    ])

    const publicTrigger = within(explorerRegion).getByRole('button', {
      name: /Public-input checks/i,
    })
    const chainTrigger = within(explorerRegion).getByRole('button', {
      name: /Chain observations/i,
    })
    const trustTrigger = within(explorerRegion).getByRole('button', {
      name: /Trust reasons/i,
    })

    // Default state: first section expanded, others collapsed
    expect(publicTrigger).toHaveAttribute('aria-expanded', 'true')
    expect(chainTrigger).toHaveAttribute('aria-expanded', 'false')
    expect(trustTrigger).toHaveAttribute('aria-expanded', 'false')

    // Never leaks raw filename from backend event into explorer output
    expect(explorerRegion.textContent).not.toContain(
      'private-raw-filename-must-not-leak.mp4',
    )

    // Keyboard focus order: Tab from publicTrigger -> chainTrigger -> trustTrigger
    publicTrigger.focus()
    expect(document.activeElement).toBe(publicTrigger)

    await user.tab()
    expect(document.activeElement).toBe(chainTrigger)

    // Expand Chain observations with Enter
    await user.keyboard('{Enter}')
    expect(chainTrigger).toHaveAttribute('aria-expanded', 'true')
    expect(within(explorerRegion).getByText('Registered on-chain')).toBeInTheDocument()
    expect(within(explorerRegion).getByText('Tier 0 (Silent Witness)')).toBeInTheDocument()

    // ArrowDown moves to Trust reasons trigger; Space expands Trust reasons
    await user.keyboard('{ArrowDown}')
    expect(document.activeElement).toBe(trustTrigger)
    await user.keyboard(' ')
    expect(trustTrigger).toHaveAttribute('aria-expanded', 'true')
    expect(
      within(explorerRegion).getByText(
        /Public digests, backend event history, and active Soroban registry record agree/i,
      ),
    ).toBeInTheDocument()

    // Home / End keys preserve predictable accordion navigation
    await user.keyboard('{Home}')
    expect(document.activeElement).toBe(publicTrigger)
    await user.keyboard('{End}')
    expect(document.activeElement).toBe(trustTrigger)

    expectNoA11yViolations(await runAxe(container), 'verify view with detail explorer')
  })

  it('surfaces revoked and offline boundary states accurately without claiming online confirmation', async () => {
    const user = userEvent.setup()

    // Boundary 1: Revoked evidence
    const { rerender } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeVerification({
          status: 'error',
          errorCode: 'REVOKED_EVIDENCE',
          verifyHash: 'd'.repeat(64),
          chainProof: {
            videoHash: 'd'.repeat(64),
            metadataHash: 'e'.repeat(64),
            tier: 1,
            status: 2,
            createdAt: '2026-10-01T00:00:00Z',
            expiresAt: 0,
            source: null,
            issuer: null,
          },
        })}
        provenanceRecord={null}
      />,
    )

    const trustTrigger = screen.getByRole('button', { name: /Trust reasons/i })
    expect(trustTrigger.textContent).toContain('Rejected: on-chain record revoked')
    await user.click(trustTrigger)
    expect(screen.getByText('REVOKED_EVIDENCE')).toBeInTheDocument()

    // Boundary 2: Offline mode never claims chain check passed
    rerender(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeVerification({
          status: 'success',
          offline: true,
          verifyHash: 'f'.repeat(64),
        })}
        provenanceRecord={null}
      />,
    )

    const chainTrigger = screen.getByRole('button', { name: /Chain observations/i })
    expect(chainTrigger.textContent).toContain('Skipped in offline local mode')
    await user.click(chainTrigger)
    expect(screen.getAllByText('Not checked (offline mode)').length).toBeGreaterThan(0)
  })
})
