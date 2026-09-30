import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { IssuerTrustBadge } from './IssuerTrustBadge'
import {
  resolveIssuerTrust,
  STELLAR_STRKEY_LENGTH,
  type IssuerLookupOutcome,
  type IssuerTrust,
} from './issuerTrust'

const ACCOUNT_ISSUER = `G${'A'.repeat(STELLAR_STRKEY_LENGTH - 1)}`
const NOW = 1_800_000_000

function trustFor(
  issuer: string | null | undefined,
  lookup: IssuerLookupOutcome,
  expiresAt?: number | null,
): IssuerTrust {
  return resolveIssuerTrust({ issuer, lookup, expiresAt, now: NOW })
}

describe('IssuerTrustBadge', () => {
  it('renders the label and the resolved state', () => {
    render(<IssuerTrustBadge trust={trustFor(ACCOUNT_ISSUER, { kind: 'active' })} />)

    const badge = screen.getByRole('status')
    expect(badge).toHaveTextContent('Issuer trusted')
    expect(badge).toHaveAttribute('data-state', 'trusted')
    expect(badge).toHaveAttribute('data-severity', 'positive')
    expect(badge).toHaveClass('issuer-trust-badge', 'issuer-trust-positive')
  })

  it('exposes the description as both the tooltip and the accessible name', () => {
    const trust = trustFor(ACCOUNT_ISSUER, { kind: 'inactive' })

    render(<IssuerTrustBadge trust={trust} />)

    const badge = screen.getByRole('status')
    expect(badge).toHaveAttribute('title', trust.description)
    expect(
      screen.getByRole('status', { name: `${trust.label}. ${trust.description}` }),
    ).toBe(badge)
  })

  it('shows the truncated issuer address', () => {
    render(<IssuerTrustBadge trust={trustFor(ACCOUNT_ISSUER, { kind: 'active' })} />)

    expect(screen.getByText('GAAAAA…AAAA')).toBeInTheDocument()
  })

  it('omits the issuer address when asked to', () => {
    render(
      <IssuerTrustBadge trust={trustFor(ACCOUNT_ISSUER, { kind: 'active' })} showIssuer={false} />,
    )

    expect(screen.queryByText('GAAAAA…AAAA')).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Issuer trusted')
  })

  it('renders no address for a state that has none', () => {
    render(<IssuerTrustBadge trust={trustFor(null, { kind: 'active' })} />)

    const badge = screen.getByRole('status')
    expect(badge).toHaveAttribute('data-state', 'unsupported')
    expect(badge.querySelector('code')).toBeNull()
  })

  it('hides the icon from assistive technology', () => {
    const { container } = render(
      <IssuerTrustBadge trust={trustFor(ACCOUNT_ISSUER, { kind: 'active' })} />,
    )

    const icon = container.querySelector('.issuer-trust-badge__icon')
    expect(icon).not.toBeNull()
    expect(icon).toHaveAttribute('aria-hidden', 'true')
  })

  it.each([
    ['trusted', 'positive', () => trustFor(ACCOUNT_ISSUER, { kind: 'active' })],
    ['revoked', 'critical', () => trustFor(ACCOUNT_ISSUER, { kind: 'inactive' })],
    ['unknown', 'caution', () => trustFor(ACCOUNT_ISSUER, { kind: 'missing' })],
    ['expired', 'caution', () => trustFor(ACCOUNT_ISSUER, { kind: 'active' }, NOW - 1)],
    ['unsupported', 'neutral', () => trustFor(null, { kind: 'active' })],
    ['malformed', 'caution', () => trustFor('nope', { kind: 'active' })],
    ['oversized', 'caution', () => trustFor(`${ACCOUNT_ISSUER}A`, { kind: 'active' })],
    ['unavailable', 'caution', () => trustFor(ACCOUNT_ISSUER, { kind: 'failed' })],
    ['checking', 'neutral', () => trustFor(ACCOUNT_ISSUER, { kind: 'pending' })],
  ])('renders the %s state with %s severity', (state, severity, build) => {
    const trust = build()

    render(<IssuerTrustBadge trust={trust} />)

    const badge = screen.getByRole('status')
    expect(badge).toHaveAttribute('data-state', state)
    expect(badge).toHaveAttribute('data-severity', severity)
    expect(badge).toHaveClass(`issuer-trust-${severity}`)
    expect(badge).toHaveTextContent(trust.label)
  })

  it('announces as a live region without becoming a keyboard stop', () => {
    render(<IssuerTrustBadge trust={trustFor(ACCOUNT_ISSUER, { kind: 'active' })} />)

    const badge = screen.getByRole('status')
    // A status is announced, not operated: it adds no tab stop and takes no
    // focus, so the side rail keeps the focus order it already had.
    expect(badge.tagName).toBe('SPAN')
    expect(badge).not.toHaveAttribute('tabindex')
    expect(document.activeElement).toBe(document.body)
  })

  it('appends a caller-provided class without dropping the state classes', () => {
    render(
      <IssuerTrustBadge
        trust={trustFor(ACCOUNT_ISSUER, { kind: 'active' })}
        className="rail-badge"
      />,
    )

    expect(screen.getByRole('status')).toHaveClass(
      'issuer-trust-badge',
      'issuer-trust-positive',
      'rail-badge',
    )
  })
})
