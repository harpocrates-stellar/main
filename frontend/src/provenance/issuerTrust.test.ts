import { describe, expect, it } from 'vitest'
import {
  isLookupEligibleIssuer,
  resolveIssuerTrust,
  shortenIssuer,
  STELLAR_STRKEY_LENGTH,
  type IssuerLookupOutcome,
  type IssuerTrustState,
} from './issuerTrust'

const ACCOUNT_ISSUER = `G${'A'.repeat(STELLAR_STRKEY_LENGTH - 1)}`
const CONTRACT_ISSUER = `C${'A'.repeat(STELLAR_STRKEY_LENGTH - 1)}`
const NOW = 1_800_000_000

const ALL_STATES: IssuerTrustState[] = [
  'trusted',
  'revoked',
  'unknown',
  'expired',
  'unsupported',
  'malformed',
  'oversized',
  'unavailable',
  'checking',
]

function resolve(
  issuer: string | null | undefined,
  lookup: IssuerLookupOutcome,
  expiresAt?: number | null,
) {
  return resolveIssuerTrust({ issuer, lookup, expiresAt, now: NOW })
}

describe('resolveIssuerTrust address shape', () => {
  it.each([
    ['null', null],
    ['undefined', undefined],
    ['empty string', ''],
    ['whitespace only', '   '],
  ])('treats %s as unsupported', (_label, issuer) => {
    const trust = resolve(issuer, { kind: 'active' })

    expect(trust.state).toBe('unsupported')
    expect(trust.severity).toBe('neutral')
    expect(trust.issuer).toBeNull()
  })

  it('accepts a 56-character account StrKey', () => {
    const trust = resolve(ACCOUNT_ISSUER, { kind: 'active' })

    expect(trust.state).toBe('trusted')
    expect(trust.issuer).toBe(ACCOUNT_ISSUER)
  })

  it('accepts a 56-character contract StrKey', () => {
    const trust = resolve(CONTRACT_ISSUER, { kind: 'active' })

    expect(trust.state).toBe('trusted')
    expect(trust.issuer).toBe(CONTRACT_ISSUER)
  })

  it('flags an address longer than a StrKey as oversized', () => {
    const trust = resolve(`${ACCOUNT_ISSUER}A`, { kind: 'active' })

    expect(trust.state).toBe('oversized')
    expect(trust.severity).toBe('caution')
    expect(trust.issuer).toBeNull()
  })

  it.each([
    ['a 55-character address', `G${'A'.repeat(53)}`],
    ['an unsupported version byte', `A${'A'.repeat(STELLAR_STRKEY_LENGTH - 1)}`],
    ['lowercase base32', `G${'a'.repeat(STELLAR_STRKEY_LENGTH - 1)}`],
    ['base32 digits outside the alphabet', `G${'0'.repeat(STELLAR_STRKEY_LENGTH - 1)}`],
    ['an embedded space', `G${'A'.repeat(53)} Z`],
  ])('flags %s as malformed', (_label, issuer) => {
    const trust = resolve(issuer, { kind: 'active' })

    expect(trust.state).toBe('malformed')
    expect(trust.severity).toBe('caution')
    expect(trust.issuer).toBeNull()
  })

  it('resolves the address shape before the lookup outcome', () => {
    const malformed = resolve('not-an-address', { kind: 'active' })
    const oversized = resolve(`${ACCOUNT_ISSUER}A`, { kind: 'inactive' })
    const unsupported = resolve(null, { kind: 'failed' })

    expect([malformed.state, oversized.state, unsupported.state]).toEqual([
      'malformed',
      'oversized',
      'unsupported',
    ])
  })
})

describe('resolveIssuerTrust lookup outcomes', () => {
  it.each([
    ['pending', { kind: 'pending' } as IssuerLookupOutcome, 'checking', 'neutral'],
    ['failed', { kind: 'failed' } as IssuerLookupOutcome, 'unavailable', 'caution'],
    ['missing', { kind: 'missing' } as IssuerLookupOutcome, 'unknown', 'caution'],
    ['inactive', { kind: 'inactive' } as IssuerLookupOutcome, 'revoked', 'critical'],
    ['active', { kind: 'active' } as IssuerLookupOutcome, 'trusted', 'positive'],
  ])('maps a %s lookup to %s', (_label, lookup, state, severity) => {
    const trust = resolve(ACCOUNT_ISSUER, lookup)

    expect(trust.state).toBe(state)
    expect(trust.severity).toBe(severity)
  })

  it('never reports a failed read as trusted or unknown', () => {
    const trust = resolve(ACCOUNT_ISSUER, { kind: 'failed' })

    expect(trust.state).not.toBe('trusted')
    expect(trust.state).not.toBe('unknown')
    expect(trust.description).toMatch(/no trust decision was made/i)
  })

  it('keeps a revoked issuer revoked even when the record has expired', () => {
    const trust = resolve(ACCOUNT_ISSUER, { kind: 'inactive' }, NOW - 1)

    expect(trust.state).toBe('revoked')
  })
})

describe('resolveIssuerTrust expiry', () => {
  it.each([
    ['0 (never expires)', 0],
    ['null', null],
    ['undefined', undefined],
  ])('treats expiresAt %s as not expired', (_label, expiresAt) => {
    expect(resolve(ACCOUNT_ISSUER, { kind: 'active' }, expiresAt).state).toBe('trusted')
  })

  it('stays trusted while now equals expiresAt', () => {
    expect(resolve(ACCOUNT_ISSUER, { kind: 'active' }, NOW).state).toBe('trusted')
  })

  it('stays trusted while now is before expiresAt', () => {
    expect(resolve(ACCOUNT_ISSUER, { kind: 'active' }, NOW + 1).state).toBe('trusted')
  })

  it('reports expired once now is strictly past expiresAt', () => {
    const trust = resolve(ACCOUNT_ISSUER, { kind: 'active' }, NOW - 1)

    expect(trust.state).toBe('expired')
    expect(trust.severity).toBe('caution')
  })

  it('ignores a non-finite expiresAt instead of treating it as expired', () => {
    expect(resolve(ACCOUNT_ISSUER, { kind: 'active' }, Number.NaN).state).toBe('trusted')
  })

  it('does not apply expiry to a record the registry has not endorsed', () => {
    expect(resolve(ACCOUNT_ISSUER, { kind: 'missing' }, NOW - 1).state).toBe('unknown')
    expect(resolve(ACCOUNT_ISSUER, { kind: 'pending' }, NOW - 1).state).toBe('checking')
  })
})

describe('issuer trust copy', () => {
  it('produces a distinct label and a longer description for each state', () => {
    const cases: Array<[IssuerTrustState, ReturnType<typeof resolve>]> = [
      ['trusted', resolve(ACCOUNT_ISSUER, { kind: 'active' })],
      ['revoked', resolve(ACCOUNT_ISSUER, { kind: 'inactive' })],
      ['unknown', resolve(ACCOUNT_ISSUER, { kind: 'missing' })],
      ['expired', resolve(ACCOUNT_ISSUER, { kind: 'active' }, NOW - 1)],
      ['unsupported', resolve(null, { kind: 'active' })],
      ['malformed', resolve('nope', { kind: 'active' })],
      ['oversized', resolve(`${ACCOUNT_ISSUER}A`, { kind: 'active' })],
      ['unavailable', resolve(ACCOUNT_ISSUER, { kind: 'failed' })],
      ['checking', resolve(ACCOUNT_ISSUER, { kind: 'pending' })],
    ]

    const labels = new Set<string>()
    for (const [state, trust] of cases) {
      expect(trust.state).toBe(state)
      expect(trust.label.length).toBeGreaterThan(0)
      expect(trust.description.length).toBeGreaterThan(trust.label.length)
      labels.add(trust.label)
    }

    expect(labels.size).toBe(ALL_STATES.length)
  })

  it('does not put raw error text into the copy', () => {
    const trust = resolve(ACCOUNT_ISSUER, { kind: 'failed' })

    expect(trust.description).not.toMatch(/rpc|error:|http|stack/i)
  })
})

describe('isLookupEligibleIssuer', () => {
  it('accepts well-formed account and contract addresses', () => {
    expect(isLookupEligibleIssuer(ACCOUNT_ISSUER)).toBe(true)
    expect(isLookupEligibleIssuer(CONTRACT_ISSUER)).toBe(true)
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['empty string', ''],
    ['malformed address', 'not-an-address'],
    ['oversized address', `${ACCOUNT_ISSUER}A`],
  ])('rejects %s', (_label, issuer) => {
    expect(isLookupEligibleIssuer(issuer)).toBe(false)
  })
})

describe('shortenIssuer', () => {
  it('keeps the first six and last four characters of a StrKey', () => {
    expect(shortenIssuer(ACCOUNT_ISSUER)).toBe(`GAAAAA…AAAA`)
  })

  it('returns short input unchanged', () => {
    expect(shortenIssuer('GABC')).toBe('GABC')
  })
})
