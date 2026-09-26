/**
 * issuerTrust — canonical mapping from a chain record's issuer to the trust
 * state shown in the Evidence Studio and the verification portal.
 *
 * The registry is the only source of truth for issuer standing
 * (`add_issuer` / `revoke_issuer` / `get_issuer` in
 * `contracts/contracts/harpocrates-registry/src/lib.rs`). This module never
 * re-derives trust from anything else, and it never reports a weaker outcome
 * as a stronger one: a registry read that did not complete is `unavailable`,
 * not `trusted` and not `unknown`.
 *
 * Privacy: labels and descriptions are fixed strings. Raw evidence, media,
 * witness values, and keys never reach a badge — only the issuer address,
 * which is already public on chain.
 */

/** Canonical issuer trust states surfaced by the frontend. */
export type IssuerTrustState =
  /** The registry lists the issuer as active and the record has not expired. */
  | 'trusted'
  /** The registry lists the issuer as revoked. */
  | 'revoked'
  /** The registry has no record for this issuer address. */
  | 'unknown'
  /** The issuer is active but the record's endorsement window has ended. */
  | 'expired'
  /** The identity tier does not carry an issuer address at all. */
  | 'unsupported'
  /** The issuer address is not a well-formed Stellar StrKey. */
  | 'malformed'
  /** The issuer address is longer than a Stellar StrKey can be. */
  | 'oversized'
  /** The registry lookup did not complete, so no trust decision was made. */
  | 'unavailable'
  /** The registry lookup is still in flight. */
  | 'checking'

export type IssuerTrustSeverity = 'positive' | 'neutral' | 'caution' | 'critical'

/**
 * Outcome of the `get_issuer` registry read, reduced to the cases the UI
 * distinguishes. `pending` is the state before the read resolves.
 */
export type IssuerLookupOutcome =
  | { kind: 'pending' }
  | { kind: 'active' }
  | { kind: 'inactive' }
  | { kind: 'missing' }
  | { kind: 'failed' }

export type IssuerTrust = {
  state: IssuerTrustState
  /** Badge text — short enough for the mobile side rail. */
  label: string
  /** Full sentence, used as the badge title and for screen readers. */
  description: string
  severity: IssuerTrustSeverity
  /** The issuer address the state was derived from, or null when there is none. */
  issuer: string | null
}

export type ResolveIssuerTrustInput = {
  /** Issuer address from the chain record (`ProofRecord.issuer`). */
  issuer: string | null | undefined
  /** Result of the registry lookup. */
  lookup: IssuerLookupOutcome
  /**
   * `ProofRecord.expires_at` in Unix seconds. `0` means the record never
   * expires, matching the registry's expiry policy.
   */
  expiresAt?: number | null
  /** Unix seconds used for the expiry comparison. Defaults to the wall clock. */
  now?: number
}

/**
 * StrKey is 1 version byte + 32 payload bytes + 2 CRC16 bytes, base32 encoded.
 * Issuers are registry `Address` values, so both account (`G…`) and contract
 * (`C…`) addresses are accepted.
 */
export const STELLAR_STRKEY_LENGTH = 56

const STELLAR_STRKEY = /^[GC][A-Z2-7]{55}$/

type TrustCopy = {
  label: string
  description: string
  severity: IssuerTrustSeverity
}

const COPY: Record<IssuerTrustState, TrustCopy> = {
  trusted: {
    label: 'Issuer trusted',
    description:
      'The registry lists this issuer as active, so the seal carries current institutional endorsement.',
    severity: 'positive',
  },
  revoked: {
    label: 'Issuer revoked',
    description:
      'The registry lists this issuer as revoked. Treat the seal as no longer endorsed, even while the record is still registered on chain.',
    severity: 'critical',
  },
  unknown: {
    label: 'Issuer unknown',
    description:
      'The registry has no issuer record for this address, so the seal has no institutional endorsement to verify.',
    severity: 'caution',
  },
  expired: {
    label: 'Endorsement expired',
    description:
      'The issuer is still active, but this record has passed its expiry, so the endorsement is no longer current.',
    severity: 'caution',
  },
  unsupported: {
    label: 'No issuer',
    description:
      'This identity tier does not carry an issuer address, so there is no institutional endorsement to check.',
    severity: 'neutral',
  },
  malformed: {
    label: 'Issuer address malformed',
    description:
      "The chain record's issuer address is not a well-formed Stellar account or contract id, so its endorsement cannot be checked.",
    severity: 'caution',
  },
  oversized: {
    label: 'Issuer address oversized',
    description:
      'The chain record\u2019s issuer address is longer than a Stellar StrKey, so it cannot match any registry issuer.',
    severity: 'caution',
  },
  unavailable: {
    label: 'Issuer lookup unavailable',
    description:
      "The registry could not be read, so this issuer's trust state is unknown. No trust decision was made.",
    severity: 'caution',
  },
  checking: {
    label: 'Checking issuer',
    description: 'Reading the issuer record from the registry.',
    severity: 'neutral',
  },
}

/**
 * Classify the issuer address before any registry read.
 *
 * A record that cannot possibly name a registry issuer is resolved locally so
 * the UI never issues a lookup that the registry would reject anyway.
 */
function classifyAddress(
  issuer: string | null | undefined,
): 'unsupported' | 'oversized' | 'malformed' | null {
  if (issuer === null || issuer === undefined || issuer.trim() === '') return 'unsupported'
  if (issuer.length > STELLAR_STRKEY_LENGTH) return 'oversized'
  if (!STELLAR_STRKEY.test(issuer)) return 'malformed'
  return null
}

/**
 * `expires_at` of 0 means "never expires". The comparison matches the
 * registry, which treats a record as expired only once ledger time is
 * strictly past `expires_at` (`lib.rs` expiry checks).
 */
function isExpired(expiresAt: number | null | undefined, now: number): boolean {
  if (expiresAt === null || expiresAt === undefined || expiresAt === 0) return false
  if (!Number.isFinite(expiresAt)) return false
  return now > expiresAt
}

/**
 * Resolve the trust state for a chain record's issuer.
 *
 * Precedence is deliberate and stable:
 * 1. address shape — an address the registry could never hold wins over any
 *    lookup outcome, because the lookup result would be meaningless;
 * 2. lookup outcome — pending, failed, missing, revoked, active;
 * 3. expiry — an active issuer whose record has expired is not `trusted`.
 */
export function resolveIssuerTrust(input: ResolveIssuerTrustInput): IssuerTrust {
  const issuer = input.issuer ?? null
  const addressIssue = classifyAddress(issuer)

  if (addressIssue) {
    return { state: addressIssue, ...COPY[addressIssue], issuer: null }
  }

  const resolvedIssuer = issuer as string
  const { lookup } = input

  if (lookup.kind === 'pending') {
    return { state: 'checking', ...COPY.checking, issuer: resolvedIssuer }
  }

  if (lookup.kind === 'failed') {
    return { state: 'unavailable', ...COPY.unavailable, issuer: resolvedIssuer }
  }

  if (lookup.kind === 'missing') {
    return { state: 'unknown', ...COPY.unknown, issuer: resolvedIssuer }
  }

  if (lookup.kind === 'inactive') {
    return { state: 'revoked', ...COPY.revoked, issuer: resolvedIssuer }
  }

  const now = input.now ?? Math.floor(Date.now() / 1000)
  if (isExpired(input.expiresAt, now)) {
    return { state: 'expired', ...COPY.expired, issuer: resolvedIssuer }
  }

  return { state: 'trusted', ...COPY.trusted, issuer: resolvedIssuer }
}

/**
 * Whether an issuer address is worth a registry read. Callers use this to skip
 * the lookup for tiers without an issuer and for addresses the registry could
 * not hold.
 */
export function isLookupEligibleIssuer(issuer: string | null | undefined): boolean {
  return classifyAddress(issuer) === null
}

/** Abbreviate an issuer address for display: first 6 + last 4 characters. */
export function shortenIssuer(issuer: string): string {
  if (issuer.length <= 14) return issuer
  return `${issuer.slice(0, 6)}…${issuer.slice(-4)}`
}
