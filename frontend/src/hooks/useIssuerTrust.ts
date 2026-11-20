/**
 * useIssuerTrust — performs the registry issuer read and reduces it to the
 * trust state shown by `IssuerTrustBadge`.
 *
 * Failure policy: a read that does not complete is reported as `unavailable`,
 * never as `trusted` and never as `unknown`. "No record" and "could not read"
 * are different answers and the UI must not merge them.
 *
 * The read is skipped entirely for addresses the registry could not hold
 * (missing, malformed, oversized), so a bad chain record cannot turn into
 * registry traffic.
 *
 * The in-flight state is derived from a key rather than written from the
 * effect: when the issuer changes, the stored outcome no longer matches the
 * current key and the hook reports `checking` without a second render pass.
 * A response that arrives after the key changed is dropped.
 *
 * Privacy: only the issuer address leaves the browser, and only as a public
 * contract argument. Errors collapse into a stable state code — raw RPC error
 * text is never surfaced or logged.
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import { getIssuerRecord } from '../harpocratesRegistry'
import {
  isLookupEligibleIssuer,
  resolveIssuerTrust,
  type IssuerLookupOutcome,
  type IssuerTrust,
} from '../provenance/issuerTrust'

const REGISTRY_CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

const PENDING: IssuerLookupOutcome = { kind: 'pending' }
const UNREADABLE: IssuerLookupOutcome = { kind: 'failed' }

type SettledLookup = {
  /** Issuer the outcome belongs to; the empty string means "nothing settled". */
  key: string
  outcome: IssuerLookupOutcome
}

const NOTHING_SETTLED: SettledLookup = { key: '', outcome: PENDING }

export type UseIssuerTrustOptions = {
  /** Issuer address from the chain record. */
  issuer: string | null | undefined
  /** `ProofRecord.expires_at` in Unix seconds; `0` or null means never. */
  expiresAt?: number | null
  /** Registry contract id. Defaults to `VITE_HARPOCRATES_REGISTRY_ID`. */
  contractId?: string
  /** Set false to hold the state at `checking` without issuing a read. */
  enabled?: boolean
  /** Unix seconds for the expiry comparison. Defaults to the wall clock. */
  now?: number
}

export function useIssuerTrust(options: UseIssuerTrustOptions): IssuerTrust {
  const {
    issuer,
    expiresAt = null,
    contractId = REGISTRY_CONTRACT_ID,
    enabled = true,
    now,
  } = options

  const [settled, setSettled] = useState<SettledLookup>(NOTHING_SETTLED)
  const requestRef = useRef(0)

  const eligible = enabled && isLookupEligibleIssuer(issuer)
  const lookupKey = eligible && contractId ? `${contractId}|${issuer}` : ''

  useEffect(() => {
    if (!lookupKey) return

    const request = requestRef.current + 1
    requestRef.current = request
    let cancelled = false

    void (async () => {
      let outcome: IssuerLookupOutcome
      try {
        const record = await getIssuerRecord(contractId, issuer as string)
        outcome = record ? { kind: record.active ? 'active' : 'inactive' } : { kind: 'missing' }
      } catch {
        outcome = UNREADABLE
      }

      if (cancelled || requestRef.current !== request) return
      setSettled({ key: lookupKey, outcome })
    })()

    return () => {
      cancelled = true
    }
  }, [lookupKey, contractId, issuer])

  // Without a registry id there is nothing to read. That is a missing
  // dependency, not an issuer the registry declined to list.
  const lookup: IssuerLookupOutcome = !eligible
    ? PENDING
    : !contractId
      ? UNREADABLE
      : settled.key === lookupKey
        ? settled.outcome
        : PENDING

  return useMemo(
    () => resolveIssuerTrust({ issuer, lookup, expiresAt, now }),
    [issuer, lookup, expiresAt, now],
  )
}
