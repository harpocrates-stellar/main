/**
 * IssuerTrustBadge — renders the issuer trust state resolved by
 * `resolveIssuerTrust`.
 *
 * Pure presentation: it takes an already-resolved `IssuerTrust` and never
 * reads the registry itself. The read lives in `useIssuerTrust`, so the badge
 * can be rendered from fixtures, unit-tested without network mocks, and reused
 * by both the verification portal and the Evidence Studio.
 *
 * Privacy: the badge shows the fixed label, the fixed description, and the
 * issuer address — which is already public on chain. No evidence, media,
 * witness values, or keys are accepted by this component.
 */

import {
  ClockAlert,
  CloudOff,
  LoaderCircle,
  Ruler,
  ShieldCheck,
  ShieldMinus,
  ShieldOff,
  ShieldQuestion,
  ShieldX,
  type LucideIcon,
} from 'lucide-react'
import { shortenIssuer, type IssuerTrust, type IssuerTrustState } from './issuerTrust'

const ICONS: Record<IssuerTrustState, LucideIcon> = {
  trusted: ShieldCheck,
  revoked: ShieldOff,
  unknown: ShieldQuestion,
  expired: ClockAlert,
  unsupported: ShieldMinus,
  malformed: ShieldX,
  oversized: Ruler,
  unavailable: CloudOff,
  checking: LoaderCircle,
}

export type IssuerTrustBadgeProps = {
  trust: IssuerTrust
  /** Show the truncated issuer address beside the label. Defaults to true. */
  showIssuer?: boolean
  className?: string
}

export function IssuerTrustBadge({
  trust,
  showIssuer = true,
  className,
}: IssuerTrustBadgeProps) {
  const Icon = ICONS[trust.state]
  const classes = ['issuer-trust-badge', `issuer-trust-${trust.severity}`, className]
    .filter(Boolean)
    .join(' ')

  return (
    <span
      className={classes}
      data-state={trust.state}
      data-severity={trust.severity}
      role="status"
      title={trust.description}
      aria-label={`${trust.label}. ${trust.description}`}
    >
      <Icon
        className="issuer-trust-badge__icon"
        aria-hidden="true"
        size={12}
        strokeWidth={2.25}
      />
      <span className="issuer-trust-badge__label">{trust.label}</span>
      {showIssuer && trust.issuer ? (
        <code className="issuer-trust-badge__issuer" title={trust.issuer}>
          {shortenIssuer(trust.issuer)}
        </code>
      ) : null}
    </span>
  )
}
