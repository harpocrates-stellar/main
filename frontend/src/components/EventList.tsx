import type { ProofEvent } from '../types'
import { shortHash } from '../utils'

type Props = {
  events: ProofEvent[]
  onRefresh: () => void
}

export function EventList({ events, onRefresh }: Props) {
  return (
    <>
      <button className="verify-input" type="button" onClick={onRefresh}>
        Refresh NeonDB feed
      </button>
      <div className="event-list">
        {events.length === 0 ? (
          <p>No events loaded.</p>
        ) : (
          events.map((event) => (
            <div className="event-row" key={event.id}>
              <strong>{event.event_type}</strong>
              <span>{event.tx_status ?? event.tier ?? 'untiered'}</span>
              <code>{shortHash(event.video_hash ?? event.proof_id ?? '')}</code>
              {event.tx_hash ? <code>{shortHash(event.tx_hash)}</code> : null}
              {event.time_attestation ? (
                <details className="event-attestation">
                  <summary>Timestamp attestation</summary>
                  <dl>
                    {event.time_attestation.claimedTime ? (
                      <>
                        <dt>Claimed</dt>
                        <dd>{new Date(event.time_attestation.claimedTime.unixMs).toISOString()}</dd>
                      </>
                    ) : null}
                    {event.time_attestation.observedTime ? (
                      <>
                        <dt>Observed</dt>
                        <dd>{new Date(event.time_attestation.observedTime.unixMs).toISOString()}</dd>
                      </>
                    ) : null}
                    <dt>Stellar anchors</dt>
                    <dd>{event.time_attestation.stellarAnchors.length}</dd>
                    <dt>RFC 3161 anchors</dt>
                    <dd>{event.time_attestation.rfc3161Anchors.length}</dd>
                  </dl>
                </details>
              ) : null}
            </div>
          ))
        )}
      </div>
    </>
  )
}
