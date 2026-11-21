"""Bounded registration conflict quarantine.

When an idempotency key is reused with a contradictory payload (a
``ConflictError`` from ``upsert_register_event``), the incoming claim is
retained for operator review in the ``registration_conflicts`` table rather
than silently discarded.

Privacy guarantees
------------------
- The quarantine record never stores raw evidence metadata envelopes,
  witness values, media content, or private keys.
- The ``conflict_field`` name is recorded (e.g. ``"metadata_hash"``) but the
  actual incoming or existing hash values are **not** stored — a hash value
  is a compact fingerprint of the full metadata payload and must not be
  persisted in an operational log.
- The ``tier`` field is a safe public enum (``silent`` / ``source`` / ``seal``)
  and is stored when it is the conflicting field.
- ``source_address`` is a Stellar G-address (a public key) and is stored
  as-is; it carries no private data.
- ``proof_id`` and ``video_hash`` are SHA-256 digests, not PII.
- ``tx_hash`` is a chain-public transaction identifier; only a short prefix
  appears in logs (see ``_short_hash``), but the full value may be stored in
  the quarantine record because it is a public ledger reference.

Bounds
------
- Per-key cap: at most ``QUARANTINE_PER_KEY_MAX`` records per idempotency
  key (default 10, override with ``CONFLICT_QUARANTINE_PER_KEY_MAX``).
  Excess attempts are silently ignored — the 409 response is still returned
  to the caller, but no additional storage is consumed.
- TTL: ``QUARANTINE_TTL_DAYS`` days after insertion (default 30, override
  with ``CONFLICT_QUARANTINE_TTL_DAYS``).  Expired records are removed by
  ``purge_expired_conflicts``.
- No in-memory bound is enforced during local dev (no DATABASE_URL); the
  in-memory store is bounded by ``QUARANTINE_PER_KEY_MAX`` per key.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from db import ConflictError, insert_registration_conflict

LOGGER = logging.getLogger("harpocrates.registration_quarantine")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

# Fields whose *values* are safe to record in the quarantine store.
# Hash fields (video_hash, metadata_hash, proof_id) are NOT in this set
# because storing incoming hash values could inadvertently expose compacted
# metadata fingerprints; we record only which field conflicted.
_SAFE_VALUE_FIELDS: frozenset[str] = frozenset({"tier"})

# Fields that are non-sensitive public identifiers always captured on the record.
_PUBLIC_ID_FIELDS: frozenset[str] = frozenset(
    {"proof_id", "video_hash", "source_address"}
)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 1 else default


def quarantine_per_key_max() -> int:
    """Maximum quarantine records stored per idempotency key."""
    return _env_int("CONFLICT_QUARANTINE_PER_KEY_MAX", 10)


def quarantine_ttl_days() -> int:
    """TTL in days for quarantine records (default 30)."""
    return _env_int("CONFLICT_QUARANTINE_TTL_DAYS", 30)


def _short_hash(value: str | None) -> str:
    """Return an 8-character prefix for log messages (privacy-safe)."""
    if not value or len(value) < 8:
        return value or ""
    return value[:8]


def _safe_tier(value: object) -> str | None:
    """Return the tier value only when it is a known safe enum member."""
    if isinstance(value, str) and value in {"silent", "source", "seal"}:
        return value
    return None


def record_registration_conflict(exc: ConflictError, *, tx_hash: str | None = None) -> bool:
    """Persist a quarantine record for the given ``ConflictError``.

    Parameters
    ----------
    exc:
        The ``ConflictError`` raised by ``upsert_register_event``.  Used to
        extract the idempotency key and the conflicting field.
    tx_hash:
        The incoming transaction hash (a public ledger reference).  Optional.

    Returns
    -------
    bool
        ``True`` when a new record was stored, ``False`` when the per-key cap
        was already reached or the insert was otherwise skipped.

    Privacy
    -------
    Only safe fields are written to storage.  The incoming and existing field
    *values* are discarded except when the conflicting field is ``tier``
    (a public enum).
    """
    conflict_field = exc.field

    # Determine what tier value (if any) is safe to record.
    conflict_tier_incoming: str | None = None
    if conflict_field == "tier":
        conflict_tier_incoming = _safe_tier(exc.incoming_value)

    # Extract safe public identifiers from the ConflictError attributes.
    # exc.existing_value holds the DB row value for the conflicting field —
    # derive proof_id/video_hash/source_address from the idempotency context
    # only when the conflicting field is not one of those fields itself, so we
    # never write an unexpected hash value as a "safe" identifier.
    proof_id: str | None = None
    video_hash: str | None = None
    source_address: str | None = None

    # The idempotency key encodes video_hash:proof_id:tx_hash as SHA-256,
    # so we cannot reconstruct those from the key alone. The caller must
    # pass them explicitly via the ConflictError attributes when present.
    # We access them defensively: only store if the field is not the one
    # that conflicted (to avoid storing a compromised incoming value as an id).
    if conflict_field not in ("proof_id",) and isinstance(getattr(exc, "_proof_id", None), str):
        proof_id = exc._proof_id  # type: ignore[attr-defined]
    if conflict_field not in ("video_hash",) and isinstance(getattr(exc, "_video_hash", None), str):
        video_hash = exc._video_hash  # type: ignore[attr-defined]
    if conflict_field not in ("source_address",) and isinstance(
        getattr(exc, "_source_address", None), str
    ):
        source_address = exc._source_address  # type: ignore[attr-defined]

    try:
        stored = insert_registration_conflict(
            idempotency_key=exc.idempotency_key,
            conflict_field=conflict_field,
            proof_id=proof_id,
            video_hash=video_hash,
            source_address=source_address,
            tx_hash=tx_hash,
            conflict_tier_incoming=conflict_tier_incoming,
            per_key_max=quarantine_per_key_max(),
            ttl_days=quarantine_ttl_days(),
        )
        if stored:
            LOGGER.info(
                "registration_conflict_quarantined key=%s field=%s",
                _short_hash(exc.idempotency_key),
                conflict_field,
            )
        else:
            LOGGER.info(
                "registration_conflict_cap_reached key=%s field=%s",
                _short_hash(exc.idempotency_key),
                conflict_field,
            )
        return stored
    except Exception as db_exc:
        # Quarantine storage failure must never obscure the 409 to the caller.
        LOGGER.warning(
            "registration_conflict_quarantine_failed key=%s field=%s err=%s",
            _short_hash(exc.idempotency_key),
            conflict_field,
            type(db_exc).__name__,
        )
        return False
