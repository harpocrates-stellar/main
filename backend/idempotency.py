from __future__ import annotations

import datetime
import functools
import hashlib
from typing import Any, Optional, Tuple

from flask import Response, has_request_context, jsonify, request

from db import Jsonb, get_connection


# Table: idempotency_records
# Columns:
#   id SERIAL PRIMARY KEY
#   request_digest TEXT NOT NULL
#   request_type TEXT NOT NULL
#   created_at TIMESTAMPTZ NOT NULL DEFAULT now()
#   expires_at TIMESTAMPTZ NOT NULL
#   status TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED'))
#   response_payload JSONB NULL
#   error_payload JSONB NULL
#   UNIQUE (request_digest, request_type)
#
# Race model (deterministic fixtures in tests/test_registration_races.py):
#   * Duplicate submissions converge on a single PENDING/COMPLETED record via
#     the UNIQUE constraint; losers replay the winner's stored outcome.
#   * A worker that dies while holding PENDING leaves the record in place.
#     Once ``expires_at`` passes, the stale PENDING lock is reclaimed by the
#     next caller so a replacement worker can proceed exactly once.
#   * Only one caller may transition a reclaimed record back to PENDING; the
#     reclaim is a conditional UPDATE, so concurrent reclaimers cannot both win.


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _default_expiry(window_seconds: int = 86400) -> datetime.datetime:
    return _now() + datetime.timedelta(seconds=window_seconds)


def _db_available() -> bool:
    """Return True when persistence is configured for idempotency records."""
    try:
        from db import database_url

        return bool(database_url())
    except Exception:
        return False


def create_idempotency_record(
    request_digest: str, request_type: str, expires_at: Optional[datetime.datetime] = None
) -> Tuple[int, str]:
    """Insert a new idempotency record with status PENDING.

    Returns (record_id, status). If a record already exists, returns its id and current status.
    A stale PENDING record whose lock has expired is reclaimed for this caller
    (status returned as PENDING with the reclaimed id), so a replacement worker
    can retry after the original worker vanished.
    """
    if expires_at is None:
        expires_at = _default_expiry()
    now = _now()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO idempotency_records (request_digest, request_type, expires_at, status)
                VALUES (%s, %s, %s, 'PENDING')
                ON CONFLICT (request_digest, request_type) DO UPDATE SET status = idempotency_records.status
                RETURNING id, status;
                """,
                (request_digest, request_type, expires_at),
            )
            row = cur.fetchone()
            record_id, status = int(row["id"]), row["status"]

            if status == "PENDING":
                # Reclaim only if the existing lock is stale. Conditional UPDATE
                # ensures at most one replacement worker wins the reclaim.
                cur.execute(
                    """
                    UPDATE idempotency_records
                    SET expires_at = %s
                    WHERE id = %s AND status = 'PENDING' AND expires_at <= %s
                    RETURNING id;
                    """,
                    (expires_at, record_id, now),
                )
                reclaimed = cur.fetchone()
                if reclaimed is not None:
                    conn.commit()
                    return record_id, "PENDING"

            conn.commit()
            return record_id, status


def get_idempotency_record(request_digest: str, request_type: str) -> Optional[dict]:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM idempotency_records WHERE request_digest = %s AND request_type = %s",
                (request_digest, request_type),
            )
            row = cur.fetchone()
            if row:
                return dict(row)
            return None


def store_response(record_id: int, payload: Any) -> None:
    """Store a successful response payload and mark record as COMPLETED."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE idempotency_records
                SET status = 'COMPLETED', response_payload = %s, error_payload = NULL
                WHERE id = %s;
                """,
                (Jsonb(payload), record_id),
            )
            conn.commit()


def store_error(record_id: int, error: dict) -> None:
    """Store an error payload and mark record as FAILED."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE idempotency_records
                SET status = 'FAILED', error_payload = %s, response_payload = NULL
                WHERE id = %s;
                """,
                (Jsonb(error), record_id),
            )
            conn.commit()


def clear_idempotency_record(record_id: int) -> None:
    """Remove a PENDING record so a later retry can re-acquire the lock."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM idempotency_records WHERE id = %s AND status = 'PENDING'",
                (record_id,),
            )
            conn.commit()


def _extract_identity_tier() -> Optional[str]:
    """Extract the identity tier from a JSON request body when present."""
    if not has_request_context():
        return None
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        tier = payload.get("tier")
        if isinstance(tier, str):
            return tier.strip()
    return None


def _idempotency_key_header() -> Optional[str]:
    """Return the trimmed Idempotency-Key header value if present."""
    if not has_request_context():
        return None
    raw = request.headers.get("Idempotency-Key")
    if isinstance(raw, str):
        trimmed = raw.strip()
        if trimmed:
            return trimmed
    return None


def _idempotency_key_digest(request_type: str, key: str) -> str:
    """Derive a fixed-length lookup digest for an explicit Idempotency-Key."""
    data = b"|".join([b"key", request_type.encode(), key.encode()])
    return hashlib.sha256(data).hexdigest()


def _canonical_digest() -> str:
    """SHA-256 of method, path, query string, identity tier, and raw body (canonical request identity)."""
    method = request.method.encode()
    path = request.path.encode()
    query = request.query_string  # already bytes
    tier = (_extract_identity_tier() or "").encode()
    body = request.get_data() or b""
    data = b"|".join([method, path, query, tier, body])
    return hashlib.sha256(data).hexdigest()


def _extract_response_parts(result: Any) -> tuple[Any, int]:
    """Normalize a Flask view result into (json_body_or_none, status_code)."""
    status = 200
    data = result

    if isinstance(result, tuple):
        data = result[0]
        if len(result) >= 2 and isinstance(result[1], int):
            status = result[1]

    if isinstance(data, Response):
        # Prefer explicit tuple status when provided: return jsonify(x), 201
        if isinstance(result, tuple) and len(result) >= 2 and isinstance(result[1], int):
            status = result[1]
        else:
            status = data.status_code
        body = data.get_json(silent=True)
        return body, status

    if isinstance(data, (dict, list)):
        return data, status

    return None, status


def _replay_stored(
    record: dict,
    *,
    binding_digest: Optional[str] = None,
    tier: Optional[str] = None,
):
    status = record.get("status")
    if status == "COMPLETED":
        payload = record.get("response_payload") or {}
        if (
            binding_digest is not None
            and isinstance(payload, dict)
            and isinstance(payload.get("binding"), dict)
        ):
            stored_binding = payload["binding"]
            if stored_binding.get("digest") != binding_digest:
                conflict: dict[str, Any] = {
                    "error": "idempotency key reused with conflicting payload"
                }
                if stored_binding.get("tier") != tier:
                    conflict["conflict_field"] = "tier"
                return jsonify(conflict), 409
        if isinstance(payload, dict) and "body" in payload and "status" in payload:
            body = payload.get("body")
            code = int(payload.get("status") or 200)
            if body is None:
                return Response(status=code)
            return jsonify(body), code
        # Legacy: bare JSON body stored without status wrapper
        return jsonify(payload), 200
    if status == "FAILED":
        error = record.get("error_payload") or {"error": "previous request failed"}
        code = 500
        if isinstance(error, dict) and isinstance(error.get("status"), int):
            code = error["status"]
            error = {k: v for k, v in error.items() if k != "status"}
        return jsonify(error), code
    # PENDING – another request is currently processing
    return jsonify({"error": "duplicate request in progress"}), 409


def idempotent(request_type: str):
    """Flask view decorator to enforce idempotent request handling.

    Uses a canonical request digest (including identity tier). When an explicit
    ``Idempotency-Key`` header is supplied, the key is bound to the canonical
    digest and identity tier; reusing the key with a changed tier or payload
    returns 409 Conflict without invoking the handler. Completed records replay
    the stored JSON body and HTTP status. Pending records return 409. When
    DATABASE_URL is unset (local/unit tests), the decorator is a no-op so
    callers still rely on semantic upsert idempotency in the register path.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not _db_available():
                return func(*args, **kwargs)

            binding_digest = _canonical_digest()
            tier = _extract_identity_tier()
            idem_key = _idempotency_key_header()
            lookup_digest = (
                _idempotency_key_digest(request_type, idem_key)
                if idem_key is not None
                else binding_digest
            )

            record = get_idempotency_record(lookup_digest, request_type)
            if record:
                return _replay_stored(
                    record,
                    binding_digest=binding_digest if idem_key is not None else None,
                    tier=tier,
                )

            record_id, status = create_idempotency_record(lookup_digest, request_type)
            if status != "PENDING":
                # Lost the race to another worker that already finished (or is in flight).
                existing = get_idempotency_record(lookup_digest, request_type) or {
                    "status": status,
                    "response_payload": None,
                    "error_payload": None,
                }
                return _replay_stored(
                    existing,
                    binding_digest=binding_digest if idem_key is not None else None,
                    tier=tier,
                )

            try:
                result = func(*args, **kwargs)
                body, code = _extract_response_parts(result)
                if code == 503:
                    # Retryable operational outage (e.g. chain RPC unavailable):
                    # keep the request retryable and never cache it as evidence invalidity.
                    clear_idempotency_record(record_id)
                elif 200 <= code < 500:
                    # Cache 2xx and stable 4xx for exact replay (no raw media/secrets).
                    stored_payload: dict[str, Any] = {"status": code, "body": body}
                    if idem_key is not None:
                        stored_payload["binding"] = {
                            "digest": binding_digest,
                            "tier": tier,
                        }
                    store_response(record_id, stored_payload)
                else:
                    # Do not cache server failures — allow a later retry to re-acquire.
                    clear_idempotency_record(record_id)
                return result
            except RetryableOperationalError:
                clear_idempotency_record(record_id)
                raise
            except Exception:
                # Privacy-safe: never persist exception strings (may contain paths/secrets).
                store_error(record_id, {"error": "request processing failed", "status": 500})
                raise

        return wrapper

    return decorator
