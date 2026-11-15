from __future__ import annotations

import datetime
import functools
import hashlib
import threading
from typing import Any, Optional, Tuple

from flask import Response, jsonify, request

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
    """
    if expires_at is None:
        expires_at = _default_expiry()
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
            conn.commit()
            return int(row["id"]), row["status"]


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


def compute_canonical_request_digest(
    method: str | bytes,
    path: str | bytes,
    query_string: bytes = b"",
    body: bytes = b"",
) -> str:
    """Compute canonical SHA-256 request identity without requiring a Flask context."""
    method_bytes = method.encode("utf-8") if isinstance(method, str) else method
    path_bytes = path.encode("utf-8") if isinstance(path, str) else path
    data = b"|".join([method_bytes, path_bytes, query_string or b"", body or b""])
    return hashlib.sha256(data).hexdigest()


def _canonical_digest() -> str:
    """SHA-256 of method, path, query string, and raw body (canonical request identity)."""
    return compute_canonical_request_digest(
        request.method,
        request.path,
        request.query_string,
        request.get_data() or b"",
    )


class InMemoryIdempotencyStore:
    """Deterministic, thread-safe in-memory idempotency store for race simulation.

    Models ``idempotency_records`` contention (duplicate submission, in-flight
    ``PENDING`` collision, and worker replacement fencing) without requiring a
    live PostgreSQL connection or external network calls.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_id = 1
        self._records_by_id: dict[int, dict[str, Any]] = {}
        self._index: dict[tuple[str, str], int] = {}

    def acquire(
        self,
        request_digest: str,
        request_type: str,
        *,
        worker_id: str | None = None,
        expires_at: Optional[datetime.datetime] = None,
    ) -> tuple[int, str, bool, int]:
        """Atomically insert or inspect an idempotency record.

        Returns ``(record_id, status, acquired, generation)``.
        """
        if expires_at is None:
            expires_at = _default_expiry()
        key = (request_digest, request_type)
        with self._lock:
            existing_id = self._index.get(key)
            if existing_id is not None:
                existing = self._records_by_id[existing_id]
                return (
                    int(existing["id"]),
                    str(existing["status"]),
                    False,
                    int(existing["generation"]),
                )
            record_id = self._next_id
            self._next_id += 1
            record: dict[str, Any] = {
                "id": record_id,
                "request_digest": request_digest,
                "request_type": request_type,
                "created_at": _now(),
                "expires_at": expires_at,
                "status": "PENDING",
                "response_payload": None,
                "error_payload": None,
                "worker_id": worker_id,
                "generation": 1,
            }
            self._records_by_id[record_id] = record
            self._index[key] = record_id
            return record_id, "PENDING", True, 1

    def replace_stalled_worker(self, record_id: int, *, new_worker_id: str) -> int:
        """Advance attempt generation on a stalled ``PENDING`` record for a replacement worker."""
        with self._lock:
            record = self._records_by_id.get(record_id)
            if record is None:
                raise KeyError(f"unknown idempotency record: {record_id}")
            if record["status"] != "PENDING":
                raise ValueError("cannot replace worker on a terminal idempotency record")
            next_gen = int(record["generation"]) + 1
            record["generation"] = next_gen
            record["worker_id"] = new_worker_id
            return next_gen

    def complete(
        self,
        record_id: int,
        payload: Any,
        *,
        expected_generation: int | None = None,
        worker_id: str | None = None,
    ) -> bool:
        """Mark a ``PENDING`` record ``COMPLETED`` when generation/worker fencing matches."""
        with self._lock:
            record = self._records_by_id.get(record_id)
            if record is None or record["status"] != "PENDING":
                return False
            if expected_generation is not None and int(record["generation"]) != int(expected_generation):
                return False
            if worker_id is not None and record.get("worker_id") not in (None, worker_id):
                return False
            record["status"] = "COMPLETED"
            record["response_payload"] = payload
            record["error_payload"] = None
            return True

    def fail(
        self,
        record_id: int,
        error: dict[str, Any],
        *,
        expected_generation: int | None = None,
        worker_id: str | None = None,
    ) -> bool:
        """Mark a ``PENDING`` record ``FAILED`` when generation/worker fencing matches."""
        with self._lock:
            record = self._records_by_id.get(record_id)
            if record is None or record["status"] != "PENDING":
                return False
            if expected_generation is not None and int(record["generation"]) != int(expected_generation):
                return False
            if worker_id is not None and record.get("worker_id") not in (None, worker_id):
                return False
            record["status"] = "FAILED"
            record["error_payload"] = dict(error)
            record["response_payload"] = None
            return True

    def clear_pending(
        self,
        record_id: int,
        *,
        expected_generation: int | None = None,
    ) -> bool:
        """Delete a ``PENDING`` record so a retry may re-acquire cleanly."""
        with self._lock:
            record = self._records_by_id.get(record_id)
            if record is None or record["status"] != "PENDING":
                return False
            if expected_generation is not None and int(record["generation"]) != int(expected_generation):
                return False
            key = (str(record["request_digest"]), str(record["request_type"]))
            self._index.pop(key, None)
            self._records_by_id.pop(record_id, None)
            return True

    def get_record(self, request_digest: str, request_type: str) -> Optional[dict[str, Any]]:
        with self._lock:
            record_id = self._index.get((request_digest, request_type))
            if record_id is None:
                return None
            return dict(self._records_by_id[record_id])


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


def _replay_stored(record: dict):
    status = record.get("status")
    if status == "COMPLETED":
        payload = record.get("response_payload") or {}
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

    Uses a canonical request digest. Completed records replay the stored JSON
    body and HTTP status. Pending records return 409. When DATABASE_URL is
    unset (local/unit tests), the decorator is a no-op so callers still rely
    on semantic upsert idempotency in the register path.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not _db_available():
                return func(*args, **kwargs)

            digest = _canonical_digest()
            record = get_idempotency_record(digest, request_type)
            if record:
                return _replay_stored(record)

            record_id, status = create_idempotency_record(digest, request_type)
            if status != "PENDING":
                # Lost the race to another worker that already finished (or is in flight).
                existing = get_idempotency_record(digest, request_type) or {
                    "status": status,
                    "response_payload": None,
                    "error_payload": None,
                }
                return _replay_stored(existing)

            try:
                result = func(*args, **kwargs)
                body, code = _extract_response_parts(result)
                if 200 <= code < 500:
                    # Cache 2xx and stable 4xx for exact replay (no raw media/secrets).
                    store_response(record_id, {"status": code, "body": body})
                else:
                    # Do not cache server failures — allow a later retry to re-acquire.
                    clear_idempotency_record(record_id)
                return result
            except Exception:
                # Privacy-safe: never persist exception strings (may contain paths/secrets).
                store_error(record_id, {"error": "request processing failed", "status": 500})
                raise

        return wrapper

    return decorator
