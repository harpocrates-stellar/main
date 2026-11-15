from __future__ import annotations

from collections import OrderedDict
import datetime
import functools
import hashlib
import json
import threading
from typing import Any, Mapping, Optional, Tuple

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


ALLOWED_IDENTITY_TIERS = frozenset({"silent", "source", "seal"})
CANONICAL_BINDING_DOMAIN = b"harpocrates:registration-idempotency-binding:v1"
CLIENT_KEY_HASH_DOMAIN = b"harpocrates:client-idempotency-key:v1"
MAX_CLIENT_IDEMPOTENCY_KEY_LEN = 128
MAX_TRACKED_KEY_BINDINGS = 4096


class RegistrationKeyConflictError(Exception):
    """Raised when a registration key or Idempotency-Key is reused with changed tier or fields."""

    def __init__(self, *, field: str, code: str = "IDEMPOTENCY_CONFLICT") -> None:
        super().__init__(f"idempotency key reused with conflicting value for '{field}'")
        self.field = field
        self.code = code


def normalize_identity_tier(tier: object) -> str:
    """Validate and canonicalize an identity tier (`silent`, `source`, or `seal`)."""
    if not isinstance(tier, str):
        raise ValueError("tier must be one of: silent, source, seal")
    normalized = tier.strip().lower()
    if normalized not in ALLOWED_IDENTITY_TIERS:
        raise ValueError("tier must be one of: silent, source, seal")
    return normalized


def normalize_client_idempotency_key(raw_key: object) -> str | None:
    """Validate optional client ``Idempotency-Key`` header and return its SHA-256 digest."""
    if raw_key is None:
        return None
    if not isinstance(raw_key, str):
        raise ValueError("Idempotency-Key must be a printable ASCII string")
    cleaned = raw_key.strip()
    if not cleaned:
        return None
    if len(cleaned) > MAX_CLIENT_IDEMPOTENCY_KEY_LEN:
        raise ValueError(f"Idempotency-Key exceeds {MAX_CLIENT_IDEMPOTENCY_KEY_LEN} characters")
    if not all(33 <= ord(ch) <= 126 or ch == " " for ch in cleaned):
        raise ValueError("Idempotency-Key contains invalid control or non-ASCII characters")
    hasher = hashlib.sha256()
    hasher.update(CLIENT_KEY_HASH_DOMAIN)
    encoded = cleaned.encode("ascii")
    hasher.update(len(encoded).to_bytes(4, "big"))
    hasher.update(encoded)
    return hasher.hexdigest()


def canonical_registration_idempotency_binding(
    *,
    video_hash: str | None,
    metadata_hash: str | None,
    proof_id: str | None,
    tier: str,
    tx_hash: str | None = None,
    source_address: str | None = None,
    contract_id: str | None = None,
) -> str:
    """Compute canonical domain-separated idempotency binding digest including ``tier``."""
    canonical_tier = normalize_identity_tier(tier)
    fields = (
        (video_hash or "").strip().lower(),
        (metadata_hash or "").strip().lower(),
        (proof_id or "").strip().lower(),
        canonical_tier,
        (tx_hash or "").strip().lower(),
        (source_address or "").strip().upper(),
        (contract_id or "").strip().upper(),
    )
    hasher = hashlib.sha256()
    hasher.update(CANONICAL_BINDING_DOMAIN)
    for part in fields:
        raw = part.encode("utf-8")
        hasher.update(len(raw).to_bytes(4, "big"))
        hasher.update(raw)
    return hasher.hexdigest()


class RegistrationKeyBindingRegistry:
    """Bounded in-process registry enforcing tier-bound registration key reuse."""

    def __init__(self, max_entries: int = MAX_TRACKED_KEY_BINDINGS) -> None:
        self._lock = threading.Lock()
        self._max_entries = max(1, int(max_entries))
        self._bindings: OrderedDict[str, dict[str, str]] = OrderedDict()

    def _evict_if_needed(self) -> None:
        while len(self._bindings) > self._max_entries:
            self._bindings.popitem(last=False)

    @staticmethod
    def _compare(existing: Mapping[str, str], incoming: Mapping[str, str]) -> None:
        if existing["tier"] != incoming["tier"]:
            raise RegistrationKeyConflictError(
                field="tier",
                code="REGISTRATION_TIER_CONFLICT",
            )
        for field in (
            "proof_id",
            "video_hash",
            "metadata_hash",
            "tx_hash",
            "source_address",
            "contract_id",
            "binding_digest",
        ):
            if existing.get(field, "") != incoming.get(field, ""):
                raise RegistrationKeyConflictError(field=field)

    def check_only(
        self,
        *,
        slot_keys: tuple[str, ...],
        tier: str,
        statement: Mapping[str, str | None],
    ) -> bool:
        canonical_tier = normalize_identity_tier(tier)
        binding_digest = canonical_registration_idempotency_binding(
            video_hash=statement.get("video_hash"),
            metadata_hash=statement.get("metadata_hash"),
            proof_id=statement.get("proof_id"),
            tier=canonical_tier,
            tx_hash=statement.get("tx_hash"),
            source_address=statement.get("source_address"),
            contract_id=statement.get("contract_id"),
        )
        incoming = {
            "tier": canonical_tier,
            "proof_id": (statement.get("proof_id") or "").strip().lower(),
            "video_hash": (statement.get("video_hash") or "").strip().lower(),
            "metadata_hash": (statement.get("metadata_hash") or "").strip().lower(),
            "tx_hash": (statement.get("tx_hash") or "").strip().lower(),
            "source_address": (statement.get("source_address") or "").strip().upper(),
            "contract_id": (statement.get("contract_id") or "").strip().upper(),
            "binding_digest": binding_digest,
        }
        found_exact = False
        with self._lock:
            for slot in slot_keys:
                existing = self._bindings.get(slot)
                if existing is not None:
                    self._compare(existing, incoming)
                    found_exact = True
        return found_exact

    def bind(
        self,
        *,
        slot_keys: tuple[str, ...],
        tier: str,
        statement: Mapping[str, str | None],
    ) -> tuple[str, bool]:
        """Validate or record canonical binding across ``slot_keys``.

        Returns ``(binding_digest, already_bound)``. Raises
        :class:`RegistrationKeyConflictError` when any slot key is reused with a
        different ``tier`` or conflicting canonical statement field.
        """
        canonical_tier = normalize_identity_tier(tier)
        binding_digest = canonical_registration_idempotency_binding(
            video_hash=statement.get("video_hash"),
            metadata_hash=statement.get("metadata_hash"),
            proof_id=statement.get("proof_id"),
            tier=canonical_tier,
            tx_hash=statement.get("tx_hash"),
            source_address=statement.get("source_address"),
            contract_id=statement.get("contract_id"),
        )
        incoming = {
            "tier": canonical_tier,
            "proof_id": (statement.get("proof_id") or "").strip().lower(),
            "video_hash": (statement.get("video_hash") or "").strip().lower(),
            "metadata_hash": (statement.get("metadata_hash") or "").strip().lower(),
            "tx_hash": (statement.get("tx_hash") or "").strip().lower(),
            "source_address": (statement.get("source_address") or "").strip().upper(),
            "contract_id": (statement.get("contract_id") or "").strip().upper(),
            "binding_digest": binding_digest,
        }
        with self._lock:
            already_bound = False
            for slot in slot_keys:
                existing = self._bindings.get(slot)
                if existing is not None:
                    self._compare(existing, incoming)
                    already_bound = True
            for slot in slot_keys:
                self._bindings[slot] = dict(incoming)
                self._bindings.move_to_end(slot)
            self._evict_if_needed()
            return binding_digest, already_bound

    def clear(self) -> None:
        with self._lock:
            self._bindings.clear()


_KEY_BINDING_REGISTRY = RegistrationKeyBindingRegistry()


def check_registration_key_binding(
    *,
    registration_key: str,
    client_key_digest: str | None = None,
    tier: str,
    statement: Mapping[str, str | None],
) -> bool:
    slots = [f"reg:{registration_key}"]
    if client_key_digest:
        slots.append(f"hdr:{client_key_digest}")
    return _KEY_BINDING_REGISTRY.check_only(
        slot_keys=tuple(slots),
        tier=tier,
        statement=statement,
    )


def record_registration_key_binding(
    *,
    registration_key: str,
    client_key_digest: str | None = None,
    tier: str,
    statement: Mapping[str, str | None],
) -> tuple[str, bool]:
    slots = [f"reg:{registration_key}"]
    if client_key_digest:
        slots.append(f"hdr:{client_key_digest}")
    return _KEY_BINDING_REGISTRY.bind(
        slot_keys=tuple(slots),
        tier=tier,
        statement=statement,
    )


def reset_registration_key_bindings_for_tests() -> None:
    _KEY_BINDING_REGISTRY.clear()


def _canonical_digest() -> str:
    """SHA-256 of method, path, query string, identity tier, client key digest, and raw body."""
    method = request.method.encode()
    path = request.path.encode()
    query = request.query_string  # already bytes
    body = request.get_data() or b""
    tier_bytes = b""
    if body:
        parsed = request.get_json(silent=True)
        if isinstance(parsed, dict) and isinstance(parsed.get("tier"), str):
            tier_bytes = parsed["tier"].strip().lower().encode("utf-8")
    raw_hdr_key = request.headers.get("Idempotency-Key")
    hdr_digest = b""
    if isinstance(raw_hdr_key, str) and raw_hdr_key.strip():
        try:
            normalized_hdr = normalize_client_idempotency_key(raw_hdr_key)
            if normalized_hdr:
                hdr_digest = normalized_hdr.encode("ascii")
        except ValueError:
            hdr_digest = b"invalid"
    data = b"|".join([method, path, query, tier_bytes, hdr_digest, body])
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
