from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import datetime
import functools
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import threading
from typing import Any, Mapping, Optional, Tuple

from flask import Response, jsonify, request

from db import Jsonb, get_connection
from strkey import validate_contract_id, validate_source_address


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


def _canonical_digest() -> str:
    """SHA-256 of method, path, query string, and raw body (canonical request identity)."""
    method = request.method.encode()
    path = request.path.encode()
    query = request.query_string  # already bytes
    body = request.get_data() or b""
    data = b"|".join([method, path, query, body])
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


STATEMENT_SCHEMA_VERSION = "harpocrates.evidence-statement.v1"
STATEMENT_INTENT_DOMAIN = "harpocrates:evidence-statement-intent:v1:"
INTENT_OWNER_DOMAIN = "harpocrates:intent-owner:v1:"
INTENT_REQUEST_TYPE = "registration_intent"
ALLOWED_STATEMENT_TIERS = frozenset({"silent", "source", "seal"})
DEFAULT_INTENT_MAX_ENTRIES = 4096


def _normalize_hex_32(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a 32-byte hex string")
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 64 or not all(ch in "0123456789abcdef" for ch in cleaned):
        raise ValueError(f"{field_name} must be a 32-byte hex string")
    return cleaned


def _owner_binding_digest(source_address: str) -> str:
    cleaned = source_address.strip()
    if not cleaned:
        return ""
    return hashlib.sha256((INTENT_OWNER_DOMAIN + cleaned).encode("utf-8")).hexdigest()


class StatementIntentConflictError(ValueError):
    """Raised when a registration transaction or proof intent is re-bound to a different statement."""

    def __init__(
        self,
        *,
        proof_id: str,
        existing_digest: str,
        incoming_digest: str,
        tx_hash: str | None = None,
    ) -> None:
        super().__init__("registration intent conflicts with previously approved evidence statement")
        self.proof_id = proof_id
        self.tx_hash = tx_hash
        self.existing_digest = existing_digest
        self.incoming_digest = incoming_digest


@dataclass(frozen=True)
class CanonicalEvidenceStatement:
    """Canonical protocol statement bound to an approved registration request."""

    proof_id: str
    video_hash: str
    metadata_hash: str
    tier: str
    source_address: str = ""
    contract_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "proof_id", _normalize_hex_32(self.proof_id, "proofId"))
        object.__setattr__(self, "video_hash", _normalize_hex_32(self.video_hash, "videoHash"))
        object.__setattr__(
            self, "metadata_hash", _normalize_hex_32(self.metadata_hash, "metadataHash")
        )
        if not isinstance(self.tier, str) or self.tier not in ALLOWED_STATEMENT_TIERS:
            raise ValueError("tier must be one of: silent, source, seal")
        raw_source = self.source_address or ""
        if raw_source:
            validated_source = validate_source_address(raw_source) or ""
        else:
            validated_source = ""
        object.__setattr__(self, "source_address", validated_source)

        raw_contract = self.contract_id or ""
        if raw_contract:
            validated_contract = validate_contract_id(raw_contract) or ""
        else:
            validated_contract = ""
        object.__setattr__(self, "contract_id", validated_contract)

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
        *,
        default_source_address: str | None = None,
        default_contract_id: str | None = None,
    ) -> CanonicalEvidenceStatement:
        if not isinstance(payload, Mapping):
            raise ValueError("evidence statement must be a mapping")
        proof_id = payload.get("proofId") if "proofId" in payload else payload.get("proof_id")
        video_hash = payload.get("videoHash") if "videoHash" in payload else payload.get("video_hash")
        metadata_hash = (
            payload.get("metadataHash")
            if "metadataHash" in payload
            else payload.get("metadata_hash")
        )
        tier = payload.get("tier")
        if "sourceAddress" in payload:
            source_raw = payload.get("sourceAddress")
        elif "source_address" in payload:
            source_raw = payload.get("source_address")
        else:
            source_raw = default_source_address
        if "contractId" in payload:
            contract_raw = payload.get("contractId")
        elif "contract_id" in payload:
            contract_raw = payload.get("contract_id")
        else:
            contract_raw = default_contract_id

        if source_raw is not None and not isinstance(source_raw, str):
            raise ValueError("sourceAddress must be a string")
        if contract_raw is not None and not isinstance(contract_raw, str):
            raise ValueError("contractId must be a string")

        return cls(
            proof_id=proof_id,  # type: ignore[arg-type]
            video_hash=video_hash,  # type: ignore[arg-type]
            metadata_hash=metadata_hash,  # type: ignore[arg-type]
            tier=tier,  # type: ignore[arg-type]
            source_address=source_raw or "",
            contract_id=contract_raw or "",
        )

    def canonical_dict(self) -> dict[str, str]:
        return {
            "contractId": self.contract_id,
            "metadataHash": self.metadata_hash,
            "proofId": self.proof_id,
            "schema": STATEMENT_SCHEMA_VERSION,
            "sourceAddress": self.source_address,
            "tier": self.tier,
            "videoHash": self.video_hash,
        }

    def canonical_bytes(self) -> bytes:
        encoded = json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return STATEMENT_INTENT_DOMAIN.encode("utf-8") + encoded

    def intent_digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def compute_statement_intent_digest(
    statement: CanonicalEvidenceStatement | Mapping[str, Any],
) -> str:
    """Return the canonical 32-byte hex intent digest for an evidence statement."""
    parsed = (
        statement
        if isinstance(statement, CanonicalEvidenceStatement)
        else CanonicalEvidenceStatement.from_mapping(statement)
    )
    return parsed.intent_digest()


@dataclass(frozen=True)
class PersistedRegistrationIntent:
    """Privacy-safe persisted registration statement intent."""

    intent_digest: str
    proof_id: str
    tier: str
    tx_hash: str | None = None
    contract_id: str = ""
    owner_digest: str = ""
    recorded_at: str = ""

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "intentDigest": self.intent_digest,
            "proofId": self.proof_id,
            "tier": self.tier,
            "txHash": self.tx_hash,
            "contractId": self.contract_id,
            "ownerDigest": self.owner_digest,
            "recordedAt": self.recorded_at,
        }

    @classmethod
    def from_storage_dict(cls, raw: Mapping[str, Any]) -> PersistedRegistrationIntent:
        intent_digest = _normalize_hex_32(raw.get("intentDigest"), "intentDigest")
        proof_id = _normalize_hex_32(raw.get("proofId"), "proofId")
        tier = str(raw.get("tier") or "")
        if tier not in ALLOWED_STATEMENT_TIERS:
            raise ValueError("invalid stored tier")
        tx_raw = raw.get("txHash")
        tx_hash = _normalize_hex_32(tx_raw, "txHash") if tx_raw is not None else None
        contract_id = str(raw.get("contractId") or "")
        if contract_id:
            contract_id = validate_contract_id(contract_id) or ""
        owner_digest = str(raw.get("ownerDigest") or "")
        if owner_digest:
            owner_digest = _normalize_hex_32(owner_digest, "ownerDigest")
        recorded_at = str(raw.get("recordedAt") or "")
        return cls(
            intent_digest=intent_digest,
            proof_id=proof_id,
            tier=tier,
            tx_hash=tx_hash,
            contract_id=contract_id,
            owner_digest=owner_digest,
            recorded_at=recorded_at,
        )

    def public_view(self) -> dict[str, Any]:
        """Return non-sensitive fields suitable for administrative or client responses."""
        return {
            "intentDigest": self.intent_digest,
            "proofId": self.proof_id,
            "tier": self.tier,
            "txHash": self.tx_hash,
            "contractId": self.contract_id or None,
            "recordedAt": self.recorded_at,
        }


def _intent_max_entries() -> int:
    raw = os.getenv("REGISTRATION_INTENT_MAX_ENTRIES")
    if raw is None or not raw.strip():
        return DEFAULT_INTENT_MAX_ENTRIES
    try:
        parsed = int(raw.strip())
    except ValueError:
        return DEFAULT_INTENT_MAX_ENTRIES
    return max(16, min(parsed, 100_000))


def _intent_store_path(explicit_path: Path | str | None = None) -> Path | None:
    if explicit_path is not None:
        return Path(explicit_path)
    raw = os.getenv("REGISTRATION_INTENT_STORE_PATH")
    if raw and raw.strip():
        return Path(raw.strip())
    return None


def _intent_db_key(*, tx_hash: str | None, proof_id: str) -> str:
    if tx_hash:
        return f"tx:{tx_hash}"
    return f"proof:{proof_id}"


class RegistrationIntentStore:
    """Bounded, privacy-safe store persisting canonical statement digests before tx verification."""

    def __init__(
        self,
        *,
        max_entries: int | None = None,
        store_path: Path | str | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._explicit_max = max_entries
        self._explicit_path = Path(store_path) if store_path is not None else None
        self._by_tx: OrderedDict[str, PersistedRegistrationIntent] = OrderedDict()
        self._by_proof: OrderedDict[str, PersistedRegistrationIntent] = OrderedDict()
        self._loaded_path: Path | None = None

    def _effective_max(self) -> int:
        if self._explicit_max is not None:
            return max(1, int(self._explicit_max))
        return _intent_max_entries()

    def _effective_path(self) -> Path | None:
        return _intent_store_path(self._explicit_path)

    def _ensure_loaded_locked(self) -> None:
        path = self._effective_path()
        if path is None or self._loaded_path == path:
            return
        self._loaded_path = path
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        for item in payload.get("intents", []):
            if not isinstance(item, Mapping):
                continue
            try:
                record = PersistedRegistrationIntent.from_storage_dict(item)
            except ValueError:
                continue
            if record.tx_hash:
                self._by_tx[record.tx_hash] = record
            self._by_proof[record.proof_id] = record
        self._trim_locked()

    def _flush_locked(self) -> None:
        path = self._effective_path()
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        seen: OrderedDict[tuple[str | None, str], dict[str, Any]] = OrderedDict()
        for rec in self._by_tx.values():
            seen[(rec.tx_hash, rec.proof_id)] = rec.to_storage_dict()
        for rec in self._by_proof.values():
            seen.setdefault((rec.tx_hash, rec.proof_id), rec.to_storage_dict())
        serialized = json.dumps(
            {"version": 1, "intents": list(seen.values())},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".intent_", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(serialized)
            try:
                os.chmod(tmp_name, 0o600)
            except OSError:
                pass
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _trim_locked(self) -> None:
        cap = self._effective_max()
        while len(self._by_tx) > cap:
            self._by_tx.popitem(last=False)
        while len(self._by_proof) > cap:
            self._by_proof.popitem(last=False)

    def _persist_db(self, record: PersistedRegistrationIntent, *, allow_overwrite: bool) -> None:
        if not _db_available():
            return
        db_key = _intent_db_key(tx_hash=record.tx_hash, proof_id=record.proof_id)
        existing = get_idempotency_record(db_key, INTENT_REQUEST_TYPE)
        if existing and existing.get("status") == "COMPLETED":
            stored_payload = existing.get("response_payload")
            if isinstance(stored_payload, Mapping):
                existing_digest = str(stored_payload.get("intentDigest") or "")
                if existing_digest and not hmac.compare_digest(
                    existing_digest, record.intent_digest
                ):
                    if not allow_overwrite:
                        raise StatementIntentConflictError(
                            proof_id=record.proof_id,
                            tx_hash=record.tx_hash,
                            existing_digest=existing_digest,
                            incoming_digest=record.intent_digest,
                        )
                elif existing_digest:
                    return
        rec_id, _status = create_idempotency_record(db_key, INTENT_REQUEST_TYPE)
        store_response(rec_id, record.to_storage_dict())

    def _lookup_db(
        self,
        *,
        tx_hash: str | None,
        proof_id: str | None,
    ) -> PersistedRegistrationIntent | None:
        if not _db_available():
            return None
        candidates: list[str] = []
        if tx_hash:
            candidates.append(f"tx:{tx_hash}")
        if proof_id:
            candidates.append(f"proof:{proof_id}")
        for key in candidates:
            existing = get_idempotency_record(key, INTENT_REQUEST_TYPE)
            if not existing or existing.get("status") != "COMPLETED":
                continue
            payload = existing.get("response_payload")
            if isinstance(payload, Mapping):
                try:
                    return PersistedRegistrationIntent.from_storage_dict(payload)
                except ValueError:
                    continue
        return None

    def persist_intent(
        self,
        statement: CanonicalEvidenceStatement | Mapping[str, Any],
        *,
        tx_hash: str | None = None,
        strict_proof_binding: bool = False,
        allow_overwrite: bool = False,
    ) -> PersistedRegistrationIntent:
        parsed = (
            statement
            if isinstance(statement, CanonicalEvidenceStatement)
            else CanonicalEvidenceStatement.from_mapping(statement)
        )
        normalized_tx = _normalize_hex_32(tx_hash, "txHash") if tx_hash else None
        digest = parsed.intent_digest()
        owner_digest = _owner_binding_digest(parsed.source_address)
        recorded_at = _now().isoformat()

        record = PersistedRegistrationIntent(
            intent_digest=digest,
            proof_id=parsed.proof_id,
            tier=parsed.tier,
            tx_hash=normalized_tx,
            contract_id=parsed.contract_id,
            owner_digest=owner_digest,
            recorded_at=recorded_at,
        )

        with self._lock:
            self._ensure_loaded_locked()
            if normalized_tx and normalized_tx in self._by_tx:
                existing = self._by_tx[normalized_tx]
                if hmac.compare_digest(existing.intent_digest, digest):
                    self._by_tx.move_to_end(normalized_tx)
                    return existing
                if not allow_overwrite:
                    raise StatementIntentConflictError(
                        proof_id=parsed.proof_id,
                        tx_hash=normalized_tx,
                        existing_digest=existing.intent_digest,
                        incoming_digest=digest,
                    )

            if strict_proof_binding and parsed.proof_id in self._by_proof:
                existing_proof = self._by_proof[parsed.proof_id]
                if not hmac.compare_digest(existing_proof.intent_digest, digest):
                    if not allow_overwrite:
                        raise StatementIntentConflictError(
                            proof_id=parsed.proof_id,
                            tx_hash=normalized_tx,
                            existing_digest=existing_proof.intent_digest,
                            incoming_digest=digest,
                        )

            self._persist_db(record, allow_overwrite=allow_overwrite)

            if normalized_tx:
                self._by_tx[normalized_tx] = record
                self._by_tx.move_to_end(normalized_tx)
            self._by_proof[parsed.proof_id] = record
            self._by_proof.move_to_end(parsed.proof_id)
            self._trim_locked()
            self._flush_locked()
            return record

    def lookup_intent(
        self,
        *,
        tx_hash: str | None = None,
        proof_id: str | None = None,
    ) -> PersistedRegistrationIntent | None:
        normalized_tx = _normalize_hex_32(tx_hash, "txHash") if tx_hash else None
        normalized_proof = _normalize_hex_32(proof_id, "proofId") if proof_id else None

        with self._lock:
            self._ensure_loaded_locked()
            if normalized_tx and normalized_tx in self._by_tx:
                rec = self._by_tx[normalized_tx]
                self._by_tx.move_to_end(normalized_tx)
                return rec
            if normalized_proof and normalized_proof in self._by_proof:
                rec = self._by_proof[normalized_proof]
                if normalized_tx is None or rec.tx_hash in (None, normalized_tx):
                    self._by_proof.move_to_end(normalized_proof)
                    return rec

            db_rec = self._lookup_db(tx_hash=normalized_tx, proof_id=normalized_proof)
            if db_rec is not None:
                if db_rec.tx_hash:
                    self._by_tx[db_rec.tx_hash] = db_rec
                self._by_proof[db_rec.proof_id] = db_rec
                self._trim_locked()
            return db_rec

    def clear(self) -> None:
        with self._lock:
            self._by_tx.clear()
            self._by_proof.clear()
            self._loaded_path = None


_DEFAULT_INTENT_STORE = RegistrationIntentStore()


def persist_registration_intent(
    statement: CanonicalEvidenceStatement | Mapping[str, Any],
    *,
    tx_hash: str | None = None,
    strict_proof_binding: bool = False,
    allow_overwrite: bool = False,
) -> PersistedRegistrationIntent:
    """Persist the approved canonical statement digest prior to transaction verification."""
    return _DEFAULT_INTENT_STORE.persist_intent(
        statement,
        tx_hash=tx_hash,
        strict_proof_binding=strict_proof_binding,
        allow_overwrite=allow_overwrite,
    )


def get_registration_intent(
    *,
    tx_hash: str | None = None,
    proof_id: str | None = None,
) -> PersistedRegistrationIntent | None:
    """Retrieve a previously persisted canonical statement intent."""
    return _DEFAULT_INTENT_STORE.lookup_intent(tx_hash=tx_hash, proof_id=proof_id)


def reset_registration_intents() -> None:
    """Clear in-memory cached registration intents (intended for tests)."""
    _DEFAULT_INTENT_STORE.clear()
