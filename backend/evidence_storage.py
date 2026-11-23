from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Tuple
import uuid
from cryptography.fernet import Fernet, InvalidToken
import db
import storage
from storage import _parse_timestamp

DEFAULT_VERIFY_BATCH_SIZE = 50
MAX_VERIFY_BATCH_SIZE = 500
PROGRESS_SCHEMA_VERSION = 1

STATUS_VERIFIED = "verified"
STATUS_FAILED = "failed"
STATUS_UNVERIFIABLE_LEGACY = "unverifiable_legacy"

ENVELOPE_VERSION_FERNET_V1 = "fernet-v1"
DEFAULT_ENVELOPE_VERSION = ENVELOPE_VERSION_FERNET_V1
SUPPORTED_ENVELOPE_VERSIONS: frozenset[str] = frozenset({ENVELOPE_VERSION_FERNET_V1})
KNOWN_LEGACY_ENVELOPE_VERSIONS: frozenset[str] = frozenset({"legacy-v0", "fernet-v0"})

ENVELOPE_CLASS_SUPPORTED = "supported"
ENVELOPE_CLASS_LEGACY = "legacy"
ENVELOPE_CLASS_UNSUPPORTED = "unsupported"

_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

logger = logging.getLogger("harpocrates.evidence_storage")

EXPORT_MANIFEST_VERSION = 1
DEFAULT_ENVELOPE_VERSION = "fernet-v1"
_HEX_32_PATTERN = re.compile(r"[0-9a-fA-F]{64}")


class UnsupportedEnvelopeVersionError(ValueError):
    """Raised when an encryption envelope version is unknown or unsupported."""


class LegacyEnvelopeVersionError(ValueError):
    """Raised when a known legacy envelope version cannot be decrypted directly."""


def classify_envelope_version(envelope_version: object) -> str:
    """Classify an encryption envelope version as supported, known legacy, or unsupported.

    A ``None`` value represents a pre-versioning legacy metadata row and is
    classified as ``legacy``. Explicit legacy identifiers in
    ``KNOWN_LEGACY_ENVELOPE_VERSIONS`` are also classified as ``legacy``.
    Any other unrecognized, empty, or non-string value is ``unsupported``.
    """
    if envelope_version is None:
        return ENVELOPE_CLASS_LEGACY
    if not isinstance(envelope_version, str):
        return ENVELOPE_CLASS_UNSUPPORTED
    normalized = envelope_version.strip()
    if normalized in SUPPORTED_ENVELOPE_VERSIONS:
        return ENVELOPE_CLASS_SUPPORTED
    if normalized in KNOWN_LEGACY_ENVELOPE_VERSIONS:
        return ENVELOPE_CLASS_LEGACY
    return ENVELOPE_CLASS_UNSUPPORTED


def validate_envelope_version(envelope_version: object) -> str:
    """Validate and return a supported envelope version for new evidence blobs."""
    if not isinstance(envelope_version, str):
        raise UnsupportedEnvelopeVersionError("envelope_version must be a supported string identifier")
    normalized = envelope_version.strip()
    if normalized in SUPPORTED_ENVELOPE_VERSIONS:
        return normalized
    if normalized in KNOWN_LEGACY_ENVELOPE_VERSIONS:
        raise LegacyEnvelopeVersionError(
            f"legacy envelope_version {normalized!r} cannot be used for new evidence blobs"
        )
    raise UnsupportedEnvelopeVersionError(f"unsupported envelope_version: {envelope_version!r}")


def generate_dek() -> Tuple[bytes, bytes]:
    """Generates a Data Encryption Key (DEK) and its encrypted form (using a Master Key)."""
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        master_key_b64 = Fernet.generate_key().decode()
    f = Fernet(master_key_b64.encode())

    dek = Fernet.generate_key()
    encrypted_dek = f.encrypt(dek)

    return dek, encrypted_dek


class LegacyEnvelopeVersionError(ValueError):
    """Raised when a known legacy envelope version cannot be decrypted directly."""


def get_encryptor(dek: bytes, envelope_version: str = DEFAULT_ENVELOPE_VERSION):
    validated = validate_envelope_version(envelope_version)
    if validated == ENVELOPE_VERSION_FERNET_V1:
        return Fernet(dek)
    raise UnsupportedEnvelopeVersionError(f"unsupported envelope_version: {envelope_version!r}")


def decrypt_blob_ciphertext(
    dek: bytes,
    ciphertext: bytes,
    *,
    envelope_version: object = DEFAULT_ENVELOPE_VERSION,
) -> bytes:
    """Decrypt blob ciphertext using only the algorithm declared by ``envelope_version``.

    Never inspects or guesses a decryption algorithm from malformed ciphertext.
    A ``None`` ``envelope_version`` represents a pre-versioning legacy Fernet
    row and is decrypted strictly with Fernet (no fallback). Explicit known
    legacy versions raise ``LegacyEnvelopeVersionError``; unknown or malformed
    version identifiers raise ``UnsupportedEnvelopeVersionError``.
    """
    if envelope_version is None:
        return Fernet(dek).decrypt(ciphertext)

    classification = classify_envelope_version(envelope_version)
    if classification == ENVELOPE_CLASS_SUPPORTED:
        normalized = envelope_version.strip()  # type: ignore[union-attr]
        if normalized == ENVELOPE_VERSION_FERNET_V1:
            return Fernet(dek).decrypt(ciphertext)
    if classification == ENVELOPE_CLASS_LEGACY:
        raise LegacyEnvelopeVersionError(
            f"known legacy envelope_version cannot be decrypted directly: {envelope_version!r}"
        )
    raise UnsupportedEnvelopeVersionError(
        f"unsupported envelope_version: {envelope_version!r}"
    )


def record_blob(
    content_hash: str,
    encrypted_dek: bytes,
    size_bytes: int,
    storage_path: str,
    envelope_version: str = DEFAULT_ENVELOPE_VERSION,
):
    validated_version = validate_envelope_version(envelope_version)
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                insert into blobs (content_hash, encrypted_dek, size_bytes, storage_path, envelope_version)
                values (%s, %s, %s, %s, %s)
                on conflict (content_hash) do nothing
                """,
                (content_hash, encrypted_dek.decode(), size_bytes, storage_path, validated_version),
            )
        conn.commit()


def record_tenant_ref(tenant_id: str, content_hash: str):
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                insert into tenant_blob_refs (tenant_id, content_hash, ref_count)
                values (%s, %s, 1)
                on conflict (tenant_id, content_hash) do update
                set ref_count = tenant_blob_refs.ref_count + 1, updated_at = now()
                """,
                (tenant_id, content_hash)
            )
        conn.commit()


def remove_tenant_ref(tenant_id: str, content_hash: str) -> bool:
    """Remove or decrement a tenant's reference to an encrypted evidence blob."""
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select ref_count from tenant_blob_refs
                where tenant_id = %s and content_hash = %s
                for update
                """,
                (tenant_id, content_hash)
            )
            row = cursor.fetchone()
            if not row:
                conn.commit()
                return False

            ref_count = row["ref_count"] if isinstance(row, dict) else row[0]
            if ref_count > 1:
                cursor.execute(
                    """
                    update tenant_blob_refs
                    set ref_count = ref_count - 1, updated_at = now()
                    where tenant_id = %s and content_hash = %s
                    """,
                    (tenant_id, content_hash)
                )
            else:
                cursor.execute(
                    """
                    delete from tenant_blob_refs
                    where tenant_id = %s and content_hash = %s
                    """,
                    (tenant_id, content_hash)
                )
        conn.commit()
    return True


def collect_unreferenced_blobs(limit: int = 100) -> int:
    """Transactionally delete blob rows and files that have zero references.

    Uses SELECT ... FOR UPDATE to avoid races with concurrent record_tenant_ref.
    Deletes the underlying file first; if file deletion fails, the blob row
    is left intact so the deletion will be retried on the next run.
    Deletions are recorded in metrics without exposing content hashes.
    """
    if envelope_version is None:
        return ENVELOPE_CLASS_LEGACY
    if not isinstance(envelope_version, str):
        return ENVELOPE_CLASS_UNSUPPORTED
    normalized = envelope_version.strip()
    if normalized in SUPPORTED_ENVELOPE_VERSIONS:
        return ENVELOPE_CLASS_SUPPORTED
    if normalized in KNOWN_LEGACY_ENVELOPE_VERSIONS:
        return ENVELOPE_CLASS_LEGACY
    return ENVELOPE_CLASS_UNSUPPORTED


def validate_envelope_version(envelope_version: object) -> str:
    """Validate and return a supported envelope version for new evidence blobs."""
    if not isinstance(envelope_version, str):
        raise UnsupportedEnvelopeVersionError("envelope_version must be a supported string identifier")
    normalized = envelope_version.strip()
    if normalized in SUPPORTED_ENVELOPE_VERSIONS:
        return normalized
    if normalized in KNOWN_LEGACY_ENVELOPE_VERSIONS:
        raise LegacyEnvelopeVersionError(
            f"legacy envelope_version {normalized!r} cannot be used for new evidence blobs"
        )
    raise UnsupportedEnvelopeVersionError(f"unsupported envelope_version: {envelope_version!r}")


def assert_safe_destination(
    destination: Path,
    protected_paths: frozenset[Path],
) -> None:
    """Raise :class:`ValueError` when *destination* aliases a protected path.

    Parameters
    ----------
    destination:
        The fully-resolved output path that is about to be written.
        The caller must pass the result of ``Path(...).resolve()`` — a
        relative or unresolved path will be resolved here as a defensive
        measure, but the expectation is that the caller has already done
        this.
    protected_paths:
        A frozen set of *resolved* :class:`~pathlib.Path` objects that
        must never be overwritten or shadowed.  Obtain this set from
        :func:`storage._collect_protected_paths` or construct it
        directly in tests.

    Raises
    ------
    ValueError
        When *destination* is equal to, a descendant of, or an ancestor
        of any path in *protected_paths*.

    Examples
    --------
    >>> from pathlib import Path
    >>> from evidence_storage import assert_safe_destination
    >>> safe = Path("/var/evidence/abc123.bin").resolve()
    >>> protected = frozenset({Path("/etc/app/keys.pem").resolve()})
    >>> assert_safe_destination(safe, protected)  # no exception
    >>> assert_safe_destination(Path("/etc/app/keys.pem"), protected)
    Traceback (most recent call last):
        ...
    ValueError: destination '/etc/app/keys.pem' aliases protected path '/etc/app/keys.pem'
    """
    resolved = destination.resolve()

    for protected in protected_paths:
        reason = _alias_reason(resolved, protected)
        if reason is not None:
            raise ValueError(
                f"destination '{resolved}' aliases protected path "
                f"'{protected}': {reason}"
            )


def get_blob_info(content_hash: str) -> dict | None:
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "select encrypted_dek, storage_path, envelope_version from blobs where content_hash = %s",
                (content_hash,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None


def clamp_verify_batch_size(batch_size: int | None) -> int:
    if batch_size is None:
        return DEFAULT_VERIFY_BATCH_SIZE
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError("batch_size must be a positive integer")
    return min(batch_size, MAX_VERIFY_BATCH_SIZE)


def list_blobs_batch(
    after_content_hash: str | None = None,
    batch_size: int = DEFAULT_VERIFY_BATCH_SIZE,
) -> list[dict[str, Any]]:
    limit = clamp_verify_batch_size(batch_size)
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select content_hash, encrypted_dek, size_bytes, storage_path, envelope_version
                from blobs
                where (%s is null or content_hash > %s)
                order by content_hash asc
                limit %s
                """,
                (after_content_hash, after_content_hash, limit),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]


def verify_blob_integrity(blob: Mapping[str, Any]) -> dict[str, str]:
    """Verify metadata and ciphertext integrity for a single evidence blob.

    Returns a nonsecret status dictionary with keys ``content_hash``,
    ``status``, and ``reason``. Never returns plaintext, ciphertext, DEKs,
    storage paths, or raw exception messages.
    """
    content_hash_raw = blob.get("content_hash")
    content_hash = content_hash_raw if isinstance(content_hash_raw, str) else ""

    if _SHA256_HEX_RE.fullmatch(content_hash) is None:
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "legacy_hash_format",
        }

    envelope_version = blob.get("envelope_version")
    if envelope_version is not None:
        env_class = classify_envelope_version(envelope_version)
        if env_class == ENVELOPE_CLASS_LEGACY:
            return {
                "content_hash": content_hash,
                "status": STATUS_UNVERIFIABLE_LEGACY,
                "reason": "legacy_envelope_version",
            }
        if env_class == ENVELOPE_CLASS_UNSUPPORTED:
            return {
                "content_hash": content_hash,
                "status": STATUS_FAILED,
                "reason": "unsupported_envelope_version",
            }

    size_bytes = blob.get("size_bytes")
    if size_bytes is None:
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "missing_size_metadata",
        }
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "invalid_metadata",
        }

    storage_path_raw = blob.get("storage_path")
    if not isinstance(storage_path_raw, str) or not storage_path_raw.strip():
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "invalid_metadata",
        }

    encrypted_dek_raw = blob.get("encrypted_dek")
    if isinstance(encrypted_dek_raw, bytes):
        encrypted_dek_bytes = encrypted_dek_raw
        is_legacy_prefix = encrypted_dek_bytes.startswith(b"legacy:")
    elif isinstance(encrypted_dek_raw, str):
        if not encrypted_dek_raw.strip():
            return {
                "content_hash": content_hash,
                "status": STATUS_UNVERIFIABLE_LEGACY,
                "reason": "missing_encrypted_dek",
            }
        is_legacy_prefix = encrypted_dek_raw.startswith("legacy:")
        encrypted_dek_bytes = encrypted_dek_raw.encode("utf-8")
    else:
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "missing_encrypted_dek",
        }

    if is_legacy_prefix:
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "legacy_dek_format",
        }

    blob_path = Path(storage_path_raw)
    if not blob_path.exists():
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "missing_blob",
        }
    if not blob_path.is_file():
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "invalid_metadata",
        }

    try:
        dek = decrypt_dek(encrypted_dek_bytes)
    except (ValueError, InvalidToken):
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "unreadable_legacy_dek",
        }

    try:
        ciphertext = blob_path.read_bytes()
    except OSError:
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "missing_blob",
        }

    try:
        plaintext = decrypt_blob_ciphertext(
            dek,
            ciphertext,
            envelope_version=envelope_version,
        )
    except LegacyEnvelopeVersionError:
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "legacy_envelope_version",
        }
    except UnsupportedEnvelopeVersionError:
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "unsupported_envelope_version",
        }
    except (InvalidToken, ValueError):
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "corrupt_ciphertext",
        }

    actual_hash = hashlib.sha256(plaintext).hexdigest()
    if actual_hash != content_hash.lower():
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "hash_mismatch",
        }

    if size_bytes not in (len(ciphertext), len(plaintext)):
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "size_mismatch",
        }

    return {
        "content_hash": content_hash,
        "status": STATUS_VERIFIED,
        "reason": "ok",
    }


def _new_integrity_progress(batch_size: int) -> dict[str, Any]:
    return {
        "schema_version": PROGRESS_SCHEMA_VERSION,
        "run_id": str(uuid.uuid4()),
        "status": "in_progress",
        "cursor": None,
        "batch_size": batch_size,
        "batches_completed": 0,
        "totals": {
            "checked": 0,
            "verified": 0,
            "failed": 0,
            "unverifiable_legacy": 0,
        },
        "failure_reasons": {},
        "legacy_reasons": {},
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _sanitize_progress_payload(progress: Mapping[str, Any]) -> dict[str, Any]:
    totals_raw = progress.get("totals")
    totals = totals_raw if isinstance(totals_raw, Mapping) else {}
    failure_reasons_raw = progress.get("failure_reasons")
    failure_reasons = (
        {str(k): int(v) for k, v in failure_reasons_raw.items()}
        if isinstance(failure_reasons_raw, Mapping)
        else {}
    )
    legacy_reasons_raw = progress.get("legacy_reasons")
    legacy_reasons = (
        {str(k): int(v) for k, v in legacy_reasons_raw.items()}
        if isinstance(legacy_reasons_raw, Mapping)
        else {}
    )
    cursor = progress.get("cursor")
    return {
        "schema_version": PROGRESS_SCHEMA_VERSION,
        "run_id": str(progress.get("run_id") or uuid.uuid4()),
        "status": "completed" if progress.get("status") == "completed" else "in_progress",
        "cursor": cursor if isinstance(cursor, str) else None,
        "batch_size": clamp_verify_batch_size(int(progress.get("batch_size", DEFAULT_VERIFY_BATCH_SIZE))),
        "batches_completed": max(0, int(progress.get("batches_completed", 0))),
        "totals": {
            "checked": max(0, int(totals.get("checked", 0))),
            "verified": max(0, int(totals.get("verified", 0))),
            "failed": max(0, int(totals.get("failed", 0))),
            "unverifiable_legacy": max(0, int(totals.get("unverifiable_legacy", 0))),
        },
        "failure_reasons": failure_reasons,
        "legacy_reasons": legacy_reasons,
        "updated_at": str(progress.get("updated_at") or datetime.now(timezone.utc).isoformat()),
    }


def load_integrity_progress(progress_path: Path | None = None) -> dict[str, Any] | None:
    path = progress_path if progress_path is not None else storage.get_integrity_progress_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("integrity progress file is unreadable or malformed") from exc
    if not isinstance(data, dict) or data.get("schema_version") != PROGRESS_SCHEMA_VERSION:
        raise ValueError("integrity progress file has unsupported schema version")
    return _sanitize_progress_payload(data)


def save_integrity_progress(
    progress: Mapping[str, Any],
    progress_path: Path | None = None,
) -> Path:
    path = progress_path if progress_path is not None else storage.get_integrity_progress_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _sanitize_progress_payload(progress)
    payload["updated_at"] = datetime.now(timezone.utc).isoformat()
    encoded = json.dumps(payload, sort_keys=True, indent=2) + "\n"

    fd, tmp_name = tempfile.mkstemp(prefix=".integrity_progress_", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
        os.replace(tmp_name, path)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise
    return path


def verify_evidence_batch(
    *,
    batch_size: int = DEFAULT_VERIFY_BATCH_SIZE,
    progress_path: Path | None = None,
    reset: bool = False,
    fetch_batch: Callable[[str | None, int], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Run one bounded batch of resumable evidence integrity verification.

    Persists only nonsecret progress metadata and advances the cursor
    deterministically by ``content_hash``.
    """
    effective_batch_size = clamp_verify_batch_size(batch_size)
    path = progress_path if progress_path is not None else storage.get_integrity_progress_path()

    progress = None if reset else load_integrity_progress(path)
    if progress is None or progress["status"] == "completed":
        progress = _new_integrity_progress(effective_batch_size)
    else:
        progress["batch_size"] = effective_batch_size

    loader = fetch_batch if fetch_batch is not None else list_blobs_batch
    blobs = loader(progress["cursor"], effective_batch_size)

    for blob in blobs:
        result = verify_blob_integrity(blob)
        progress["totals"]["checked"] += 1
        status = result["status"]
        reason = result["reason"]
        if status == STATUS_VERIFIED:
            progress["totals"]["verified"] += 1
        elif status == STATUS_UNVERIFIABLE_LEGACY:
            progress["totals"]["unverifiable_legacy"] += 1
            progress["legacy_reasons"][reason] = progress["legacy_reasons"].get(reason, 0) + 1
        else:
            progress["totals"]["failed"] += 1
            progress["failure_reasons"][reason] = progress["failure_reasons"].get(reason, 0) + 1
        if isinstance(blob.get("content_hash"), str):
            progress["cursor"] = blob["content_hash"]

    progress["batches_completed"] += 1
    progress["status"] = "completed" if len(blobs) < effective_batch_size else "in_progress"
    save_integrity_progress(progress, path)
    return progress


def verify_evidence_resumable(
    *,
    batch_size: int = DEFAULT_VERIFY_BATCH_SIZE,
    max_batches: int | None = None,
    progress_path: Path | None = None,
    reset: bool = False,
    fetch_batch: Callable[[str | None, int], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Resume and run bounded integrity verification batches until complete or ``max_batches``."""
    if max_batches is not None and (
        isinstance(max_batches, bool) or not isinstance(max_batches, int) or max_batches < 1
    ):
        raise ValueError("max_batches must be a positive integer")

    batches_run = 0
    progress: dict[str, Any] | None = None
    while True:
        progress = verify_evidence_batch(
            batch_size=batch_size,
            progress_path=progress_path,
            reset=(reset and batches_run == 0),
            fetch_batch=fetch_batch,
        )
        batches_run += 1
        if progress["status"] == "completed":
            return progress
        if max_batches is not None and batches_run >= max_batches:
            return progress
def preview_tenant_retention(
    tenant_id: str,
    *,
    error: EvidenceStorageOperationalError,
) -> bool:
    """Mark a blob quarantined ONLY on genuine cryptographic/digest corruption.

    Refuses to quarantine blobs on quota exhaustion or transient I/O errors.
    """
    if not isinstance(error, EvidenceStorageOperationalError) or not error.quarantine_eligible:
        raise ValueError(
            "only EVIDENCE_CORRUPTED errors are eligible for evidence quarantine"
        )
    key = _blob_quarantine_key(content_hash)
    with _QUARANTINE_LOCK:
        _CORRUPTED_BLOB_REFS[key] = error.reason_code
        _CORRUPTED_BLOB_REFS.move_to_end(key)
        while len(_CORRUPTED_BLOB_REFS) > _QUARANTINE_MAX:
            _CORRUPTED_BLOB_REFS.popitem(last=False)
    return True


def is_blob_quarantined(content_hash: str) -> bool:
    key = _blob_quarantine_key(content_hash)
    with _QUARANTINE_LOCK:
        return key in _CORRUPTED_BLOB_REFS


def reset_corrupted_quarantine() -> None:
    with _QUARANTINE_LOCK:
        _CORRUPTED_BLOB_REFS.clear()


def store_encrypted_blob(
    plaintext: bytes,
    *,
    storage_dir: Path | str | None = None,
    quota_bytes: int | None = None,
    min_free_bytes: int | None = None,
    record_in_db: bool = True,
    raise_on_error: bool = False,
) -> dict[str, Any]:
    """Encrypt and atomically store evidence, reporting quota exhaustion distinctly."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    raw_bytes = bytes(plaintext)
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    target_dir = Path(storage_dir) if storage_dir is not None else get_storage_dir()
    blob_path = target_dir / f"{content_hash}.enc"

    dek, encrypted_dek = generate_dek()
    ciphertext = get_encryptor(dek).encrypt(raw_bytes)

    try:
        written = atomic_write_blob_bytes(
            blob_path,
            ciphertext,
            quota_bytes=quota_bytes,
            min_free_bytes=min_free_bytes,
        )
    except BaseException as exc:
        classified = classify_storage_exception(exc)
        logger.warning(
            "evidence_blob_write_failed reason_code=%s retryable=%s",
            classified.reason_code,
            classified.retryable,
        )
        if raise_on_error:
            raise classified from exc
        return classified.to_dict()

    if record_in_db:
        record_blob(content_hash, encrypted_dek, written, str(blob_path))

    return {
        "ok": True,
        "reasonCode": "OK",
        "retryable": False,
        "quarantined": False,
        "contentHash": content_hash,
        "ciphertextBytes": written,
    }


def verify_or_stage_encrypted_blob(
    content_hash: str,
    *,
    expected_plaintext_hash: str | None = None,
    stage_path: Path | str | None = None,
    quota_bytes: int | None = None,
    min_free_bytes: int | None = None,
    quarantine_on_corruption: bool = True,
    raise_on_error: bool = False,
) -> dict[str, Any]:
    """Authenticate and optionally stage an encrypted blob without conflating quota errors with corruption."""
    if is_blob_quarantined(content_hash):
        err = EvidenceCorruptionError("evidence is quarantined due to prior corruption")
        if raise_on_error:
            raise err
        out = err.to_dict()
        out["quarantined"] = True
        return out

    info = get_blob_info(content_hash)
    if info is None:
        return {
            "ok": False,
            "reasonCode": "BLOB_NOT_FOUND",
            "retryable": False,
            "quarantined": False,
        }

    storage_path = info.get("storage_path")
    encrypted_dek_raw = info.get("encrypted_dek")
    if not storage_path or not encrypted_dek_raw:
        corr = EvidenceCorruptionError("missing blob metadata fields")
        quarantined = (
            quarantine_corrupted_blob(content_hash, error=corr)
            if quarantine_on_corruption
            else False
        )
        if raise_on_error:
            raise corr
        out = corr.to_dict()
        out["quarantined"] = quarantined
        return out

    try:
        ciphertext = Path(storage_path).read_bytes()
    except OSError as exc:
        classified = classify_storage_exception(exc)
        if raise_on_error:
            raise classified from exc
        return classified.to_dict()

    encrypted_dek = (
        encrypted_dek_raw.encode("utf-8")
        if isinstance(encrypted_dek_raw, str)
        else bytes(encrypted_dek_raw)
    )
    try:
        dek = decrypt_dek(encrypted_dek)
        plaintext = get_encryptor(dek).decrypt(ciphertext)
    except InvalidToken as exc:
        corr = EvidenceCorruptionError("evidence ciphertext or wrapped DEK failed authentication")
        quarantined = (
            quarantine_corrupted_blob(content_hash, error=corr)
            if quarantine_on_corruption
            else False
        )
        logger.warning(
            "evidence_blob_corrupted reason_code=%s quarantined=%s",
            corr.reason_code,
            quarantined,
        )
        if raise_on_error:
            raise corr from exc
        out = corr.to_dict()
        out["quarantined"] = quarantined
        return out

    expected_digest = expected_plaintext_hash
    if expected_digest is None and len(content_hash) == 64 and all(
        c in "0123456789abcdefABCDEF" for c in content_hash
    ):
        expected_digest = content_hash.lower()

    if expected_digest is not None:
        observed_digest = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(observed_digest, expected_digest.lower()):
            corr = EvidenceCorruptionError("decrypted evidence digest mismatch")
            quarantined = (
                quarantine_corrupted_blob(content_hash, error=corr)
                if quarantine_on_corruption
                else False
            )
            if raise_on_error:
                raise corr
            out = corr.to_dict()
            out["quarantined"] = quarantined
            return out

    if stage_path is not None:
        try:
            atomic_write_blob_bytes(
                stage_path,
                plaintext,
                quota_bytes=quota_bytes,
                min_free_bytes=min_free_bytes,
            )
        except BaseException as exc:
            classified = classify_storage_exception(exc)
            # Capacity exhaustion during staging MUST NOT quarantine valid evidence!
            logger.warning(
                "evidence_blob_stage_failed reason_code=%s retryable=%s quarantined=False",
                classified.reason_code,
                classified.retryable,
            )
            if raise_on_error:
                raise classified from exc
            return classified.to_dict()

    return {
        "ok": True,
        "reasonCode": "OK",
        "retryable": False,
        "quarantined": False,
        "verifiedBytes": len(plaintext),
    }
