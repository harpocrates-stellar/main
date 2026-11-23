from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Tuple

from cryptography.fernet import Fernet
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

STORAGE_METADATA_ERROR_CODE = "DEPENDENCY_UNAVAILABLE"
STORAGE_METADATA_ERROR_STATUS = 503

COLLECTED = "collected"
REFERENCED = "referenced"
MISSING = "missing"
UNLINK_FAILED = "collected_unlink_failed"


class StorageMetadataRetryableError(RuntimeError):
    def __init__(
        self,
        message: str = "storage metadata update is temporarily unavailable",
        attempts: int = 0,
    ) -> None:
        super().__init__(message)
        self.attempts = attempts
        self.code = STORAGE_METADATA_ERROR_CODE
        self.status = STORAGE_METADATA_ERROR_STATUS


RetryableStorageError = StorageMetadataRetryableError
StorageRetryableError = StorageMetadataRetryableError


@dataclass(frozen=True)
class BlobCollectionResult:
    status: str
    content_hash: str
    storage_path: str | None = None
    attempts: int = 1

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


def record_tenant_ref(
    tenant_id: str,
    content_hash: str,
    *,
    connection_factory: Callable[[], Any] | None = None,
):
    """Record a tenant reference after locking the blob row.

    The lock makes concurrent collection wait for this committed reference, so
    a collector cannot observe a blob as unreferenced while a reference update
    is still in flight. Exhausted retries raise a bounded retryable error.
    """
    factory = connection_factory or db.get_connection

    def attempt(_attempt: int) -> None:
        with factory() as conn:
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "select 1 from blobs where content_hash = %s for update",
                        (content_hash,),
                    )
                    cursor.execute(
                        """
                        insert into tenant_blob_refs (tenant_id, content_hash, ref_count)
                        values (%s, %s, 1)
                        on conflict (tenant_id, content_hash) do update
                        set ref_count = tenant_blob_refs.ref_count + 1, updated_at = now()
                        """,
                        (tenant_id, content_hash),
                    )
                conn.commit()
            except Exception:
                _safe_rollback(conn)
                raise

    _with_bounded_retry(attempt, "tenant reference metadata update")



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


def _audit_ref(content_hash: str) -> str:
    """Return a non-reversible audit reference for a blob without exposing its hash."""
    return hashlib.sha256(("audit:" + content_hash).encode("utf-8")).hexdigest()[:32]


def record_deletion_receipt(receipt_id: str, phase: str, selected: list, completed: list):
    """Persist a two-phase deletion receipt.

    phase 'approved' records the selection before any storage action runs.
    phase 'completed' records audit references for storage actions that finished.
    Only audit references are stored: no content hashes, storage paths, or keys.
    """
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                insert into blob_deletion_receipts (receipt_id, phase, selected_refs, completed_refs)
                values (%s, %s, %s, %s)
                on conflict (receipt_id) do update
                set phase = excluded.phase,
                    completed_refs = excluded.completed_refs,
                    updated_at = now()
                """,
                (receipt_id, phase, ",".join(selected), ",".join(completed))
            )
        conn.commit()


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

    collected = 0
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            receipt_id = uuid.uuid4().hex
            selected_refs: list = []
            completed_refs: list = []
            cursor.execute(
                """
                select content_hash, storage_path
                from blobs
                where not exists (
                    select 1 from tenant_blob_refs
                    where tenant_blob_refs.content_hash = blobs.content_hash
                      and tenant_blob_refs.ref_count > 0
                )
                order by created_at asc
                limit %s
                for update
                """,
                (limit,)
            )
            rows = cursor.fetchall()
            if not rows:
                conn.commit()
                return 0

            for row in rows:
                content_hash = row["content_hash"] if isinstance(row, dict) else row[0]
                storage_path = row["storage_path"] if isinstance(row, dict) else row[1]
                selected_refs.append(_audit_ref(content_hash))

                # Attempt file deletion first
                try:
                    if storage_path:
                        try:
                            os.unlink(storage_path)
                        except FileNotFoundError:
                            pass
                except OSError as err:
                    # File deletion failed: do not delete the blob row so it is retried next run
                    logger.warning(
                        "Failed to delete evidence blob file; will retry on next run: %s",
                        type(err).__name__,
                    )
                    continue

                cursor.execute("delete from blobs where content_hash = %s", (content_hash,))
                completed_refs.append(_audit_ref(content_hash))
                collected += 1

        conn.commit()

    if collected > 0:
        try:
            from metrics import collector as metrics_collector
            metrics_collector.record_deleted_blob(collected)
        except Exception:
            pass

    return collected


def get_blob_info(content_hash: str) -> dict | None:
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "select encrypted_dek, storage_path, envelope_version from blobs where content_hash = %s",
                (content_hash,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None


def collect_unreferenced_blob(
    content_hash: str,
    *,
    connection_factory: Callable[[], Any] | None = None,
) -> BlobCollectionResult:
    """Collect an unreferenced encrypted blob without risking live evidence.

    The blob row is locked, tenant references are checked, and the metadata
    deletion is committed before the encrypted file is removed. If either
    metadata step fails, the file is left untouched and a bounded retryable
    storage error is raised.
    """
    factory = connection_factory or db.get_connection

    def attempt(attempt_number: int) -> BlobCollectionResult:
        result, storage_path = _collect_once(factory, content_hash)
        if result.status == COLLECTED and storage_path:
            try:
                Path(storage_path).unlink(missing_ok=True)
            except OSError:
                result = BlobCollectionResult(UNLINK_FAILED, content_hash, storage_path, attempt_number)
        return BlobCollectionResult(result.status, content_hash, storage_path, attempt_number)

    return _with_bounded_retry(attempt, "blob collection metadata update")


collect_blob = collect_unreferenced_blob


def _collect_once(
    factory: Callable[[], Any], content_hash: str
) -> tuple[BlobCollectionResult, str | None]:
    with factory() as conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "select storage_path from blobs where content_hash = %s for update",
                    (content_hash,),
                )
                row = cursor.fetchone()
                if row is None:
                    conn.commit()
                    return BlobCollectionResult(MISSING, content_hash), None
                storage_path = str(dict(row)["storage_path"])
                cursor.execute(
                    "select 1 from tenant_blob_refs where content_hash = %s and ref_count > 0 limit 1",
                    (content_hash,),
                )
                if cursor.fetchone() is not None:
                    conn.commit()
                    return BlobCollectionResult(REFERENCED, content_hash, storage_path), storage_path
                cursor.execute("delete from blobs where content_hash = %s", (content_hash,))
            conn.commit()
        except Exception:
            _safe_rollback(conn)
            raise
    return BlobCollectionResult(COLLECTED, content_hash, storage_path), storage_path


def _safe_rollback(conn: Any) -> None:
    try:
        conn.rollback()
    except Exception:
        pass


def _positive_env(name: str, default: float, maximum: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return min(value, maximum)


def _with_bounded_retry(operation: Callable[[int], Any], description: str) -> Any:
    max_attempts = int(_positive_env("DB_CONNECT_MAX_ATTEMPTS", 4, 10))
    deadline_seconds = _positive_env("DB_CONNECT_DEADLINE_SECONDS", 15.0, 60.0)
    retry_base_seconds = _positive_env("DB_CONNECT_RETRY_BASE_SECONDS", 0.05, 1.0)
    started = time.monotonic()
    last_error: Exception | None = None

    for attempt_number in range(1, max_attempts + 1):
        try:
            return operation(attempt_number)
        except StorageMetadataRetryableError:
            raise
        except Exception as exc:
            last_error = exc
            elapsed = time.monotonic() - started
            remaining = deadline_seconds - elapsed
            if attempt_number >= max_attempts or remaining <= 0:
                break
            delay = min(retry_base_seconds * (2 ** (attempt_number - 1)), remaining, 0.5)
            if delay > 0:
                time.sleep(delay)

    raise StorageMetadataRetryableError(
        f"{description} failed after {attempt_number} attempt(s)",
        attempts=attempt_number,
    ) from last_error
