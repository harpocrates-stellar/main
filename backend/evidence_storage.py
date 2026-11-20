from __future__ import annotations

from collections import OrderedDict
import hashlib
import hmac
import logging
import os
from pathlib import Path
import threading
from typing import Any, Tuple

from cryptography.fernet import Fernet, InvalidToken
import db
from storage import (
    EVIDENCE_CORRUPTED,
    STORAGE_IO_UNAVAILABLE,
    STORAGE_QUOTA_EXHAUSTED,
    EvidenceCorruptionError,
    EvidenceStorageOperationalError,
    StorageIOUnavailableError,
    StorageQuotaExhaustedError,
    atomic_write_blob_bytes,
    classify_storage_exception,
    get_storage_dir,
    is_quota_or_capacity_error,
)

logger = logging.getLogger("harpocrates.evidence_storage")


def generate_dek() -> Tuple[bytes, bytes]:
    """Generates a Data Encryption Key (DEK) and its encrypted form (using a Master Key)."""
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        master_key_b64 = Fernet.generate_key().decode()
    f = Fernet(master_key_b64.encode())

    dek = Fernet.generate_key()
    encrypted_dek = f.encrypt(dek)

    return dek, encrypted_dek


def decrypt_dek(encrypted_dek: bytes) -> bytes:
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        raise ValueError("MASTER_ENCRYPTION_KEY is not set")
    f = Fernet(master_key_b64.encode())
    return f.decrypt(encrypted_dek)


def get_encryptor(dek: bytes):
    return Fernet(dek)


def record_blob(content_hash: str, encrypted_dek: bytes, size_bytes: int, storage_path: str):
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                insert into blobs (content_hash, encrypted_dek, size_bytes, storage_path)
                values (%s, %s, %s, %s)
                on conflict (content_hash) do nothing
                """,
                (content_hash, encrypted_dek.decode(), size_bytes, storage_path)
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
    if limit < 1:
        return 0

    collected = 0
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
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
            cursor.execute("select encrypted_dek, storage_path from blobs where content_hash = %s", (content_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None


_QUARANTINE_LOCK = threading.Lock()
_QUARANTINE_MAX = 4096
_CORRUPTED_BLOB_REFS: OrderedDict[str, str] = OrderedDict()


def _blob_quarantine_key(content_hash: str) -> str:
    return hashlib.sha256(
        f"harpocrates:corrupt-blob-ref:v1:{content_hash.strip()}".encode("utf-8")
    ).hexdigest()


def quarantine_corrupted_blob(
    content_hash: str,
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
