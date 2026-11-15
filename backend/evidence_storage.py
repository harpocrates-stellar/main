from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import Any, Mapping, Tuple

from cryptography.fernet import Fernet, InvalidToken
import db
from storage import (
    INTEGRITY_VERIFY_BATCH_DEFAULT,
    INTEGRITY_VERIFY_BATCH_MAX,
    IntegrityCheckpointStore,
    IntegrityVerificationCheckpoint,
    clamp_integrity_batch_size,
    compute_integrity_audit_ref,
    compute_integrity_cursor_digest,
    get_default_integrity_checkpoint_store,
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


STATUS_VERIFIED = "verified"
STATUS_CORRUPTED = "corrupted"
STATUS_UNVERIFIABLE_LEGACY = "unverifiable_legacy"


def _is_hex_64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def _is_fernet_v1_token(token: bytes) -> bool:
    if not token:
        return False
    try:
        decoded = base64.urlsafe_b64decode(token)
    except (binascii.Error, ValueError):
        return False
    # Fernet format: 1B version (0x80) + 8B timestamp + 16B IV + >=16B ciphertext + 32B HMAC = >=73B
    return len(decoded) >= 73 and decoded[0] == 0x80


def inspect_blob_integrity(row: Mapping[str, Any]) -> tuple[str, str]:
    """Verify ciphertext and metadata for a single blob row without leaking secrets.

    Returns ``(status, reason)`` where ``status`` is one of ``verified``,
    ``corrupted``, or ``unverifiable_legacy``.
    """
    content_hash = str(row.get("content_hash") or "")
    storage_path = row.get("storage_path")
    size_bytes = row.get("size_bytes")
    encrypted_dek_raw = row.get("encrypted_dek")
    envelope_version = row.get("envelope_version")
    ciphertext_sha256 = row.get("ciphertext_sha256")

    if not isinstance(storage_path, str) or not storage_path.strip():
        return STATUS_CORRUPTED, "missing_storage_path"

    blob_path = Path(storage_path)
    try:
        ciphertext = blob_path.read_bytes()
    except FileNotFoundError:
        return STATUS_CORRUPTED, "missing_ciphertext_file"
    except OSError:
        return STATUS_CORRUPTED, "storage_read_failed"

    if size_bytes is not None:
        try:
            expected_size = int(size_bytes)
        except (TypeError, ValueError):
            return STATUS_CORRUPTED, "invalid_size_metadata"
        if expected_size < 0:
            return STATUS_CORRUPTED, "invalid_size_metadata"
        if expected_size > 0 and len(ciphertext) != expected_size:
            return STATUS_CORRUPTED, "size_mismatch"

    has_verified_ct_digest = False
    if isinstance(ciphertext_sha256, str) and ciphertext_sha256.strip():
        cleaned_ct = ciphertext_sha256.strip().lower()
        if not _is_hex_64(cleaned_ct):
            return STATUS_CORRUPTED, "invalid_ciphertext_digest_metadata"
        actual_ct = hashlib.sha256(ciphertext).hexdigest()
        if not hmac.compare_digest(actual_ct, cleaned_ct):
            return STATUS_CORRUPTED, "ciphertext_digest_mismatch"
        has_verified_ct_digest = True

    if envelope_version in {"legacy", "v0", "none", 0, "0"}:
        return STATUS_UNVERIFIABLE_LEGACY, "legacy_envelope_version"

    if encrypted_dek_raw is None or (
        isinstance(encrypted_dek_raw, (str, bytes)) and len(encrypted_dek_raw) == 0
    ):
        return STATUS_UNVERIFIABLE_LEGACY, "missing_envelope_key"

    encrypted_dek = (
        encrypted_dek_raw.encode("utf-8")
        if isinstance(encrypted_dek_raw, str)
        else bytes(encrypted_dek_raw)
    )

    if not _is_fernet_v1_token(encrypted_dek):
        if envelope_version == "fernet-v1":
            return STATUS_CORRUPTED, "malformed_wrapped_dek"
        return STATUS_UNVERIFIABLE_LEGACY, "legacy_key_envelope"

    if not _is_fernet_v1_token(ciphertext):
        return STATUS_CORRUPTED, "malformed_ciphertext_envelope"

    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        if has_verified_ct_digest:
            return STATUS_VERIFIED, "ciphertext_digest_verified"
        return STATUS_UNVERIFIABLE_LEGACY, "master_key_unavailable"

    try:
        dek = decrypt_dek(encrypted_dek)
    except InvalidToken:
        return STATUS_CORRUPTED, "dek_authentication_failed"
    except ValueError:
        return STATUS_CORRUPTED, "invalid_master_key_configuration"

    try:
        plaintext = get_encryptor(dek).decrypt(ciphertext)
    except (InvalidToken, ValueError):
        return STATUS_CORRUPTED, "ciphertext_authentication_failed"

    if not _is_hex_64(content_hash):
        return STATUS_UNVERIFIABLE_LEGACY, "legacy_non_sha256_identifier"

    actual_pt_digest = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(actual_pt_digest, content_hash.lower()):
        return STATUS_CORRUPTED, "plaintext_digest_mismatch"

    return STATUS_VERIFIED, "ok"


def _fetch_integrity_batch(limit: int, offset: int) -> list[dict[str, Any]]:
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select content_hash, encrypted_dek, size_bytes, storage_path
                from blobs
                order by content_hash asc
                limit %s offset %s
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()
            conn.commit()
    result: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, Mapping):
            result.append(dict(row))
        else:
            result.append(
                {
                    "content_hash": row[0],
                    "encrypted_dek": row[1],
                    "size_bytes": row[2],
                    "storage_path": row[3],
                }
            )
    return result


def verify_evidence_integrity_batch(
    *,
    batch_size: object = None,
    checkpoint_store: IntegrityCheckpointStore | None = None,
    checkpoint_path: Path | str | None = None,
    reset: bool = False,
) -> dict[str, Any]:
    """Verify stored evidence ciphertext and metadata in bounded, resumable batches."""
    clamped_batch = clamp_integrity_batch_size(batch_size)
    store = (
        checkpoint_store
        if checkpoint_store is not None
        else (
            IntegrityCheckpointStore(checkpoint_path=checkpoint_path)
            if checkpoint_path is not None
            else get_default_integrity_checkpoint_store()
        )
    )
    current = store.reset() if reset else store.load()
    if current.completed and not reset:
        return {
            "ok": True,
            "batchSize": clamped_batch,
            "batchScanned": 0,
            "batchCounts": {
                STATUS_VERIFIED: 0,
                STATUS_CORRUPTED: 0,
                STATUS_UNVERIFIABLE_LEGACY: 0,
            },
            "items": [],
            "checkpoint": current.to_dict(),
        }

    rows = _fetch_integrity_batch(clamped_batch, current.cursor_offset)
    batch_counts = {
        STATUS_VERIFIED: 0,
        STATUS_CORRUPTED: 0,
        STATUS_UNVERIFIABLE_LEGACY: 0,
    }
    items: list[dict[str, str]] = []
    last_cursor_digest = current.cursor_digest

    for row in rows:
        content_hash = str(row.get("content_hash") or "")
        status, reason = inspect_blob_integrity(row)
        batch_counts[status] += 1
        items.append(
            {
                "auditRef": compute_integrity_audit_ref(content_hash or "empty"),
                "status": status,
                "reason": reason,
            }
        )
        if content_hash:
            last_cursor_digest = compute_integrity_cursor_digest(content_hash)

    batch_scanned = len(rows)
    completed = batch_scanned < clamped_batch
    updated = IntegrityVerificationCheckpoint(
        cursor_offset=current.cursor_offset + batch_scanned,
        cursor_digest=last_cursor_digest,
        scanned_count=current.scanned_count + batch_scanned,
        verified_count=current.verified_count + batch_counts[STATUS_VERIFIED],
        corrupted_count=current.corrupted_count + batch_counts[STATUS_CORRUPTED],
        unverifiable_legacy_count=(
            current.unverifiable_legacy_count + batch_counts[STATUS_UNVERIFIABLE_LEGACY]
        ),
        completed=completed,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    store.save(updated)

    logger.info(
        "evidence_integrity_batch_completed scanned=%d verified=%d corrupted=%d legacy=%d completed=%s",
        batch_scanned,
        batch_counts[STATUS_VERIFIED],
        batch_counts[STATUS_CORRUPTED],
        batch_counts[STATUS_UNVERIFIABLE_LEGACY],
        completed,
    )

    return {
        "ok": True,
        "batchSize": clamped_batch,
        "batchScanned": batch_scanned,
        "batchCounts": batch_counts,
        "items": items,
        "checkpoint": updated.to_dict(),
    }
