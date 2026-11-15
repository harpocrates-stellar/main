from __future__ import annotations

import hashlib
import logging
import os
from typing import Any, Tuple

from cryptography.fernet import Fernet
import db
from storage import (
    DeletionReceipt,
    DeletionReceiptLedger,
    compute_deletion_audit_ref,
    get_default_deletion_ledger,
    reset_deletion_receipts,
    verify_deletion_receipt,
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


def collect_unreferenced_blobs_with_receipts(
    limit: int = 100,
    *,
    receipt_ledger: DeletionReceiptLedger | None = None,
    reason: str = "unreferenced_blob_gc",
) -> tuple[int, list[dict[str, Any]]]:
    """Transactionally delete unreferenced blobs and emit two-phase deletion receipts."""
    if limit < 1:
        return 0, []

    active_ledger = receipt_ledger or get_default_deletion_ledger()
    collected = 0
    receipts: list[dict[str, Any]] = []
    pending_completions: list[str] = []

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
                (limit,),
            )
            rows = cursor.fetchall()
            if not rows:
                conn.commit()
                return 0, []

            for row in rows:
                content_hash = row["content_hash"] if isinstance(row, dict) else row[0]
                storage_path = row["storage_path"] if isinstance(row, dict) else row[1]

                phase1 = active_ledger.approve_selection(
                    identifier=str(content_hash),
                    reason=reason,
                    requires_metadata_delete=True,
                )

                # Attempt file deletion first
                try:
                    if storage_path:
                        try:
                            os.unlink(storage_path)
                        except FileNotFoundError:
                            pass
                except OSError as err:
                    failed_rec = active_ledger.record_storage_failure(
                        phase1.receipt_id,
                        error_code=type(err).__name__,
                        file_deleted=False,
                        metadata_deleted=False,
                    )
                    receipts.append(failed_rec.to_dict())
                    logger.warning(
                        "Failed to delete evidence blob file; will retry on next run: %s",
                        type(err).__name__,
                    )
                    continue

                cursor.execute("delete from blobs where content_hash = %s", (content_hash,))
                pending_completions.append(phase1.receipt_id)
                collected += 1

        conn.commit()

    for rec_id in pending_completions:
        completed_rec = active_ledger.complete_deletion(
            rec_id,
            file_deleted=True,
            metadata_deleted=True,
        )
        receipts.append(completed_rec.to_dict())

    if collected > 0:
        try:
            from metrics import collector as metrics_collector

            metrics_collector.record_deleted_blob(collected)
        except Exception:
            pass

    return collected, receipts


def collect_unreferenced_blobs(limit: int = 100) -> int:
    """Transactionally delete blob rows and files that have zero references.

    Uses SELECT ... FOR UPDATE to avoid races with concurrent record_tenant_ref.
    Deletes the underlying file first; if file deletion fails, the blob row
    is left intact so the deletion will be retried on the next run.
    Records two-phase deletion receipts without retaining media, filenames, or keys.
    """
    collected, _receipts = collect_unreferenced_blobs_with_receipts(limit=limit)
    return collected


def list_deletion_receipts(
    *,
    phase: str | None = None,
    content_hash: str | None = None,
    limit: int = 100,
    receipt_ledger: DeletionReceiptLedger | None = None,
) -> list[dict[str, Any]]:
    """Return privacy-safe two-phase deletion receipts."""
    active_ledger = receipt_ledger or get_default_deletion_ledger()
    audit_ref = (
        compute_deletion_audit_ref(content_hash) if content_hash is not None else None
    )
    return active_ledger.list_receipts(phase=phase, audit_ref=audit_ref, limit=limit)


def get_deletion_receipt(
    receipt_id: str,
    *,
    receipt_ledger: DeletionReceiptLedger | None = None,
) -> dict[str, Any] | None:
    """Look up a single deletion receipt by receiptId."""
    active_ledger = receipt_ledger or get_default_deletion_ledger()
    rec = active_ledger.get_receipt(receipt_id)
    return rec.to_dict() if rec is not None else None


def get_blob_info(content_hash: str) -> dict | None:
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select encrypted_dek, storage_path from blobs where content_hash = %s", (content_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None
