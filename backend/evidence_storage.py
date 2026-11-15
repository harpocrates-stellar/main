import logging
import os
import hashlib
from pathlib import Path
from typing import Any, Tuple
from cryptography.fernet import Fernet
import db
from storage import (
    DEFAULT_GC_RETRY_AFTER_SECONDS,
    RetryableStorageError,
    finalize_preserved_blob,
    restore_preserved_blob,
    stage_blob_preservation,
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


def collect_unreferenced_blobs(
    limit: int = 100,
    *,
    retry_after_seconds: int = DEFAULT_GC_RETRY_AFTER_SECONDS,
) -> int:
    """Transactionally delete blob rows and files that have zero references.

    Uses SELECT ... FOR UPDATE and a guarded DELETE ... WHERE NOT EXISTS (...)
    so physical blob data is never permanently removed before a committed
    reference check. Encrypted files are preserved via a staged link/copy until
    the database metadata deletion commits; if the metadata update or commit
    fails, all staged files are atomically restored and a bounded
    `RetryableStorageError` is raised.
    """
    if limit < 1:
        return 0

    collected = 0
    staged_files: list[tuple[Path | None, str]] = []

    with db.get_connection() as conn:
        try:
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

                    staged_path: Path | None = None
                    if storage_path:
                        try:
                            staged_path = stage_blob_preservation(storage_path)
                        except OSError as err:
                            logger.warning(
                                "Failed to stage evidence blob preservation; skipping GC candidate: %s",
                                type(err).__name__,
                            )
                            continue

                        try:
                            try:
                                os.unlink(storage_path)
                            except FileNotFoundError:
                                pass
                        except OSError as err:
                            finalize_preserved_blob(staged_path)
                            logger.warning(
                                "Failed to delete evidence blob file; will retry on next run: %s",
                                type(err).__name__,
                            )
                            continue

                    if storage_path:
                        staged_files.append((staged_path, storage_path))

                    cursor.execute(
                        """
                        delete from blobs where content_hash = %s
                        and not exists (
                            select 1 from tenant_blob_refs
                            where tenant_blob_refs.content_hash = blobs.content_hash
                              and tenant_blob_refs.ref_count > 0
                        )
                        """,
                        (content_hash,),
                    )
                    rowcount = getattr(cursor, "rowcount", None)
                    if isinstance(rowcount, int) and rowcount == 0:
                        if storage_path:
                            staged_files.pop()
                            restore_preserved_blob(staged_path, storage_path)
                        continue

                    collected += 1

            conn.commit()
        except RetryableStorageError:
            raise
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            preserved_count = 0
            for staged_path, original_path in staged_files:
                try:
                    restore_preserved_blob(staged_path, original_path)
                    if Path(original_path).exists():
                        preserved_count += 1
                except OSError:
                    pass
            logger.warning(
                "Evidence GC metadata update failed (%s); preserved %d encrypted artifact(s).",
                type(exc).__name__,
                preserved_count,
            )
            raise RetryableStorageError(
                code="GC_METADATA_UPDATE_FAILED",
                retry_after_seconds=retry_after_seconds,
                preserved_count=preserved_count,
            ) from exc

    for staged_path, _ in staged_files:
        finalize_preserved_blob(staged_path)

    if collected > 0:
        try:
            from metrics import collector as metrics_collector
            metrics_collector.record_deleted_blob(collected)
        except Exception:
            pass

    return collected


def run_garbage_collection_cycle(
    limit: int = 100,
    *,
    retry_after_seconds: int = DEFAULT_GC_RETRY_AFTER_SECONDS,
) -> dict[str, Any]:
    """Execute one GC cycle and return a bounded status or retryable error dict."""
    try:
        deleted = collect_unreferenced_blobs(
            limit=limit,
            retry_after_seconds=retry_after_seconds,
        )
    except RetryableStorageError as err:
        return {
            "ok": False,
            "collected": 0,
            "error": err.to_dict(),
        }
    return {
        "ok": True,
        "collected": deleted,
        "error": None,
    }


def get_blob_info(content_hash: str) -> dict | None:
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select encrypted_dek, storage_path from blobs where content_hash = %s", (content_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None
