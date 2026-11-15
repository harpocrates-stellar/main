from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Tuple
from cryptography.fernet import Fernet
import db
from storage import inspect_storage_files_readonly

logger = logging.getLogger("harpocrates.evidence_storage")

CONSISTENCY_REPORT_SCHEMA = "hpx-evidence-consistency/1"
_CONSISTENCY_TAG_DOMAIN = b"harpocrates:evidence-consistency:v1:"
MAX_CONSISTENCY_SAMPLES = 500


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


def _consistency_tag(kind: str, raw_identifier: str) -> str:
    digest = hashlib.sha256(
        _CONSISTENCY_TAG_DOMAIN
        + kind.encode("utf-8")
        + b":"
        + raw_identifier.encode("utf-8", errors="replace")
    ).hexdigest()
    return f"v1:{digest[:16]}"


def generate_consistency_report(
    storage_dir: Path | str | None = None,
    *,
    max_samples: int = 50,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compare blob metadata, tenant references, and physical files without modifying state.

    Reports missing physical files, orphaned/unreferenced blob records, dangling
    tenant references, and orphaned physical files using privacy-safe opaque tags
    and bounded counts. Never mutates database rows or filesystem entries.
    """
    if isinstance(max_samples, bool) or not isinstance(max_samples, int) or max_samples < 1:
        raise ValueError("max_samples must be a positive integer.")
    bounded_samples = min(max_samples, MAX_CONSISTENCY_SAMPLES)
    evaluated_dt = (
        datetime.now(timezone.utc)
        if now is None
        else (now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc))
    )

    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select content_hash, size_bytes, storage_path
                from blobs
                order by content_hash asc
                """
            )
            blob_rows = cursor.fetchall() or []

            cursor.execute(
                """
                select tenant_id, content_hash, ref_count
                from tenant_blob_refs
                order by content_hash asc, tenant_id asc
                """
            )
            ref_rows = cursor.fetchall() or []

    disk_scan = inspect_storage_files_readonly(storage_dir)
    physical_files: dict[str, int] = dict(disk_scan["files"])

    blobs_by_hash: dict[str, dict[str, Any]] = {}
    tracked_paths: set[str] = set()
    for row in blob_rows:
        if isinstance(row, dict):
            c_hash = str(row["content_hash"])
            size_bytes = int(row.get("size_bytes") or 0)
            raw_path = row.get("storage_path")
        else:
            c_hash = str(row[0])
            size_bytes = int(row[1] or 0)
            raw_path = row[2]
        norm_path = (
            os.path.normcase(os.path.abspath(str(raw_path)))
            if raw_path
            else None
        )
        if norm_path is not None:
            tracked_paths.add(norm_path)
        blobs_by_hash[c_hash] = {
            "size_bytes": size_bytes,
            "raw_path": str(raw_path) if raw_path else None,
            "norm_path": norm_path,
        }

    active_ref_totals: dict[str, int] = {}
    dangling_refs: list[dict[str, Any]] = []
    zero_or_negative_refs: list[dict[str, Any]] = []
    active_ref_rows = 0

    for row in ref_rows:
        if isinstance(row, dict):
            tenant_id = str(row["tenant_id"])
            c_hash = str(row["content_hash"])
            ref_count = int(row["ref_count"])
        else:
            tenant_id = str(row[0])
            c_hash = str(row[1])
            ref_count = int(row[2])

        if ref_count <= 0:
            zero_or_negative_refs.append(
                {
                    "record_tag": _consistency_tag("stale_ref", f"{tenant_id}:{c_hash}"),
                    "ref_count": ref_count,
                }
            )
            continue

        active_ref_rows += 1
        active_ref_totals[c_hash] = active_ref_totals.get(c_hash, 0) + ref_count
        if c_hash not in blobs_by_hash:
            dangling_refs.append(
                {
                    "record_tag": _consistency_tag("dangling_ref", f"{tenant_id}:{c_hash}"),
                    "blob_tag": _consistency_tag("blob", c_hash),
                    "ref_count": ref_count,
                }
            )

    missing_physical_files: list[dict[str, Any]] = []
    referenced_missing_count = 0
    unreferenced_blobs: list[dict[str, Any]] = []

    for c_hash, meta in blobs_by_hash.items():
        ref_total = active_ref_totals.get(c_hash, 0)
        raw_path = meta["raw_path"]
        norm_path = meta["norm_path"]

        file_exists = False
        if norm_path is not None:
            if norm_path in physical_files:
                file_exists = True
            else:
                try:
                    candidate = Path(raw_path)
                    file_exists = candidate.exists() and candidate.is_file() and not candidate.is_symlink()
                except OSError:
                    file_exists = False

        if not file_exists:
            if ref_total > 0:
                referenced_missing_count += 1
            missing_physical_files.append(
                {
                    "blob_tag": _consistency_tag("blob", c_hash),
                    "referenced": ref_total > 0,
                    "active_ref_count": ref_total,
                    "declared_size_bytes": meta["size_bytes"],
                }
            )

        if ref_total == 0:
            unreferenced_blobs.append(
                {
                    "blob_tag": _consistency_tag("blob", c_hash),
                    "declared_size_bytes": meta["size_bytes"],
                    "physical_file_present": file_exists,
                }
            )

    orphaned_physical_files: list[dict[str, Any]] = []
    orphaned_physical_bytes = 0
    for norm_path, file_size in sorted(physical_files.items()):
        if norm_path not in tracked_paths:
            orphaned_physical_bytes += file_size
            orphaned_physical_files.append(
                {
                    "file_tag": _consistency_tag("file", norm_path),
                    "size_bytes": file_size,
                }
            )

    consistent = (
        len(missing_physical_files) == 0
        and len(dangling_refs) == 0
        and len(zero_or_negative_refs) == 0
        and len(unreferenced_blobs) == 0
        and len(orphaned_physical_files) == 0
    )

    return {
        "schema": CONSISTENCY_REPORT_SCHEMA,
        "evaluated_at": evaluated_dt.isoformat(),
        "consistent": consistent,
        "storage_directory_present": bool(disk_scan["directory_exists"]),
        "counts": {
            "blobs_checked": len(blobs_by_hash),
            "active_tenant_references_checked": active_ref_rows,
            "physical_files_scanned": len(physical_files),
            "missing_physical_files": len(missing_physical_files),
            "referenced_missing_physical_files": referenced_missing_count,
            "dangling_tenant_references": len(dangling_refs),
            "stale_non_positive_references": len(zero_or_negative_refs),
            "unreferenced_blob_records": len(unreferenced_blobs),
            "orphaned_physical_files": len(orphaned_physical_files),
            "orphaned_physical_bytes": orphaned_physical_bytes,
        },
        "anomalies": {
            "missing_physical_files": missing_physical_files[:bounded_samples],
            "dangling_tenant_references": dangling_refs[:bounded_samples],
            "stale_non_positive_references": zero_or_negative_refs[:bounded_samples],
            "unreferenced_blob_records": unreferenced_blobs[:bounded_samples],
            "orphaned_physical_files": orphaned_physical_files[:bounded_samples],
        },
        "samples_truncated": any(
            len(bucket) > bounded_samples
            for bucket in (
                missing_physical_files,
                dangling_refs,
                zero_or_negative_refs,
                unreferenced_blobs,
                orphaned_physical_files,
            )
        ),
    }
