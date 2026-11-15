from datetime import datetime, timezone
import hashlib
import logging
import os
from typing import Any, Tuple
from cryptography.fernet import Fernet
import db

logger = logging.getLogger("harpocrates.evidence_storage")

DEFAULT_EVIDENCE_RETENTION_TTL_SECONDS = 86_400
MAX_RETENTION_PREVIEW_ITEMS = 500


class TenantAccessDeniedError(PermissionError):
    """Raised when a retention preview lacks or violates tenant scope."""


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


def _coerce_utc_datetime(value: Any, *, default: datetime) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return default
    return default


def _resolve_retention_ttl_seconds(retention_ttl_seconds: int | float | None) -> float:
    if retention_ttl_seconds is None:
        raw_env = os.getenv("EVIDENCE_RETENTION_TTL_SECONDS")
        if raw_env is not None and raw_env.strip():
            retention_ttl_seconds = float(raw_env)
        else:
            retention_ttl_seconds = DEFAULT_EVIDENCE_RETENTION_TTL_SECONDS

    if isinstance(retention_ttl_seconds, bool) or not isinstance(retention_ttl_seconds, (int, float)):
        raise ValueError("retention_ttl_seconds must be a positive number.")
    ttl = float(retention_ttl_seconds)
    if ttl <= 0:
        raise ValueError("retention_ttl_seconds must be positive.")
    return ttl


def preview_tenant_retention(
    authenticated_tenant_id: str,
    *,
    requested_tenant_id: str | None = None,
    retention_ttl_seconds: int | float | None = None,
    now: datetime | int | float | None = None,
    max_items: int = 100,
) -> dict[str, Any]:
    """Return a read-only evidence retention preview for `authenticated_tenant_id`.

    Shows blob/reference counts, reference ages, and deletion eligibility for the
    authenticated tenant while strictly excluding `storage_path`, `encrypted_dek`,
    and any content hashes or identifiers belonging to other tenants.
    """
    if not isinstance(authenticated_tenant_id, str) or not authenticated_tenant_id.strip():
        raise TenantAccessDeniedError("Authenticated tenant identity is required.")
    tenant_id = authenticated_tenant_id.strip()

    if requested_tenant_id is not None:
        if not isinstance(requested_tenant_id, str) or requested_tenant_id.strip() != tenant_id:
            raise TenantAccessDeniedError("Cross-tenant retention preview is forbidden.")

    ttl = _resolve_retention_ttl_seconds(retention_ttl_seconds)
    now_dt = _coerce_utc_datetime(now, default=datetime.now(timezone.utc))
    if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
        raise ValueError("max_items must be a positive integer.")
    bounded_limit = min(max_items, MAX_RETENTION_PREVIEW_ITEMS)

    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select
                    t.content_hash,
                    t.ref_count,
                    t.created_at,
                    t.updated_at,
                    b.size_bytes,
                    b.created_at as blob_created_at,
                    exists (
                        select 1 from tenant_blob_refs o
                        where o.content_hash = t.content_hash
                          and o.tenant_id <> %s
                          and o.ref_count > 0
                    ) as has_external_refs
                from tenant_blob_refs t
                left join blobs b on b.content_hash = t.content_hash
                where t.tenant_id = %s
                  and t.ref_count > 0
                order by t.created_at asc, t.content_hash asc
                """,
                (tenant_id, tenant_id),
            )
            rows = cursor.fetchall() or []

    items: list[dict[str, Any]] = []
    ages_list: list[float] = []
    total_references = 0
    total_size_bytes = 0
    reclaimable_size_bytes = 0
    expired_count = 0
    within_ttl_count = 0
    eligible_for_deletion_count = 0
    shared_retained_count = 0

    for row in rows:
        if isinstance(row, dict):
            content_hash = str(row["content_hash"])
            ref_count = int(row["ref_count"])
            ref_created = row.get("created_at") or row.get("blob_created_at")
            size_bytes = int(row.get("size_bytes") or 0)
            has_external_refs = bool(row.get("has_external_refs", False))
        else:
            content_hash = str(row[0])
            ref_count = int(row[1])
            ref_created = row[2] if row[2] is not None else row[5]
            size_bytes = int(row[4] or 0)
            has_external_refs = bool(row[6])

        created_dt = _coerce_utc_datetime(ref_created, default=now_dt)
        age_seconds = round(max(0.0, (now_dt - created_dt).total_seconds()), 3)
        ages_list.append(age_seconds)

        expired = age_seconds >= ttl
        if not expired:
            within_ttl_count += 1
            eligible_for_deletion = False
            eligibility_status = "within_retention_window"
        elif has_external_refs:
            expired_count += 1
            shared_retained_count += 1
            eligible_for_deletion = False
            eligibility_status = "shared_blob_retained"
        elif ref_count > 1:
            expired_count += 1
            eligible_for_deletion = False
            eligibility_status = "multiple_tenant_references"
        else:
            expired_count += 1
            eligible_for_deletion_count += 1
            eligible_for_deletion = True
            reclaimable_size_bytes += size_bytes
            eligibility_status = "eligible_for_deletion"

        total_references += ref_count
        total_size_bytes += size_bytes

        items.append(
            {
                "content_hash": content_hash,
                "ref_count": ref_count,
                "size_bytes": size_bytes,
                "age_seconds": age_seconds,
                "expired": expired,
                "eligible_for_reference_release": expired,
                "eligible_for_deletion": eligible_for_deletion,
                "eligibility_status": eligibility_status,
            }
        )

    oldest_age = max(ages_list) if ages_list else 0.0
    newest_age = min(ages_list) if ages_list else 0.0
    average_age = round(sum(ages_list) / len(ages_list), 3) if ages_list else 0.0

    return {
        "tenant_id": tenant_id,
        "retention_ttl_seconds": ttl,
        "evaluated_at": now_dt.isoformat(),
        "counts": {
            "total_blobs": len(items),
            "total_references": total_references,
            "expired_blobs": expired_count,
            "within_retention_window": within_ttl_count,
            "eligible_for_deletion": eligible_for_deletion_count,
            "retained_by_shared_reference": shared_retained_count,
            "total_size_bytes": total_size_bytes,
            "reclaimable_size_bytes": reclaimable_size_bytes,
        },
        "ages": {
            "oldest_age_seconds": oldest_age,
            "newest_age_seconds": newest_age,
            "average_age_seconds": average_age,
        },
        "items": items[:bounded_limit],
        "truncated": len(items) > bounded_limit,
    }
