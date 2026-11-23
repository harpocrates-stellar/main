from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import json
import logging
import os
import hashlib
import re
from typing import Any, Tuple
from cryptography.fernet import Fernet
import db
from storage import _parse_timestamp

logger = logging.getLogger("harpocrates.evidence_storage")

EXPORT_MANIFEST_VERSION = 1
DEFAULT_ENVELOPE_VERSION = "fernet-v1"
_HEX_32_PATTERN = re.compile(r"[0-9a-fA-F]{64}")


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
def preview_tenant_retention(
    tenant_id: str,
    *,
    now: datetime | int | float | str | None = None,
    ttl_seconds: int | float | None = None,
) -> dict[str, Any]:
    """Return a read-only retention preview for a single authenticated tenant.

    Reports blob counts, ages, and deletion eligibility scoped strictly to
    ``tenant_id``. Other tenants' content hashes, tenant identifiers, and all
    filesystem storage paths are never queried or returned.
    """
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id must be a non-empty string")
    normalized_tenant = tenant_id.strip()

    if ttl_seconds is not None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or ttl_seconds < 0:
            raise ValueError("ttl_seconds must be a non-negative number")

    now_dt = datetime.now(timezone.utc) if now is None else _parse_timestamp(now)

    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select
                    r.content_hash,
                    r.ref_count,
                    b.size_bytes,
                    b.created_at,
                    exists (
                        select 1
                        from tenant_blob_refs other
                        where other.content_hash = r.content_hash
                          and other.tenant_id <> r.tenant_id
                          and other.ref_count > 0
                    ) as shared_with_other_tenants
                from tenant_blob_refs r
                join blobs b on b.content_hash = r.content_hash
                where r.tenant_id = %s
                  and r.ref_count > 0
                order by b.created_at asc, r.content_hash asc
                """,
                (normalized_tenant,),
            )
            rows = cursor.fetchall()

    items: list[dict[str, Any]] = []
    ages: list[float] = []
    total_ref_count = 0
    total_size_bytes = 0
    eligible_count = 0
    shared_count = 0

    for row in rows:
        if isinstance(row, dict):
            content_hash = row["content_hash"]
            ref_count = int(row["ref_count"])
            size_bytes = int(row["size_bytes"])
            created_at = row["created_at"]
            shared = bool(row["shared_with_other_tenants"])
        else:
            content_hash, ref_count, size_bytes, created_at, shared = row
            ref_count = int(ref_count)
            size_bytes = int(size_bytes)
            shared = bool(shared)

        created_dt = _parse_timestamp(created_at)
        age_seconds = max(0.0, (now_dt - created_dt).total_seconds())
        ages.append(age_seconds)

        total_ref_count += ref_count
        total_size_bytes += size_bytes
        if shared:
            shared_count += 1

        if shared:
            deletion_eligible = False
            ineligible_reason: str | None = "shared_with_other_tenants"
        elif ttl_seconds is not None and age_seconds < ttl_seconds:
            deletion_eligible = False
            ineligible_reason = "within_retention_window"
        else:
            deletion_eligible = True
            ineligible_reason = None
            eligible_count += 1

        items.append(
            {
                "content_hash": content_hash,
                "ref_count": ref_count,
                "size_bytes": size_bytes,
                "age_seconds": age_seconds,
                "deletion_eligible": deletion_eligible,
                "deletion_ineligible_reason": ineligible_reason,
            }
        )

    blob_count = len(items)
    return {
        "tenant_id": normalized_tenant,
        "evaluated_at": now_dt.isoformat(),
        "ttl_seconds": ttl_seconds,
        "blob_count": blob_count,
        "total_ref_count": total_ref_count,
        "total_size_bytes": total_size_bytes,
        "eligible_for_deletion_count": eligible_count,
        "retained_count": blob_count - eligible_count,
        "shared_blob_count": shared_count,
        "oldest_age_seconds": max(ages) if ages else None,
        "newest_age_seconds": min(ages) if ages else None,
        "average_age_seconds": (sum(ages) / blob_count) if ages else None,
        "blobs": items,
    }


def rotate_encryption_key(new_master_key=None, old_master_key=None, key_id=None, *, content_hashes=None):
    import os
    from cryptography.fernet import Fernet
    old_key = old_master_key or os.getenv("MASTER_ENCRYPTION_KEY")
    new_key = new_master_key or os.getenv("MASTER_ENCRYPTION_KEY")
    if not old_key:
        raise ValueError("old master key is not set")
    if not new_key:
        raise ValueError("new master key is not set")
    old_f = Fernet(old_key.encode() if isinstance(old_key, str) else old_key)
    new_f = Fernet(new_key.encode() if isinstance(new_key, str) else new_key)
    version = key_id or "v2"
    rotated = []
    rollback = []
    hashes = content_hashes
    if hashes is None:
        hashes = []
        try:
            import db
            with db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("select content_hash from blobs")
                    for row in cursor.fetchall():
                        hashes.append(row["content_hash"] if isinstance(row, dict) else row[0])
        except Exception:
            hashes = []
    for content_hash in hashes:
        info = get_blob_info(content_hash)
        if not info:
            continue
        old_wrapped = info["encrypted_dek"]
        dek = old_f.decrypt(old_wrapped.encode() if isinstance(old_wrapped, str) else old_wrapped)
        new_wrapped = new_f.encrypt(dek)
        assert new_f.decrypt(new_wrapped) == dek
        versioned = (version + ":" + (new_wrapped.decode() if isinstance(new_wrapped, (bytes, bytearray)) else str(new_wrapped))).encode()
        record_blob(content_hash, versioned, info.get("size_bytes", 0) or 0, info.get("storage_path", ""))
        rotated.append(content_hash)
        rollback.append({"content_hash": content_hash, "encrypted_dek": old_wrapped})
    return {"key_id": version, "rotated": rotated, "rollback": rollback}

rotate_key = rotate_encryption_key
rotate_evidence_key = rotate_encryption_key
rewrap_dek = rotate_encryption_key
rewrap_data_keys = rotate_encryption_key
stage_key_rotation = rotate_encryption_key
rotate_master_key = rotate_encryption_key


def _normalize_authorized_tenants(authorized_tenants: Iterable[str]) -> list[str]:
    if isinstance(authorized_tenants, (str, bytes)):
        raise ValueError("authorized_tenants must be an iterable of tenant identifiers, not a string")
    normalized: set[str] = set()
    for tenant in authorized_tenants:
        if not isinstance(tenant, str) or not tenant.strip():
            raise ValueError("authorized tenant identifier must be a non-empty string")
        normalized.add(tenant.strip())
    if not normalized:
        raise ValueError("authorized_tenants must contain at least one tenant identifier")
    return sorted(normalized)


def _normalize_digest(value: object) -> str:
    if not isinstance(value, str) or _HEX_32_PATTERN.fullmatch(value) is None:
        raise ValueError("blob digest must be a 32-byte hex string")
    return value.lower()


def _normalize_envelope_version(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("envelope_version must be a non-empty string")
    return value.strip()


def _normalize_non_negative_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _normalize_generated_at(generated_at: datetime | None) -> str:
    if generated_at is None:
        dt = datetime.now(timezone.utc)
    else:
        if not isinstance(generated_at, datetime) or generated_at.tzinfo is None:
            raise ValueError("generated_at must be a timezone-aware datetime")
        dt = generated_at.astimezone(timezone.utc)
    return dt.isoformat()


def serialize_evidence_export_manifest(manifest: Mapping[str, Any]) -> str:
    """Serialize an export manifest to canonical JSON."""
    return json.dumps(manifest, separators=(",", ":"), sort_keys=True)


def build_evidence_export_manifest(
    rows: Iterable[Mapping[str, Any]],
    authorized_tenants: Iterable[str],
    *,
    envelope_version: str = DEFAULT_ENVELOPE_VERSION,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a read-only encrypted evidence export manifest from storage rows.

    Only allowlisted fields (blob digest, envelope version, size_bytes, and
    authorized tenant references with positive ref_count) are included.
    Unwrapped data keys, wrapped DEKs, local storage paths, and sensitive media
    metadata are strictly excluded.
    """
    tenants = _normalize_authorized_tenants(authorized_tenants)
    allowed_set = set(tenants)
    default_env_version = _normalize_envelope_version(envelope_version)
    timestamp = _normalize_generated_at(generated_at)

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        tenant_id = row.get("tenant_id")
        if not isinstance(tenant_id, str) or tenant_id.strip() not in allowed_set:
            continue
        tenant_id = tenant_id.strip()

        ref_count = _normalize_non_negative_int(row.get("ref_count", 0), "ref_count")
        if ref_count <= 0:
            continue

        digest = _normalize_digest(row.get("content_hash"))
        size_bytes = _normalize_non_negative_int(row.get("size_bytes"), "size_bytes")
        row_env_version = _normalize_envelope_version(
            row.get("envelope_version") or default_env_version
        )

        entry = grouped.get(digest)
        if entry is None:
            grouped[digest] = {
                "blob_digest": digest,
                "envelope_version": row_env_version,
                "size_bytes": size_bytes,
                "_refs": {tenant_id: ref_count},
            }
        else:
            if entry["size_bytes"] != size_bytes:
                raise ValueError(f"conflicting size_bytes for blob {digest}")
            if entry["envelope_version"] != row_env_version:
                raise ValueError(f"conflicting envelope_version for blob {digest}")
            entry["_refs"][tenant_id] = entry["_refs"].get(tenant_id, 0) + ref_count

    entries: list[dict[str, Any]] = []
    for digest in sorted(grouped.keys()):
        raw_entry = grouped[digest]
        refs = [
            {"tenant_id": tid, "ref_count": raw_entry["_refs"][tid]}
            for tid in sorted(raw_entry["_refs"].keys())
        ]
        entries.append(
            {
                "blob_digest": raw_entry["blob_digest"],
                "envelope_version": raw_entry["envelope_version"],
                "size_bytes": raw_entry["size_bytes"],
                "authorized_references": refs,
            }
        )

    payload: dict[str, Any] = {
        "manifest_version": EXPORT_MANIFEST_VERSION,
        "read_only": True,
        "generated_at": timestamp,
        "authorized_tenants": tenants,
        "entry_count": len(entries),
        "entries": entries,
    }
    canonical = serialize_evidence_export_manifest(payload).encode("utf-8")
    payload["manifest_digest"] = hashlib.sha256(canonical).hexdigest()
    return payload


def export_evidence_manifest(
    authorized_tenants: Iterable[str],
    *,
    envelope_version: str = DEFAULT_ENVELOPE_VERSION,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Query encrypted evidence metadata in read-only mode and build an export manifest.

    Never unwraps DEKs, never selects encrypted_dek or storage_path, and never
    mutates database state.
    """
    tenants = _normalize_authorized_tenants(authorized_tenants)
    default_env_version = _normalize_envelope_version(envelope_version)
    _normalize_generated_at(generated_at)

    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select b.content_hash, b.size_bytes, r.tenant_id, r.ref_count
                from blobs b
                inner join tenant_blob_refs r on r.content_hash = b.content_hash
                where r.tenant_id = any(%s) and r.ref_count > 0
                order by b.content_hash asc, r.tenant_id asc
                """,
                (tenants,),
            )
            rows = [dict(row) for row in cursor.fetchall()]

    return build_evidence_export_manifest(
        rows,
        tenants,
        envelope_version=default_env_version,
        generated_at=generated_at,
    )
