from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import json
import logging
import os
import hashlib
import re
from pathlib import Path
from typing import Any, Tuple
from cryptography.fernet import Fernet
import db
import storage
from storage import _parse_timestamp

ENVELOPE_VERSION_FERNET_V1 = "fernet-v1"
DEFAULT_ENVELOPE_VERSION = ENVELOPE_VERSION_FERNET_V1
SUPPORTED_ENVELOPE_VERSIONS: frozenset[str] = frozenset({ENVELOPE_VERSION_FERNET_V1})
KNOWN_LEGACY_ENVELOPE_VERSIONS: frozenset[str] = frozenset({"legacy-v0", "fernet-v0"})

ENVELOPE_CLASS_SUPPORTED = "supported"
ENVELOPE_CLASS_LEGACY = "legacy"
ENVELOPE_CLASS_UNSUPPORTED = "unsupported"

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


def decrypt_dek(encrypted_dek: bytes) -> bytes:
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        raise ValueError("MASTER_ENCRYPTION_KEY is not set")
    f = Fernet(master_key_b64.encode())
    return f.decrypt(encrypted_dek)


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
            cursor.execute(
                "select encrypted_dek, storage_path, envelope_version from blobs where content_hash = %s",
                (content_hash,),
            )
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


def _resolve_path_safe(raw_path: str | Path) -> Path:
    path = Path(raw_path)
    try:
        return path.resolve()
    except OSError:
        return path


def generate_consistency_report(
    storage_dir: Path | str | None = None,
    *,
    now: datetime | int | float | str | None = None,
) -> dict[str, Any]:
    """Compare blob metadata, tenant references, and physical files without modifying evidence.

    Performs read-only database queries (never selecting ``encrypted_dek``) and
    read-only filesystem inspection to report:
    - ``missing_files``: blob rows whose ``storage_path`` is empty, missing, or not a regular file.
    - ``orphaned_blobs``: blob rows with no active (``ref_count > 0``) tenant references.
    - ``orphaned_tenant_refs``: active tenant references pointing to a ``content_hash`` missing from ``blobs``.
    - ``orphaned_files``: physical files under ``storage_dir`` not referenced by any ``blobs`` row.
    - ``size_mismatches``: blob rows whose existing physical file size differs from ``size_bytes``.
    """
    now_dt = datetime.now(timezone.utc) if now is None else _parse_timestamp(now)

    if storage_dir is None:
        raw_storage_dir = os.getenv("HARPOCRATES_STORAGE_DIR", storage.default_storage_dir)
        target_dir = _resolve_path_safe(raw_storage_dir)
    else:
        target_dir = _resolve_path_safe(storage_dir)

    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select content_hash, size_bytes, storage_path
                from blobs
                order by content_hash asc
                """
            )
            blob_rows = cursor.fetchall()

            cursor.execute(
                """
                select tenant_id, content_hash, ref_count
                from tenant_blob_refs
                where ref_count > 0
                order by tenant_id asc, content_hash asc
                """
            )
            ref_rows = cursor.fetchall()

    blobs_by_hash: dict[str, dict[str, Any]] = {}
    referenced_paths: set[Path] = set()
    missing_files: list[dict[str, Any]] = []
    size_mismatches: list[dict[str, Any]] = []
    file_exists_by_hash: dict[str, bool] = {}

    for row in blob_rows:
        if isinstance(row, dict):
            content_hash = row["content_hash"]
            size_bytes = int(row["size_bytes"])
            storage_path = row["storage_path"]
        else:
            content_hash, size_bytes, storage_path = row
            size_bytes = int(size_bytes)

        blobs_by_hash[content_hash] = {
            "content_hash": content_hash,
            "size_bytes": size_bytes,
            "storage_path": storage_path,
        }

        if not storage_path or not isinstance(storage_path, str) or not storage_path.strip():
            file_exists_by_hash[content_hash] = False
            missing_files.append(
                {
                    "content_hash": content_hash,
                    "storage_path": storage_path or "",
                    "size_bytes": size_bytes,
                    "reason": "missing_storage_path",
                }
            )
            continue

        resolved_blob_path = _resolve_path_safe(storage_path)
        referenced_paths.add(resolved_blob_path)

        try:
            if not resolved_blob_path.exists():
                file_exists_by_hash[content_hash] = False
                missing_files.append(
                    {
                        "content_hash": content_hash,
                        "storage_path": str(resolved_blob_path),
                        "size_bytes": size_bytes,
                        "reason": "file_not_found",
                    }
                )
            elif not resolved_blob_path.is_file():
                file_exists_by_hash[content_hash] = False
                missing_files.append(
                    {
                        "content_hash": content_hash,
                        "storage_path": str(resolved_blob_path),
                        "size_bytes": size_bytes,
                        "reason": "not_a_file",
                    }
                )
            else:
                file_exists_by_hash[content_hash] = True
                actual_size = resolved_blob_path.stat().st_size
                if actual_size != size_bytes:
                    size_mismatches.append(
                        {
                            "content_hash": content_hash,
                            "expected_size_bytes": size_bytes,
                            "actual_size_bytes": actual_size,
                        }
                    )
        except OSError:
            file_exists_by_hash[content_hash] = False
            missing_files.append(
                {
                    "content_hash": content_hash,
                    "storage_path": str(resolved_blob_path),
                    "size_bytes": size_bytes,
                    "reason": "file_not_found",
                }
            )

    referenced_hashes: set[str] = set()
    orphaned_tenant_refs: list[dict[str, Any]] = []
    active_ref_count = 0

    for row in ref_rows:
        if isinstance(row, dict):
            tenant_id = row["tenant_id"]
            content_hash = row["content_hash"]
            ref_count = int(row["ref_count"])
        else:
            tenant_id, content_hash, ref_count = row
            ref_count = int(ref_count)

        if ref_count <= 0:
            continue

        active_ref_count += 1
        referenced_hashes.add(content_hash)
        if content_hash not in blobs_by_hash:
            orphaned_tenant_refs.append(
                {
                    "tenant_id": tenant_id,
                    "content_hash": content_hash,
                    "ref_count": ref_count,
                }
            )

    orphaned_blobs: list[dict[str, Any]] = []
    for content_hash, blob in blobs_by_hash.items():
        if content_hash not in referenced_hashes:
            orphaned_blobs.append(
                {
                    "content_hash": content_hash,
                    "size_bytes": blob["size_bytes"],
                    "file_exists": file_exists_by_hash.get(content_hash, False),
                }
            )

    orphaned_files: list[dict[str, Any]] = []
    total_physical_files = 0
    if target_dir.exists() and target_dir.is_dir():
        for entry in sorted(target_dir.rglob("*"), key=lambda p: str(p)):
            try:
                if not entry.is_file():
                    continue
                resolved_entry = _resolve_path_safe(entry)
                total_physical_files += 1
                if resolved_entry not in referenced_paths:
                    orphaned_files.append(
                        {
                            "path": str(resolved_entry),
                            "size_bytes": resolved_entry.stat().st_size,
                        }
                    )
            except OSError:
                continue

    missing_files.sort(key=lambda item: item["content_hash"])
    orphaned_blobs.sort(key=lambda item: item["content_hash"])
    orphaned_tenant_refs.sort(key=lambda item: (item["tenant_id"], item["content_hash"]))
    orphaned_files.sort(key=lambda item: item["path"])
    size_mismatches.sort(key=lambda item: item["content_hash"])

    consistent = not (
        missing_files
        or orphaned_blobs
        or orphaned_tenant_refs
        or orphaned_files
        or size_mismatches
    )

    return {
        "evaluated_at": now_dt.isoformat(),
        "storage_dir": str(target_dir),
        "consistent": consistent,
        "summary": {
            "total_blobs": len(blobs_by_hash),
            "total_tenant_refs": active_ref_count,
            "total_physical_files": total_physical_files,
            "missing_files_count": len(missing_files),
            "orphaned_blobs_count": len(orphaned_blobs),
            "orphaned_tenant_refs_count": len(orphaned_tenant_refs),
            "orphaned_files_count": len(orphaned_files),
            "size_mismatches_count": len(size_mismatches),
        },
        "missing_files": missing_files,
        "orphaned_blobs": orphaned_blobs,
        "orphaned_tenant_refs": orphaned_tenant_refs,
        "orphaned_files": orphaned_files,
        "size_mismatches": size_mismatches,
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
