from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import logging
import os
import re
from typing import Any, Mapping, Sequence, Tuple

from cryptography.fernet import Fernet
import db
from storage import (
    EXPORT_MANIFEST_SCHEMA,
    EXPORT_MAX_LIMIT_CAP,
    EXPORT_MAX_LIMIT_DEFAULT,
    ExportManifestEntry,
    clamp_export_manifest_limit,
    compute_export_manifest_digest,
    compute_tenant_export_ref_digest,
    detect_encryption_envelope_version,
    read_only_ciphertext_summary,
    verify_export_manifest_digest,
)

logger = logging.getLogger("harpocrates.evidence_storage")

_WRAPPED_DEK_COMMITMENT_DOMAIN = "harpocrates:wrapped-dek-commitment:v1:"
_FORBIDDEN_EXPORT_SQL_RE = re.compile(
    r"\b(?:insert|update|delete|alter|drop|truncate|create|grant|revoke)\b"
    r"|\bfor\s+(?:update|share|no\s+key\s+update|key\s+share)\b"
)


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


class _ReadOnlyCursorGuard:
    """Cursor wrapper enforcing non-locking ``SELECT`` queries for export manifests."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def __enter__(self) -> "_ReadOnlyCursorGuard":
        entered = self._cursor.__enter__() if hasattr(self._cursor, "__enter__") else self._cursor
        return _ReadOnlyCursorGuard(entered)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        if hasattr(self._cursor, "__exit__"):
            return self._cursor.__exit__(exc_type, exc_val, exc_tb)
        return None

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        normalized = " ".join(str(sql).lower().split())
        if not normalized.startswith("select ") or _FORBIDDEN_EXPORT_SQL_RE.search(normalized):
            raise RuntimeError("export manifest cursor is strictly read-only")
        return self._cursor.execute(sql, params)

    def fetchone(self) -> Any:
        return self._cursor.fetchone()

    def fetchall(self) -> list[Any]:
        return list(self._cursor.fetchall())


def _compute_wrapped_dek_commitment(wrapped_dek_raw: str | bytes | None) -> str | None:
    if wrapped_dek_raw is None:
        return None
    raw_bytes = (
        wrapped_dek_raw.encode("utf-8")
        if isinstance(wrapped_dek_raw, str)
        else bytes(wrapped_dek_raw)
    )
    if not raw_bytes:
        return None
    return hashlib.sha256(
        _WRAPPED_DEK_COMMITMENT_DOMAIN.encode("utf-8") + raw_bytes
    ).hexdigest()


def build_encrypted_evidence_export_manifest(
    authorized_tenant_id: str,
    *,
    content_hashes: Sequence[str] | None = None,
    limit: object = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a strictly read-only encrypted evidence export manifest for one tenant.

    Includes content digests, ciphertext SHA-256 digests and sizes, encryption
    envelope versions, wrapped-key commitments, and privacy-safe authorized
    reference counts. Strictly excludes unwrapped DEKs, raw wrapped DEKs, master
    keys, filesystem paths, filenames, cross-tenant references, and sensitive
    media metadata.
    """
    tenant_ref_digest = compute_tenant_export_ref_digest(authorized_tenant_id)
    cleaned_tenant_id = authorized_tenant_id.strip()
    clamped_limit = clamp_export_manifest_limit(limit)

    requested_hashes: list[str] | None = None
    if content_hashes is not None:
        if isinstance(content_hashes, (str, bytes)):
            raise ValueError("content_hashes must be a sequence of digest strings")
        deduped: set[str] = set()
        for item in content_hashes:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("content_hashes entries must be non-empty digest strings")
            deduped.add(item.strip())
        requested_hashes = sorted(deduped)

    ts = now if now is not None else datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    generated_at = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    if requested_hashes is not None and len(requested_hashes) == 0:
        manifest_digest = compute_export_manifest_digest(
            schema_version=EXPORT_MANIFEST_SCHEMA,
            tenant_ref_digest=tenant_ref_digest,
            entries=[],
        )
        return {
            "ok": True,
            "readOnly": True,
            "schema": EXPORT_MANIFEST_SCHEMA,
            "generatedAt": generated_at,
            "tenantRefDigest": tenant_ref_digest,
            "entryCount": 0,
            "limitApplied": clamped_limit,
            "entries": [],
            "manifestDigest": manifest_digest,
        }

    with db.get_connection() as conn:
        try:
            with _ReadOnlyCursorGuard(conn.cursor()) as cursor:
                if requested_hashes is None:
                    cursor.execute(
                        """
                        select b.content_hash, b.encrypted_dek, b.size_bytes, b.storage_path, r.ref_count
                        from blobs b
                        join tenant_blob_refs r on r.content_hash = b.content_hash
                        where r.tenant_id = %s and r.ref_count > 0
                        order by b.content_hash asc
                        limit %s
                        """,
                        (cleaned_tenant_id, clamped_limit),
                    )
                else:
                    cursor.execute(
                        """
                        select b.content_hash, b.encrypted_dek, b.size_bytes, b.storage_path, r.ref_count
                        from blobs b
                        join tenant_blob_refs r on r.content_hash = b.content_hash
                        where r.tenant_id = %s and r.ref_count > 0 and b.content_hash = any(%s)
                        order by b.content_hash asc
                        limit %s
                        """,
                        (cleaned_tenant_id, requested_hashes, clamped_limit),
                    )
                rows = cursor.fetchall()
        finally:
            if hasattr(conn, "rollback"):
                conn.rollback()

    manifest_entries: list[ExportManifestEntry] = []
    for row in rows:
        explicit_envelope_version: str | None = None
        if isinstance(row, Mapping):
            if "tenant_id" in row and str(row["tenant_id"]) != cleaned_tenant_id:
                continue
            content_digest = str(row["content_hash"])
            encrypted_dek_raw = row.get("encrypted_dek")
            storage_path = row.get("storage_path")
            ref_count = int(row["ref_count"])
            if isinstance(row.get("envelope_version"), str):
                explicit_envelope_version = row["envelope_version"]
        else:
            content_digest = str(row[0])
            encrypted_dek_raw = row[1]
            storage_path = row[3]
            ref_count = int(row[4])
            if len(row) > 5 and isinstance(row[5], str):
                explicit_envelope_version = row[5]

        if ref_count <= 0:
            continue
        if not isinstance(storage_path, str) or not storage_path.strip():
            raise FileNotFoundError("encrypted evidence blob path is missing")

        try:
            ciphertext_sha256, ciphertext_bytes, ciphertext_prefix = (
                read_only_ciphertext_summary(storage_path)
            )
        except FileNotFoundError:
            raise FileNotFoundError(
                "encrypted evidence blob is missing on disk"
            ) from None
        except OSError:
            raise OSError(
                "encrypted evidence blob could not be read"
            ) from None

        if ciphertext_bytes <= 0:
            raise ValueError("encrypted evidence blob is empty or truncated")

        envelope_version = detect_encryption_envelope_version(
            ciphertext_prefix,
            encrypted_dek_raw,
            explicit_envelope_version,
        )
        wrapped_dek_digest = _compute_wrapped_dek_commitment(encrypted_dek_raw)
        manifest_entries.append(
            ExportManifestEntry(
                content_digest=content_digest,
                ciphertext_sha256=ciphertext_sha256,
                ciphertext_bytes=ciphertext_bytes,
                envelope_version=envelope_version,
                wrapped_dek_digest=wrapped_dek_digest,
                tenant_ref_digest=tenant_ref_digest,
                ref_count=ref_count,
            )
        )

    entries_dicts = [
        entry.to_dict()
        for entry in sorted(manifest_entries, key=lambda item: item.content_digest)
    ]
    manifest_digest = compute_export_manifest_digest(
        schema_version=EXPORT_MANIFEST_SCHEMA,
        tenant_ref_digest=tenant_ref_digest,
        entries=entries_dicts,
    )
    return {
        "ok": True,
        "readOnly": True,
        "schema": EXPORT_MANIFEST_SCHEMA,
        "generatedAt": generated_at,
        "tenantRefDigest": tenant_ref_digest,
        "entryCount": len(entries_dicts),
        "limitApplied": clamped_limit,
        "entries": entries_dicts,
        "manifestDigest": manifest_digest,
    }
