import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

LOGGER = logging.getLogger(__name__)

default_storage_dir = "/tmp/harpocrates_jobs"


def _log_warning(message: str) -> None:
    try:
        import logging

        logging.getLogger(__name__).warning(message)
    except Exception:
        pass


def _get_owner_uid(path: Path) -> int | None:
    try:
        return path.stat().st_uid
    except OSError:
        return None


def get_storage_dir() -> Path:
    storage_dir = Path(os.getenv("HARPOCRATES_STORAGE_DIR", default_storage_dir))

    posix = os.name == "posix"
    if posix:
        storage_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            owner_uid = _get_owner_uid(storage_dir)
            if owner_uid == os.getuid():
                current_mode = stat.S_IMODE(storage_dir.stat().st_mode)
                if current_mode != 0o700:
                    os.chmod(storage_dir, 0o700)
            elif owner_uid is not None:
                _log_warning(
                    "Storage directory is owned by another user; "
                    "unable to tighten permissions."
                )
        except OSError:
            pass
    else:
        storage_dir.mkdir(parents=True, exist_ok=True)

    return storage_dir


def get_job_input_path(job_id: int | str) -> Path:
    return get_storage_dir() / f"job_{job_id}_input"


def get_job_output_path(job_id: int | str) -> Path:
    return get_storage_dir() / f"job_{job_id}_output"


def _parse_timestamp(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=timezone.utc)
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def sweep_job_files(
    storage_dir: Path | str | None = None,
    ttl_seconds: int | float | None = None,
    now: datetime | None = None,
) -> int:
    """Sweep and remove expired terminal job files and orphaned files from storage.

    Deletes files for jobs in terminal states older than TTL, and orphaned files
    with no job row older than TTL.
    Never removes files for running or pending jobs.
    Logs counts only, never file names derived from user input.

    Returns the count of deleted files.
    """
    if storage_dir is None:
        target_dir = get_storage_dir()
    else:
        target_dir = Path(storage_dir)

    if not target_dir.exists():
        return 0

    if ttl_seconds is None:
        try:
            from config import load_config

            ttl_seconds = load_config().job_file_ttl_seconds
        except Exception:
            ttl_seconds = 86_400

    if now is None:
        now_dt = datetime.now(timezone.utc)
    elif isinstance(now, datetime):
        now_dt = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    elif isinstance(now, (int, float)):
        now_dt = datetime.fromtimestamp(now, tz=timezone.utc)
    else:
        now_dt = datetime.now(timezone.utc)

    terminal_states = {"completed", "failed", "cancelled", "abandoned"}
    purged_count = 0

    for entry in list(target_dir.iterdir()):
        if not entry.is_file():
            continue

        # Extract job_id from filename pattern: job_<id>_input, job_<id>_output, etc.
        job_id: int | str | None = None
        match = re.match(r"^job_([^_]+)(?:_(?:input|output).*)?$", entry.name)
        if match:
            raw_id = match.group(1)
            job_id = int(raw_id) if raw_id.isdigit() else raw_id

        job = None
        if job_id is not None:
            try:
                from db import get_job

                job = get_job(job_id)
            except Exception:
                job = None

        file_stat = entry.stat()
        file_mtime = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc)

        if job is None:
            # Orphaned file with no job row
            file_age = (now_dt - file_mtime).total_seconds()
            if file_age >= ttl_seconds:
                try:
                    entry.unlink(missing_ok=True)
                    purged_count += 1
                except OSError:
                    pass
        else:
            status = job.get("status")
            if status in terminal_states:
                # Determine job completion / terminal timestamp
                ts_val = (
                    job.get("completed_at")
                    or job.get("failed_at")
                    or job.get("cancelled_at")
                    or job.get("finished_at")
                    or job.get("ended_at")
                    or job.get("updated_at")
                    or job.get("created_at")
                )
                if ts_val is not None:
                    job_dt = _parse_timestamp(ts_val)
                else:
                    job_dt = file_mtime

                job_age = (now_dt - job_dt).total_seconds()
                if job_age >= ttl_seconds:
                    try:
                        entry.unlink(missing_ok=True)
                        purged_count += 1
                        job["purged"] = True
                    except OSError:
                        pass
            # If status not in terminal_states (e.g., 'running' or 'pending'), do not remove.

    if purged_count > 0:
        LOGGER.info("Purged %d stale job files", purged_count)

    return purged_count


purge_stale_job_files = sweep_job_files


EXPORT_MANIFEST_SCHEMA = "harpocrates.encrypted-evidence-export.v1"
EXPORT_MANIFEST_DOMAIN = "harpocrates:evidence-export-manifest:v1:"
EXPORT_TENANT_REF_DOMAIN = "harpocrates:export-tenant-ref:v1:"
EXPORT_MAX_LIMIT_DEFAULT = 100
EXPORT_MAX_LIMIT_CAP = 1000
_STREAM_HASH_CHUNK_BYTES = 65_536


def clamp_export_manifest_limit(limit: object = None) -> int:
    """Validate and clamp export manifest batch limit into ``1..1000``."""
    if limit is None:
        raw = os.getenv("EVIDENCE_EXPORT_MANIFEST_MAX_BLOBS")
        if raw is None or not raw.strip():
            return EXPORT_MAX_LIMIT_DEFAULT
        limit = raw.strip()
    if isinstance(limit, bool):
        raise ValueError("limit must be a positive integer")
    try:
        parsed = int(limit)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be a positive integer") from exc
    if parsed < 1:
        raise ValueError("limit must be a positive integer")
    return min(parsed, EXPORT_MAX_LIMIT_CAP)


def compute_tenant_export_ref_digest(tenant_id: str) -> str:
    """Derive a privacy-safe SHA-256 reference digest for an authorized tenant."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("authorized_tenant_id must be a non-empty string")
    return hashlib.sha256(
        (EXPORT_TENANT_REF_DOMAIN + tenant_id.strip()).encode("utf-8")
    ).hexdigest()


def read_only_ciphertext_summary(path: Path | str) -> tuple[str, int, bytes]:
    """Read ciphertext in bounded chunks without mutating filesystem state.

    Returns ``(sha256_hex, byte_length, prefix_bytes)``.
    """
    target = Path(path)
    hasher = hashlib.sha256()
    total_bytes = 0
    prefix = bytearray()
    with target.open("rb") as handle:
        while True:
            chunk = handle.read(_STREAM_HASH_CHUNK_BYTES)
            if not chunk:
                break
            if len(prefix) < 128:
                need = 128 - len(prefix)
                prefix.extend(chunk[:need])
            hasher.update(chunk)
            total_bytes += len(chunk)
    return hasher.hexdigest(), total_bytes, bytes(prefix)


def _has_fernet_v1_prefix(raw_b64: bytes) -> bool:
    if len(raw_b64) < 4:
        return False
    # Decode first 4 base64url chars (3 raw bytes) to inspect version byte 0x80 safely
    head = raw_b64[:4]
    try:
        decoded = base64.urlsafe_b64decode(head)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) >= 1 and decoded[0] == 0x80


def detect_encryption_envelope_version(
    ciphertext_prefix: bytes,
    wrapped_dek_raw: str | bytes | None,
    explicit_version: str | None = None,
) -> str:
    """Determine encryption envelope version from public framing headers only."""
    if isinstance(explicit_version, str) and explicit_version.strip():
        cleaned = explicit_version.strip()
        if len(cleaned) <= 64 and re.match(r"^[A-Za-z0-9_.-]+$", cleaned):
            return cleaned

    if wrapped_dek_raw is None or (
        isinstance(wrapped_dek_raw, (str, bytes)) and len(wrapped_dek_raw) == 0
    ):
        return "legacy-unversioned"

    dek_bytes = (
        wrapped_dek_raw.encode("utf-8")
        if isinstance(wrapped_dek_raw, str)
        else bytes(wrapped_dek_raw)
    )
    ct_v1 = _has_fernet_v1_prefix(ciphertext_prefix)
    dek_v1 = _has_fernet_v1_prefix(dek_bytes)
    if ct_v1 and dek_v1:
        return "fernet-v1"
    if ct_v1:
        return "fernet-v1-legacy-keywrap"
    return "legacy-v0"


@dataclass(frozen=True)
class ExportManifestEntry:
    """Allow-listed read-only export manifest entry excluding keys and media metadata."""

    content_digest: str
    ciphertext_sha256: str
    ciphertext_bytes: int
    envelope_version: str
    wrapped_dek_digest: str | None
    tenant_ref_digest: str
    ref_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "contentDigest": self.content_digest,
            "ciphertextSha256": self.ciphertext_sha256,
            "ciphertextBytes": self.ciphertext_bytes,
            "envelopeVersion": self.envelope_version,
            "wrappedKeyCommitment": self.wrapped_dek_digest,
            "authorizedReferences": [
                {
                    "tenantRefDigest": self.tenant_ref_digest,
                    "refCount": self.ref_count,
                }
            ],
        }


def compute_export_manifest_digest(
    *,
    schema_version: str,
    tenant_ref_digest: str,
    entries: list[dict[str, Any]],
) -> str:
    canonical = json.dumps(
        {
            "entries": entries,
            "schema": schema_version,
            "tenantRefDigest": tenant_ref_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(EXPORT_MANIFEST_DOMAIN.encode("utf-8") + canonical).hexdigest()


def verify_export_manifest_digest(manifest: Mapping[str, Any]) -> bool:
    """Verify the deterministic SHA-256 commitment of a read-only export manifest."""
    if not isinstance(manifest, Mapping) or manifest.get("readOnly") is not True:
        return False
    schema_version = str(manifest.get("schema") or "")
    tenant_ref_digest = str(manifest.get("tenantRefDigest") or "")
    entries = manifest.get("entries")
    recorded = str(manifest.get("manifestDigest") or "")
    if (
        schema_version != EXPORT_MANIFEST_SCHEMA
        or not tenant_ref_digest
        or not isinstance(entries, list)
        or len(recorded) != 64
    ):
        return False
    expected = compute_export_manifest_digest(
        schema_version=schema_version,
        tenant_ref_digest=tenant_ref_digest,
        entries=entries,
    )
    return hmac.compare_digest(recorded, expected)
