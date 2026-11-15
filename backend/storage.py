from collections import OrderedDict
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
import tempfile
import threading
from typing import Any, Mapping
import uuid

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
    *,
    receipt_ledger: "DeletionReceiptLedger | None" = None,
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
                active_ledger = receipt_ledger or _configured_file_ledger()
                rec_id: str | None = None
                if active_ledger is not None:
                    rec = active_ledger.approve_selection(
                        identifier=f"job-file:{entry.name}",
                        reason="expired_job_artifact",
                        requires_metadata_delete=False,
                    )
                    rec_id = rec.receipt_id
                try:
                    entry.unlink(missing_ok=True)
                    purged_count += 1
                    if active_ledger is not None and rec_id is not None:
                        active_ledger.complete_deletion(
                            rec_id,
                            file_deleted=True,
                            metadata_deleted=False,
                        )
                except OSError as err:
                    if active_ledger is not None and rec_id is not None:
                        active_ledger.record_storage_failure(
                            rec_id, error_code=type(err).__name__
                        )
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
                    active_ledger = receipt_ledger or _configured_file_ledger()
                    rec_id = None
                    if active_ledger is not None:
                        rec = active_ledger.approve_selection(
                            identifier=f"job:{job_id}:{entry.name}",
                            reason="expired_job_artifact",
                            requires_metadata_delete=False,
                        )
                        rec_id = rec.receipt_id
                    try:
                        entry.unlink(missing_ok=True)
                        purged_count += 1
                        job["purged"] = True
                        if active_ledger is not None and rec_id is not None:
                            active_ledger.complete_deletion(
                                rec_id,
                                file_deleted=True,
                                metadata_deleted=False,
                            )
                    except OSError as err:
                        if active_ledger is not None and rec_id is not None:
                            active_ledger.record_storage_failure(
                                rec_id, error_code=type(err).__name__
                            )
            # If status not in terminal_states (e.g., 'running' or 'pending'), do not remove.

    if purged_count > 0:
        LOGGER.info("Purged %d stale job files", purged_count)

    return purged_count


purge_stale_job_files = sweep_job_files


DELETION_AUDIT_REF_DOMAIN = "harpocrates:deletion-audit-ref:v1:"
DELETION_PHASE1_DOMAIN = "harpocrates:deletion-receipt:phase1:v1:"
DELETION_PHASE2_DOMAIN = "harpocrates:deletion-receipt:phase2:v1:"
ALLOWED_DELETION_REASONS = frozenset(
    {
        "unreferenced_blob_gc",
        "retention_expired",
        "tenant_purge",
        "expired_job_artifact",
    }
)
DEFAULT_DELETION_RECEIPT_MAX = 4096


def compute_deletion_audit_ref(identifier: str) -> str:
    """Compute a non-reversible 32-byte hex audit reference from an evidence identifier."""
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("identifier must be a non-empty string")
    payload = (DELETION_AUDIT_REF_DOMAIN + identifier.strip()).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_hash(domain: str, payload: Mapping[str, Any]) -> str:
    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(domain.encode("utf-8") + serialized).hexdigest()


@dataclass(frozen=True)
class DeletionReceipt:
    """Two-phase privacy-safe deletion receipt for retained evidence."""

    receipt_id: str
    audit_ref: str
    reason: str
    phase: str
    approved_at: str
    requires_metadata_delete: bool
    selection_digest: str
    file_deleted: bool = False
    metadata_deleted: bool = False
    completed_at: str | None = None
    completion_digest: str | None = None
    last_error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "receiptId": self.receipt_id,
            "auditRef": self.audit_ref,
            "reason": self.reason,
            "phase": self.phase,
            "approvedAt": self.approved_at,
            "completedAt": self.completed_at,
            "actions": {
                "selectionApproved": True,
                "requiresMetadataDelete": self.requires_metadata_delete,
                "fileDeleted": self.file_deleted,
                "metadataDeleted": self.metadata_deleted,
            },
            "selectionDigest": self.selection_digest,
            "completionDigest": self.completion_digest,
            "lastErrorCode": self.last_error_code,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DeletionReceipt:
        actions = raw.get("actions") if isinstance(raw.get("actions"), Mapping) else {}
        return cls(
            receipt_id=str(raw["receiptId"]),
            audit_ref=str(raw["auditRef"]),
            reason=str(raw["reason"]),
            phase=str(raw["phase"]),
            approved_at=str(raw["approvedAt"]),
            requires_metadata_delete=bool(actions.get("requiresMetadataDelete", True)),
            selection_digest=str(raw["selectionDigest"]),
            file_deleted=bool(actions.get("fileDeleted", False)),
            metadata_deleted=bool(actions.get("metadataDeleted", False)),
            completed_at=str(raw["completedAt"]) if raw.get("completedAt") else None,
            completion_digest=str(raw["completionDigest"])
            if raw.get("completionDigest")
            else None,
            last_error_code=str(raw["lastErrorCode"])
            if raw.get("lastErrorCode")
            else None,
        )


def verify_deletion_receipt(
    receipt: DeletionReceipt | Mapping[str, Any],
    *,
    expected_identifier: str | None = None,
) -> bool:
    """Verify cryptographic phase digests (and optional identifier binding) of a receipt."""
    parsed = (
        receipt
        if isinstance(receipt, DeletionReceipt)
        else DeletionReceipt.from_dict(receipt)
    )
    if parsed.reason not in ALLOWED_DELETION_REASONS:
        return False
    if expected_identifier is not None:
        expected_ref = compute_deletion_audit_ref(expected_identifier)
        if not hmac.compare_digest(parsed.audit_ref, expected_ref):
            return False

    expected_phase1 = _canonical_hash(
        DELETION_PHASE1_DOMAIN,
        {
            "approvedAt": parsed.approved_at,
            "auditRef": parsed.audit_ref,
            "reason": parsed.reason,
            "receiptId": parsed.receipt_id,
            "requiresMetadataDelete": parsed.requires_metadata_delete,
        },
    )
    if not hmac.compare_digest(parsed.selection_digest, expected_phase1):
        return False

    if parsed.phase == "completed":
        if not parsed.file_deleted:
            return False
        if parsed.requires_metadata_delete and not parsed.metadata_deleted:
            return False
        if not parsed.completed_at or not parsed.completion_digest:
            return False
        expected_phase2 = _canonical_hash(
            DELETION_PHASE2_DOMAIN,
            {
                "completedAt": parsed.completed_at,
                "fileDeleted": parsed.file_deleted,
                "metadataDeleted": parsed.metadata_deleted,
                "receiptId": parsed.receipt_id,
                "selectionDigest": parsed.selection_digest,
            },
        )
        return hmac.compare_digest(parsed.completion_digest, expected_phase2)

    return parsed.completion_digest is None and parsed.completed_at is None


def _receipt_max_entries() -> int:
    raw = os.getenv("DELETION_RECEIPT_MAX_ENTRIES")
    if raw is None or not raw.strip():
        return DEFAULT_DELETION_RECEIPT_MAX
    try:
        parsed = int(raw.strip())
    except ValueError:
        return DEFAULT_DELETION_RECEIPT_MAX
    return max(16, min(parsed, 100_000))


def _receipt_log_path(explicit: Path | str | None = None) -> Path | None:
    if explicit is not None:
        return Path(explicit)
    raw = os.getenv("DELETION_RECEIPT_LOG_PATH")
    if raw and raw.strip():
        return Path(raw.strip())
    return None


class DeletionReceiptLedger:
    """Thread-safe bounded two-phase deletion receipt ledger with optional file persistence."""

    def __init__(
        self,
        *,
        max_entries: int | None = None,
        log_path: Path | str | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._explicit_max = max_entries
        self._explicit_path = Path(log_path) if log_path is not None else None
        self._receipts: OrderedDict[str, DeletionReceipt] = OrderedDict()
        self._loaded_path: Path | None = None

    def _effective_max(self) -> int:
        if self._explicit_max is not None:
            return max(1, int(self._explicit_max))
        return _receipt_max_entries()

    def _effective_path(self) -> Path | None:
        return _receipt_log_path(self._explicit_path)

    def _ensure_loaded_locked(self) -> None:
        path = self._effective_path()
        if path is None or self._loaded_path == path:
            return
        self._loaded_path = path
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, Mapping):
            return
        for item in raw.get("receipts", []):
            if not isinstance(item, Mapping):
                continue
            try:
                rec = DeletionReceipt.from_dict(item)
            except (KeyError, TypeError, ValueError):
                continue
            self._receipts[rec.receipt_id] = rec
        self._trim_locked()

    def _trim_locked(self) -> None:
        cap = self._effective_max()
        while len(self._receipts) > cap:
            self._receipts.popitem(last=False)

    def _flush_locked(self) -> None:
        path = self._effective_path()
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {
                "version": 1,
                "receipts": [rec.to_dict() for rec in self._receipts.values()],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=".del_receipts_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
            try:
                os.chmod(tmp_name, 0o600)
            except OSError:
                pass
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def approve_selection(
        self,
        *,
        identifier: str,
        reason: str = "unreferenced_blob_gc",
        requires_metadata_delete: bool = True,
        now: datetime | None = None,
    ) -> DeletionReceipt:
        """Phase 1: Record approved selection before executing physical storage deletion."""
        if reason not in ALLOWED_DELETION_REASONS:
            raise ValueError(f"unsupported deletion reason: {reason}")
        audit_ref = compute_deletion_audit_ref(identifier)
        receipt_id = uuid.uuid4().hex
        approved_dt = (
            now.astimezone(timezone.utc)
            if isinstance(now, datetime) and now.tzinfo is not None
            else (
                now.replace(tzinfo=timezone.utc)
                if isinstance(now, datetime)
                else datetime.now(timezone.utc)
            )
        )
        approved_at = approved_dt.isoformat()
        selection_digest = _canonical_hash(
            DELETION_PHASE1_DOMAIN,
            {
                "approvedAt": approved_at,
                "auditRef": audit_ref,
                "reason": reason,
                "receiptId": receipt_id,
                "requiresMetadataDelete": bool(requires_metadata_delete),
            },
        )
        receipt = DeletionReceipt(
            receipt_id=receipt_id,
            audit_ref=audit_ref,
            reason=reason,
            phase="selection_approved",
            approved_at=approved_at,
            requires_metadata_delete=bool(requires_metadata_delete),
            selection_digest=selection_digest,
        )
        with self._lock:
            self._ensure_loaded_locked()
            self._receipts[receipt_id] = receipt
            self._trim_locked()
            self._flush_locked()
        return receipt

    def complete_deletion(
        self,
        receipt_id: str,
        *,
        file_deleted: bool,
        metadata_deleted: bool,
        now: datetime | None = None,
    ) -> DeletionReceipt:
        """Phase 2: Record completed storage and metadata deletion actions."""
        if not file_deleted:
            raise ValueError("cannot complete deletion receipt when file_deleted is False")
        completed_dt = (
            now.astimezone(timezone.utc)
            if isinstance(now, datetime) and now.tzinfo is not None
            else (
                now.replace(tzinfo=timezone.utc)
                if isinstance(now, datetime)
                else datetime.now(timezone.utc)
            )
        )
        completed_at = completed_dt.isoformat()
        with self._lock:
            self._ensure_loaded_locked()
            existing = self._receipts.get(receipt_id)
            if existing is None:
                raise KeyError(f"unknown deletion receipt: {receipt_id}")
            if existing.requires_metadata_delete and not metadata_deleted:
                raise ValueError(
                    "cannot complete deletion receipt before metadata deletion completes"
                )
            completion_digest = _canonical_hash(
                DELETION_PHASE2_DOMAIN,
                {
                    "completedAt": completed_at,
                    "fileDeleted": bool(file_deleted),
                    "metadataDeleted": bool(metadata_deleted),
                    "receiptId": existing.receipt_id,
                    "selectionDigest": existing.selection_digest,
                },
            )
            updated = DeletionReceipt(
                receipt_id=existing.receipt_id,
                audit_ref=existing.audit_ref,
                reason=existing.reason,
                phase="completed",
                approved_at=existing.approved_at,
                requires_metadata_delete=existing.requires_metadata_delete,
                selection_digest=existing.selection_digest,
                file_deleted=bool(file_deleted),
                metadata_deleted=bool(metadata_deleted),
                completed_at=completed_at,
                completion_digest=completion_digest,
                last_error_code=None,
            )
            self._receipts[receipt_id] = updated
            self._receipts.move_to_end(receipt_id)
            self._flush_locked()
            return updated

    def record_storage_failure(
        self,
        receipt_id: str,
        *,
        error_code: str,
        file_deleted: bool = False,
        metadata_deleted: bool = False,
    ) -> DeletionReceipt:
        """Record an incomplete storage deletion attempt without marking Phase 2 complete."""
        safe_code = re.sub(r"[^A-Za-z0-9_.-]", "_", str(error_code or "OSError"))[:64]
        with self._lock:
            self._ensure_loaded_locked()
            existing = self._receipts.get(receipt_id)
            if existing is None:
                raise KeyError(f"unknown deletion receipt: {receipt_id}")
            updated = DeletionReceipt(
                receipt_id=existing.receipt_id,
                audit_ref=existing.audit_ref,
                reason=existing.reason,
                phase="storage_failed",
                approved_at=existing.approved_at,
                requires_metadata_delete=existing.requires_metadata_delete,
                selection_digest=existing.selection_digest,
                file_deleted=bool(file_deleted),
                metadata_deleted=bool(metadata_deleted),
                completed_at=None,
                completion_digest=None,
                last_error_code=safe_code,
            )
            self._receipts[receipt_id] = updated
            self._receipts.move_to_end(receipt_id)
            self._flush_locked()
            return updated

    def get_receipt(self, receipt_id: str) -> DeletionReceipt | None:
        with self._lock:
            self._ensure_loaded_locked()
            return self._receipts.get(receipt_id)

    def list_receipts(
        self,
        *,
        phase: str | None = None,
        audit_ref: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        capped = max(1, min(int(limit), 1000))
        with self._lock:
            self._ensure_loaded_locked()
            items = list(self._receipts.values())
        filtered = [
            rec.to_dict()
            for rec in reversed(items)
            if (phase is None or rec.phase == phase)
            and (audit_ref is None or hmac.compare_digest(rec.audit_ref, audit_ref))
        ]
        return filtered[:capped]

    def clear(self) -> None:
        with self._lock:
            self._receipts.clear()
            self._loaded_path = None


_DEFAULT_DELETION_LEDGER = DeletionReceiptLedger()


def _configured_file_ledger() -> DeletionReceiptLedger | None:
    if _receipt_log_path() is not None:
        return _DEFAULT_DELETION_LEDGER
    return None


def get_default_deletion_ledger() -> DeletionReceiptLedger:
    return _DEFAULT_DELETION_LEDGER


def reset_deletion_receipts() -> None:
    _DEFAULT_DELETION_LEDGER.clear()
