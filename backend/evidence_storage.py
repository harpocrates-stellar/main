from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import re
from typing import Any, Tuple
import uuid
from cryptography.fernet import Fernet, InvalidToken
import db
from storage import (
    KEY_ROTATION_JOURNAL_SCHEMA,
    read_key_rotation_journal,
    write_key_rotation_journal,
)

logger = logging.getLogger("harpocrates.evidence_storage")

LEGACY_KEY_ID = "legacy"
KEY_ID_PREFIX = "kid"
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class KeyRotationError(RuntimeError):
    """Base fail-closed error for staged evidence encryption-key rotation."""

    def __init__(self, message: str, *, reason_code: str = "KEY_ROTATION_ERROR") -> None:
        super().__init__(message)
        self.reason_code = reason_code


class KeyRotationVerificationError(KeyRotationError):
    """Raised when on-disk ciphertext or DEK verification fails prior to commit."""

    def __init__(self, message: str, *, reason_code: str = "CIPHERTEXT_VERIFICATION_FAILED") -> None:
        super().__init__(message, reason_code=reason_code)


def validate_key_id(key_id: str, *, allow_legacy: bool = False) -> str:
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise KeyRotationError("Invalid encryption key identifier format.", reason_code="INVALID_KEY_ID")
    if not allow_legacy and key_id == LEGACY_KEY_ID:
        raise KeyRotationError(
            "Target encryption key identifier must be an explicit versioned ID.",
            reason_code="LEGACY_TARGET_FORBIDDEN",
        )
    return key_id


def parse_wrapped_dek(encrypted_dek: bytes | str) -> tuple[str, bytes]:
    """Return `(key_id, raw_fernet_token)` from a versioned or legacy wrapped DEK."""
    text = encrypted_dek.decode("ascii") if isinstance(encrypted_dek, bytes) else str(encrypted_dek)
    if text.startswith(f"{KEY_ID_PREFIX}:"):
        parts = text.split(":", 2)
        if len(parts) != 3 or not parts[1] or not parts[2]:
            raise KeyRotationError("Malformed versioned DEK header.", reason_code="MALFORMED_WRAPPED_DEK")
        key_id = validate_key_id(parts[1], allow_legacy=True)
        return key_id, parts[2].encode("ascii")
    return LEGACY_KEY_ID, text.encode("ascii")


def wrap_dek_with_key_id(
    dek: bytes,
    master_key: bytes | str,
    key_id: str,
) -> bytes:
    """Wrap `dek` under `master_key` with an explicit versioned `key_id` prefix."""
    validated_id = validate_key_id(key_id, allow_legacy=False)
    key_bytes = master_key.encode("ascii") if isinstance(master_key, str) else master_key
    token = Fernet(key_bytes).encrypt(dek)
    return f"{KEY_ID_PREFIX}:{validated_id}:".encode("ascii") + token


def load_master_key_ring_from_env() -> dict[str, bytes]:
    """Load optional `MASTER_ENCRYPTION_KEY_RING` (`id=key,...`) and `MASTER_ENCRYPTION_KEY`."""
    ring: dict[str, bytes] = {}
    raw_ring = os.getenv("MASTER_ENCRYPTION_KEY_RING", "")
    if raw_ring.strip():
        for entry in raw_ring.split(","):
            entry = entry.strip()
            if not entry:
                continue
            key_id, sep, key_val = entry.partition("=")
            if not sep or not key_val.strip():
                raise KeyRotationError(
                    "MASTER_ENCRYPTION_KEY_RING entries must be <key_id>=<fernet_key>.",
                    reason_code="INVALID_KEY_RING_CONFIG",
                )
            validated = validate_key_id(key_id.strip(), allow_legacy=True)
            ring[validated] = key_val.strip().encode("ascii")

    primary = os.getenv("MASTER_ENCRYPTION_KEY")
    if primary:
        primary_bytes = primary.strip().encode("ascii")
        ring.setdefault(LEGACY_KEY_ID, primary_bytes)
        active_id = os.getenv("MASTER_ENCRYPTION_KEY_ID")
        if active_id and active_id.strip():
            ring.setdefault(validate_key_id(active_id.strip(), allow_legacy=True), primary_bytes)
    return ring


def generate_dek(*, key_id: str | None = None) -> Tuple[bytes, bytes]:
    """Generates a Data Encryption Key (DEK) and its encrypted form (using a Master Key)."""
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        master_key_b64 = Fernet.generate_key().decode()
    f = Fernet(master_key_b64.encode())

    dek = Fernet.generate_key()
    effective_key_id = key_id if key_id is not None else os.getenv("MASTER_ENCRYPTION_KEY_ID")
    if effective_key_id:
        encrypted_dek = wrap_dek_with_key_id(dek, master_key_b64.encode(), effective_key_id.strip())
    else:
        encrypted_dek = f.encrypt(dek)

    return dek, encrypted_dek


def decrypt_dek(
    encrypted_dek: bytes | str,
    *,
    key_ring: Mapping[str, bytes | str] | None = None,
) -> bytes:
    key_id, raw_token = parse_wrapped_dek(encrypted_dek)
    resolved_ring: dict[str, bytes] = {}
    if key_ring is not None:
        for k, v in key_ring.items():
            resolved_ring[k] = v.encode("ascii") if isinstance(v, str) else v
    else:
        resolved_ring = load_master_key_ring_from_env()

    if not resolved_ring:
        raise ValueError("MASTER_ENCRYPTION_KEY is not set")

    master_key = resolved_ring.get(key_id)
    if master_key is None:
        raise KeyRotationError(
            f"No master encryption key configured for key_id={key_id}",
            reason_code="UNKNOWN_KEY_ID",
        )
    return Fernet(master_key).decrypt(raw_token)


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


def _verify_readable_evidence_ciphertext(
    storage_path: str | None,
    dek: bytes,
) -> tuple[str, int]:
    """Verify on-disk ciphertext exists and decrypts cleanly without retaining plaintext."""
    if not storage_path:
        raise KeyRotationVerificationError(
            "Evidence blob metadata is missing storage_path.",
            reason_code="MISSING_STORAGE_PATH",
        )
    blob_path = Path(storage_path)
    if not blob_path.exists() or not blob_path.is_file() or blob_path.is_symlink():
        raise KeyRotationVerificationError(
            "Evidence ciphertext file is missing or invalid on disk.",
            reason_code="MISSING_CIPHERTEXT_FILE",
        )
    try:
        ciphertext_bytes = blob_path.read_bytes()
    except OSError as exc:
        raise KeyRotationVerificationError(
            "Unable to read evidence ciphertext file for rotation check.",
            reason_code="UNREADABLE_CIPHERTEXT_FILE",
        ) from exc

    ciphertext_sha256 = hashlib.sha256(ciphertext_bytes).hexdigest()
    try:
        plaintext_probe = Fernet(dek).decrypt(ciphertext_bytes)
        plaintext_len = len(plaintext_probe)
        del plaintext_probe
    except InvalidToken as exc:
        raise KeyRotationVerificationError(
            "Evidence ciphertext failed integrity verification prior to key rotation.",
            reason_code="CORRUPT_EVIDENCE_CIPHERTEXT",
        ) from exc

    return ciphertext_sha256, plaintext_len


def stage_key_rotation(
    *,
    source_keys: Mapping[str, bytes | str],
    target_key_id: str,
    target_master_key: bytes | str,
    batch_limit: int = 100,
    journal_dir: Path | str | None = None,
    rotation_id: str | None = None,
) -> dict[str, Any]:
    """Stage DEK rewrapping, verify readable ciphertext on disk, and write rollback evidence.

    Performs zero database mutations during staging. Every candidate DEK is
    unwrapped, rewrapped with `target_key_id`, re-unwrapped under
    `target_master_key`, and verified against the physical encrypted evidence
    file before any rollback journal is marked ready for commit.
    """
    validated_target_id = validate_key_id(target_key_id, allow_legacy=False)
    if batch_limit < 1:
        raise ValueError("batch_limit must be positive.")

    target_key_bytes = (
        target_master_key.encode("ascii")
        if isinstance(target_master_key, str)
        else target_master_key
    )
    # Validate target Fernet master key upfront.
    Fernet(target_key_bytes)

    normalized_sources: dict[str, bytes] = {}
    for k, v in source_keys.items():
        validated_src = validate_key_id(k, allow_legacy=True)
        normalized_sources[validated_src] = v.encode("ascii") if isinstance(v, str) else v
    normalized_sources.setdefault(validated_target_id, target_key_bytes)

    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select content_hash, encrypted_dek, storage_path
                from blobs
                order by content_hash asc
                limit %s
                """,
                (batch_limit,),
            )
            rows = cursor.fetchall() or []

    staged_entries: list[dict[str, Any]] = []
    skipped_already_current = 0
    path_lookup: dict[str, str] = {}

    for row in rows:
        if isinstance(row, dict):
            content_hash = str(row["content_hash"])
            current_wrapped = str(row["encrypted_dek"])
            storage_path = row.get("storage_path")
        else:
            content_hash = str(row[0])
            current_wrapped = str(row[1])
            storage_path = row[2]

        previous_key_id, _ = parse_wrapped_dek(current_wrapped)
        if previous_key_id == validated_target_id:
            skipped_already_current += 1
            continue

        try:
            dek = decrypt_dek(current_wrapped, key_ring=normalized_sources)
        except InvalidToken as exc:
            raise KeyRotationVerificationError(
                "Stored DEK failed decryption under provided source keys.",
                reason_code="DEK_UNWRAP_FAILED",
            ) from exc

        staged_wrapped_bytes = wrap_dek_with_key_id(
            dek,
            target_key_bytes,
            validated_target_id,
        )
        # Re-unwrap under target key and verify on-disk ciphertext readability!
        re_unwrapped_dek = decrypt_dek(
            staged_wrapped_bytes,
            key_ring={validated_target_id: target_key_bytes},
        )
        ciphertext_sha256, _ = _verify_readable_evidence_ciphertext(
            storage_path,
            re_unwrapped_dek,
        )
        del dek
        del re_unwrapped_dek

        path_lookup[content_hash] = str(storage_path)
        staged_entries.append(
            {
                "content_hash": content_hash,
                "previous_key_id": previous_key_id,
                "target_key_id": validated_target_id,
                "previous_encrypted_dek": current_wrapped,
                "staged_encrypted_dek": staged_wrapped_bytes.decode("ascii"),
                "ciphertext_sha256": ciphertext_sha256,
            }
        )

    effective_rotation_id = rotation_id or uuid.uuid4().hex[:16]
    journal: dict[str, Any] = {
        "schema": KEY_ROTATION_JOURNAL_SCHEMA,
        "rotation_id": effective_rotation_id,
        "status": "staged_verified",
        "target_key_id": validated_target_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "skipped_already_rotated": skipped_already_current,
        "entries": staged_entries,
    }
    journal_path = write_key_rotation_journal(journal, journal_dir=journal_dir)
    return {
        "rotation_id": effective_rotation_id,
        "status": "staged_verified",
        "target_key_id": validated_target_id,
        "staged_count": len(staged_entries),
        "skipped_already_rotated": skipped_already_current,
        "journal_path": journal_path,
        "journal": journal,
        "_verified_paths": path_lookup,
    }


def commit_staged_key_rotation(
    staged_bundle: dict[str, Any] | Path | str,
    *,
    journal_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Atomically commit verified DEK updates after re-checking on-disk ciphertext digests."""
    if isinstance(staged_bundle, (str, Path)):
        journal_path = Path(staged_bundle)
        journal = read_key_rotation_journal(journal_path)
    else:
        journal = dict(staged_bundle["journal"])
        journal_path = Path(staged_bundle["journal_path"])

    if journal.get("status") != "staged_verified":
        raise KeyRotationError(
            "Only `staged_verified` rotation journals can be committed.",
            reason_code="INVALID_JOURNAL_STATE",
        )

    entries: list[dict[str, Any]] = list(journal["entries"])
    if not entries:
        journal["status"] = "committed"
        journal["committed_at"] = datetime.now(timezone.utc).isoformat()
        write_key_rotation_journal(journal, journal_dir=journal_path.parent if journal_dir is None else journal_dir)
        return {
            "rotation_id": journal["rotation_id"],
            "status": "committed",
            "updated_count": 0,
        }

    with db.get_connection() as conn:
        try:
            with conn.cursor() as cursor:
                for entry in entries:
                    content_hash = entry["content_hash"]
                    expected_prev_dek = entry["previous_encrypted_dek"]
                    staged_dek = entry["staged_encrypted_dek"]
                    expected_sha = entry["ciphertext_sha256"]

                    cursor.execute(
                        "select encrypted_dek, storage_path from blobs where content_hash = %s",
                        (content_hash,),
                    )
                    live_row = cursor.fetchone()
                    if not live_row:
                        raise KeyRotationVerificationError(
                            "Target blob metadata row disappeared before rotation commit.",
                            reason_code="BLOB_ROW_MISSING_AT_COMMIT",
                        )
                    live_dek = live_row["encrypted_dek"] if isinstance(live_row, dict) else live_row[0]
                    live_path = live_row["storage_path"] if isinstance(live_row, dict) else live_row[1]
                    if live_dek != expected_prev_dek:
                        raise KeyRotationError(
                            "Concurrent DEK modification detected before rotation commit.",
                            reason_code="CONCURRENT_DEK_MODIFICATION",
                        )

                    blob_file = Path(str(live_path))
                    if not blob_file.exists() or not blob_file.is_file():
                        raise KeyRotationVerificationError(
                            "Ciphertext disappeared on disk before rotation commit.",
                            reason_code="MISSING_CIPHERTEXT_AT_COMMIT",
                        )
                    live_sha = hashlib.sha256(blob_file.read_bytes()).hexdigest()
                    if live_sha != expected_sha:
                        raise KeyRotationVerificationError(
                            "Ciphertext digest changed between staging and commit.",
                            reason_code="CIPHERTEXT_DIGEST_DRIFT",
                        )

                    cursor.execute(
                        """
                        update blobs
                        set encrypted_dek = %s
                        where content_hash = %s and encrypted_dek = %s
                        """,
                        (staged_dek, content_hash, expected_prev_dek),
                    )
                    rowcount = getattr(cursor, "rowcount", None)
                    if isinstance(rowcount, int) and rowcount == 0:
                        raise KeyRotationError(
                            "Conditional DEK metadata update matched zero rows.",
                            reason_code="CONCURRENT_DEK_MODIFICATION",
                        )
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise

    journal["status"] = "committed"
    journal["committed_at"] = datetime.now(timezone.utc).isoformat()
    write_key_rotation_journal(
        journal,
        journal_dir=journal_path.parent if journal_dir is None else journal_dir,
    )
    return {
        "rotation_id": journal["rotation_id"],
        "status": "committed",
        "target_key_id": journal["target_key_id"],
        "updated_count": len(entries),
    }


def rollback_key_rotation(
    journal_or_path: dict[str, Any] | Path | str,
    *,
    source_keys: Mapping[str, bytes | str] | None = None,
    journal_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Restore previous wrapped DEKs from preserved rollback evidence."""
    if isinstance(journal_or_path, (str, Path)):
        journal_path = Path(journal_or_path)
        journal = read_key_rotation_journal(journal_path)
    else:
        journal = dict(journal_or_path.get("journal", journal_or_path))
        raw_path = journal_or_path.get("journal_path")
        journal_path = Path(raw_path) if raw_path else None

    entries: list[dict[str, Any]] = list(journal["entries"])
    restored = 0

    with db.get_connection() as conn:
        try:
            with conn.cursor() as cursor:
                for entry in entries:
                    content_hash = entry["content_hash"]
                    previous_dek = entry["previous_encrypted_dek"]
                    staged_dek = entry["staged_encrypted_dek"]

                    cursor.execute(
                        "select encrypted_dek, storage_path from blobs where content_hash = %s",
                        (content_hash,),
                    )
                    row = cursor.fetchone()
                    if not row:
                        continue
                    live_dek = row["encrypted_dek"] if isinstance(row, dict) else row[0]
                    live_path = row["storage_path"] if isinstance(row, dict) else row[1]

                    if source_keys is not None:
                        unwrapped = decrypt_dek(previous_dek, key_ring=source_keys)
                        _verify_readable_evidence_ciphertext(live_path, unwrapped)
                        del unwrapped

                    if live_dek == staged_dek:
                        cursor.execute(
                            """
                            update blobs
                            set encrypted_dek = %s
                            where content_hash = %s and encrypted_dek = %s
                            """,
                            (previous_dek, content_hash, staged_dek),
                        )
                        restored += 1
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise

    journal["status"] = "rolled_back"
    journal["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
    if journal_path is not None:
        write_key_rotation_journal(
            journal,
            journal_dir=journal_path.parent if journal_dir is None else journal_dir,
        )
    return {
        "rotation_id": journal["rotation_id"],
        "status": "rolled_back",
        "restored_count": restored,
    }


def rotate_evidence_keys(
    *,
    source_keys: Mapping[str, bytes | str],
    target_key_id: str,
    target_master_key: bytes | str,
    batch_limit: int = 100,
    journal_dir: Path | str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run staged key rotation end-to-end (or stage-only when `dry_run=True`)."""
    staged = stage_key_rotation(
        source_keys=source_keys,
        target_key_id=target_key_id,
        target_master_key=target_master_key,
        batch_limit=batch_limit,
        journal_dir=journal_dir,
    )
    if dry_run:
        return {
            "rotation_id": staged["rotation_id"],
            "status": "staged_verified",
            "dry_run": True,
            "target_key_id": staged["target_key_id"],
            "staged_count": staged["staged_count"],
            "skipped_already_rotated": staged["skipped_already_rotated"],
            "journal_path": str(staged["journal_path"]),
        }

    committed = commit_staged_key_rotation(staged, journal_dir=journal_dir)
    return {
        "rotation_id": committed["rotation_id"],
        "status": "committed",
        "dry_run": False,
        "target_key_id": committed["target_key_id"],
        "updated_count": committed["updated_count"],
        "skipped_already_rotated": staged["skipped_already_rotated"],
        "journal_path": str(staged["journal_path"]),
    }
