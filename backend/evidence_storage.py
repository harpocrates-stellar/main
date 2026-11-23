from __future__ import annotations

from collections import OrderedDict
import hashlib
import hmac
import logging
import os
from pathlib import Path
import threading
from typing import Any, Tuple

from cryptography.fernet import Fernet, InvalidToken
import db
from storage import (
    EVIDENCE_CORRUPTED,
    STORAGE_IO_UNAVAILABLE,
    STORAGE_QUOTA_EXHAUSTED,
    EvidenceCorruptionError,
    EvidenceStorageOperationalError,
    StorageIOUnavailableError,
    StorageQuotaExhaustedError,
    atomic_write_blob_bytes,
    classify_storage_exception,
    get_storage_dir,
    is_quota_or_capacity_error,
)

This module provides a single public function,
:func:`assert_safe_destination`, which must be called before any write
into the evidence storage directory.  It resolves the candidate path to
its real filesystem location and rejects it when it aliases a protected
file or directory (the metadata database, encryption-key material, the
application source tree, or any other caller-supplied protected path).

Design
------
* All comparisons are made on *resolved* (``Path.resolve()``) paths so
  that symbolic links, ``..`` components, and platform case-folding
  cannot be used to bypass the check.
* A destination is considered to alias a protected path when:
  - it is exactly equal to the protected path, or
  - it is a descendant of the protected path (i.e. it falls inside a
    protected directory), or
  - it is an ancestor of the protected path (i.e. it *is* a protected
    directory or one of its parents — writing here would replace the
    directory entry that guards the protected file).

Raises
------
ValueError
    Raised (not a custom exception) so that the existing
    ``@app.errorhandler(ValueError)`` in ``app.py`` converts it to a
    400 response without additional wiring.
"""

from __future__ import annotations

from pathlib import Path

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


def assert_safe_destination(
    destination: Path,
    protected_paths: frozenset[Path],
) -> None:
    """Raise :class:`ValueError` when *destination* aliases a protected path.

    Parameters
    ----------
    destination:
        The fully-resolved output path that is about to be written.
        The caller must pass the result of ``Path(...).resolve()`` — a
        relative or unresolved path will be resolved here as a defensive
        measure, but the expectation is that the caller has already done
        this.
    protected_paths:
        A frozen set of *resolved* :class:`~pathlib.Path` objects that
        must never be overwritten or shadowed.  Obtain this set from
        :func:`storage._collect_protected_paths` or construct it
        directly in tests.

    Raises
    ------
    ValueError
        When *destination* is equal to, a descendant of, or an ancestor
        of any path in *protected_paths*.

    Examples
    --------
    >>> from pathlib import Path
    >>> from evidence_storage import assert_safe_destination
    >>> safe = Path("/var/evidence/abc123.bin").resolve()
    >>> protected = frozenset({Path("/etc/app/keys.pem").resolve()})
    >>> assert_safe_destination(safe, protected)  # no exception
    >>> assert_safe_destination(Path("/etc/app/keys.pem"), protected)
    Traceback (most recent call last):
        ...
    ValueError: destination '/etc/app/keys.pem' aliases protected path '/etc/app/keys.pem'
    """
    resolved = destination.resolve()

    for protected in protected_paths:
        reason = _alias_reason(resolved, protected)
        if reason is not None:
            raise ValueError(
                f"destination '{resolved}' aliases protected path "
                f"'{protected}': {reason}"
            )


def get_blob_info(content_hash: str) -> dict | None:
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select encrypted_dek, storage_path from blobs where content_hash = %s", (content_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None


_QUARANTINE_LOCK = threading.Lock()
_QUARANTINE_MAX = 4096
_CORRUPTED_BLOB_REFS: OrderedDict[str, str] = OrderedDict()


def _blob_quarantine_key(content_hash: str) -> str:
    return hashlib.sha256(
        f"harpocrates:corrupt-blob-ref:v1:{content_hash.strip()}".encode("utf-8")
    ).hexdigest()


def quarantine_corrupted_blob(
    content_hash: str,
    *,
    error: EvidenceStorageOperationalError,
) -> bool:
    """Mark a blob quarantined ONLY on genuine cryptographic/digest corruption.

    Refuses to quarantine blobs on quota exhaustion or transient I/O errors.
    """
    if not isinstance(error, EvidenceStorageOperationalError) or not error.quarantine_eligible:
        raise ValueError(
            "only EVIDENCE_CORRUPTED errors are eligible for evidence quarantine"
        )
    key = _blob_quarantine_key(content_hash)
    with _QUARANTINE_LOCK:
        _CORRUPTED_BLOB_REFS[key] = error.reason_code
        _CORRUPTED_BLOB_REFS.move_to_end(key)
        while len(_CORRUPTED_BLOB_REFS) > _QUARANTINE_MAX:
            _CORRUPTED_BLOB_REFS.popitem(last=False)
    return True


def is_blob_quarantined(content_hash: str) -> bool:
    key = _blob_quarantine_key(content_hash)
    with _QUARANTINE_LOCK:
        return key in _CORRUPTED_BLOB_REFS


def reset_corrupted_quarantine() -> None:
    with _QUARANTINE_LOCK:
        _CORRUPTED_BLOB_REFS.clear()


def store_encrypted_blob(
    plaintext: bytes,
    *,
    storage_dir: Path | str | None = None,
    quota_bytes: int | None = None,
    min_free_bytes: int | None = None,
    record_in_db: bool = True,
    raise_on_error: bool = False,
) -> dict[str, Any]:
    """Encrypt and atomically store evidence, reporting quota exhaustion distinctly."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    raw_bytes = bytes(plaintext)
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    target_dir = Path(storage_dir) if storage_dir is not None else get_storage_dir()
    blob_path = target_dir / f"{content_hash}.enc"

    dek, encrypted_dek = generate_dek()
    ciphertext = get_encryptor(dek).encrypt(raw_bytes)

    try:
        written = atomic_write_blob_bytes(
            blob_path,
            ciphertext,
            quota_bytes=quota_bytes,
            min_free_bytes=min_free_bytes,
        )
    except BaseException as exc:
        classified = classify_storage_exception(exc)
        logger.warning(
            "evidence_blob_write_failed reason_code=%s retryable=%s",
            classified.reason_code,
            classified.retryable,
        )
        if raise_on_error:
            raise classified from exc
        return classified.to_dict()

    if record_in_db:
        record_blob(content_hash, encrypted_dek, written, str(blob_path))

    return {
        "ok": True,
        "reasonCode": "OK",
        "retryable": False,
        "quarantined": False,
        "contentHash": content_hash,
        "ciphertextBytes": written,
    }


def verify_or_stage_encrypted_blob(
    content_hash: str,
    *,
    expected_plaintext_hash: str | None = None,
    stage_path: Path | str | None = None,
    quota_bytes: int | None = None,
    min_free_bytes: int | None = None,
    quarantine_on_corruption: bool = True,
    raise_on_error: bool = False,
) -> dict[str, Any]:
    """Authenticate and optionally stage an encrypted blob without conflating quota errors with corruption."""
    if is_blob_quarantined(content_hash):
        err = EvidenceCorruptionError("evidence is quarantined due to prior corruption")
        if raise_on_error:
            raise err
        out = err.to_dict()
        out["quarantined"] = True
        return out

    info = get_blob_info(content_hash)
    if info is None:
        return {
            "ok": False,
            "reasonCode": "BLOB_NOT_FOUND",
            "retryable": False,
            "quarantined": False,
        }

    storage_path = info.get("storage_path")
    encrypted_dek_raw = info.get("encrypted_dek")
    if not storage_path or not encrypted_dek_raw:
        corr = EvidenceCorruptionError("missing blob metadata fields")
        quarantined = (
            quarantine_corrupted_blob(content_hash, error=corr)
            if quarantine_on_corruption
            else False
        )
        if raise_on_error:
            raise corr
        out = corr.to_dict()
        out["quarantined"] = quarantined
        return out

    try:
        ciphertext = Path(storage_path).read_bytes()
    except OSError as exc:
        classified = classify_storage_exception(exc)
        if raise_on_error:
            raise classified from exc
        return classified.to_dict()

    encrypted_dek = (
        encrypted_dek_raw.encode("utf-8")
        if isinstance(encrypted_dek_raw, str)
        else bytes(encrypted_dek_raw)
    )
    try:
        dek = decrypt_dek(encrypted_dek)
        plaintext = get_encryptor(dek).decrypt(ciphertext)
    except InvalidToken as exc:
        corr = EvidenceCorruptionError("evidence ciphertext or wrapped DEK failed authentication")
        quarantined = (
            quarantine_corrupted_blob(content_hash, error=corr)
            if quarantine_on_corruption
            else False
        )
        logger.warning(
            "evidence_blob_corrupted reason_code=%s quarantined=%s",
            corr.reason_code,
            quarantined,
        )
        if raise_on_error:
            raise corr from exc
        out = corr.to_dict()
        out["quarantined"] = quarantined
        return out

    expected_digest = expected_plaintext_hash
    if expected_digest is None and len(content_hash) == 64 and all(
        c in "0123456789abcdefABCDEF" for c in content_hash
    ):
        expected_digest = content_hash.lower()

    if expected_digest is not None:
        observed_digest = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(observed_digest, expected_digest.lower()):
            corr = EvidenceCorruptionError("decrypted evidence digest mismatch")
            quarantined = (
                quarantine_corrupted_blob(content_hash, error=corr)
                if quarantine_on_corruption
                else False
            )
            if raise_on_error:
                raise corr
            out = corr.to_dict()
            out["quarantined"] = quarantined
            return out

    if stage_path is not None:
        try:
            atomic_write_blob_bytes(
                stage_path,
                plaintext,
                quota_bytes=quota_bytes,
                min_free_bytes=min_free_bytes,
            )
        except BaseException as exc:
            classified = classify_storage_exception(exc)
            # Capacity exhaustion during staging MUST NOT quarantine valid evidence!
            logger.warning(
                "evidence_blob_stage_failed reason_code=%s retryable=%s quarantined=False",
                classified.reason_code,
                classified.retryable,
            )
            if raise_on_error:
                raise classified from exc
            return classified.to_dict()

    return {
        "ok": True,
        "reasonCode": "OK",
        "retryable": False,
        "quarantined": False,
        "verifiedBytes": len(plaintext),
    }
