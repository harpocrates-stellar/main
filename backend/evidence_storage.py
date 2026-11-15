import base64
import binascii
from dataclasses import dataclass
import hashlib
import logging
import os
import re
from typing import Callable, Tuple
from cryptography.fernet import Fernet, InvalidToken
import db

logger = logging.getLogger("harpocrates.evidence_storage")

CURRENT_ENVELOPE_VERSION = "hpx-fernet-v1"
LEGACY_ENVELOPE_VERSION = "legacy-fernet-v0"
SUPPORTED_ENVELOPE_VERSIONS = frozenset(
    {
        CURRENT_ENVELOPE_VERSION,
        LEGACY_ENVELOPE_VERSION,
    }
)
ENVELOPE_PREFIX_SEPARATOR = ":"

_FERNET_VERSION_BYTE = 0x80
_FERNET_HEADER_AND_MAC_BYTES = 1 + 8 + 16 + 32  # version + timestamp + IV + HMAC-SHA256
_FERNET_AES_BLOCK_BYTES = 16
_FERNET_MIN_DECODED_BYTES = _FERNET_HEADER_AND_MAC_BYTES + _FERNET_AES_BLOCK_BYTES
_BASE64URL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_VERSION_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class EnvelopeFormatError(InvalidToken):
    """Base error raised when an encryption envelope fails structural validation."""

    reason_code = "INVALID_ENVELOPE"

    def __init__(self, message: str, *, reason_code: str | None = None) -> None:
        super().__init__(message)
        if reason_code is not None:
            self.reason_code = reason_code


class UnsupportedEnvelopeError(EnvelopeFormatError):
    """Raised when an envelope declares an unknown or mismatched version."""

    reason_code = "UNSUPPORTED_ENVELOPE_VERSION"


class MalformedEnvelopeError(EnvelopeFormatError):
    """Raised when ciphertext or envelope framing is structurally malformed."""

    reason_code = "MALFORMED_ENVELOPE"


@dataclass(frozen=True)
class ParsedEnvelope:
    """Validated encryption envelope metadata and canonical cipher token."""

    envelope_version: str
    ciphertext_token: bytes
    is_legacy: bool


def _validate_fernet_token_framing(token_text: str) -> bytes:
    """Validate Fernet base64url framing and header/block invariants without decrypting."""
    if not token_text or not _BASE64URL_TOKEN_RE.fullmatch(token_text):
        raise MalformedEnvelopeError("Malformed encryption envelope token characters.")

    stripped = token_text.rstrip("=")
    pad_len = len(token_text) - len(stripped)
    if len(stripped) % 4 == 1:
        raise MalformedEnvelopeError("Malformed encryption envelope base64 length.")
    expected_pad = (-len(stripped)) % 4
    if pad_len not in (0, expected_pad):
        raise MalformedEnvelopeError("Malformed encryption envelope base64 padding.")

    padded = stripped + ("=" * expected_pad)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise MalformedEnvelopeError("Malformed encryption envelope base64 payload.") from exc

    # Reject non-canonical trailing base64 bits.
    if base64.urlsafe_b64encode(raw).decode("ascii") != padded:
        raise MalformedEnvelopeError("Non-canonical base64 bits in encryption envelope.")

    if len(raw) < _FERNET_MIN_DECODED_BYTES:
        raise MalformedEnvelopeError("Encryption envelope payload is shorter than minimum frame size.")

    ciphertext_len = len(raw) - _FERNET_HEADER_AND_MAC_BYTES
    if ciphertext_len % _FERNET_AES_BLOCK_BYTES != 0:
        raise MalformedEnvelopeError("Encryption envelope ciphertext is not block-aligned.")

    if raw[0] != _FERNET_VERSION_BYTE:
        raise MalformedEnvelopeError("Encryption envelope carries an invalid Fernet frame marker.")

    return padded.encode("ascii")


def inspect_envelope(
    payload: bytes | str,
    *,
    expected_version: str | None = None,
) -> ParsedEnvelope:
    """Inspect and validate an encrypted DEK or blob envelope without guessing algorithms."""
    if expected_version is not None:
        if not isinstance(expected_version, str) or not _VERSION_TAG_RE.fullmatch(expected_version):
            raise UnsupportedEnvelopeError("Unsupported encryption envelope version.")
        if expected_version not in SUPPORTED_ENVELOPE_VERSIONS:
            raise UnsupportedEnvelopeError(
                f"Unsupported encryption envelope version: {expected_version}"
            )

    if isinstance(payload, bytes):
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError as exc:
            raise MalformedEnvelopeError(
                "Encryption envelope must be ASCII-encoded."
            ) from exc
    elif isinstance(payload, str):
        try:
            payload.encode("ascii")
        except UnicodeEncodeError as exc:
            raise MalformedEnvelopeError(
                "Encryption envelope must be ASCII-encoded."
            ) from exc
        text = payload
    else:
        raise MalformedEnvelopeError("Encryption envelope must be bytes or str.")

    if not text or any(ch.isspace() for ch in text):
        raise MalformedEnvelopeError("Encryption envelope must be non-empty without whitespace.")

    if ENVELOPE_PREFIX_SEPARATOR in text:
        prefix, _, remainder = text.partition(ENVELOPE_PREFIX_SEPARATOR)
        if not prefix or not _VERSION_TAG_RE.fullmatch(prefix):
            raise MalformedEnvelopeError("Malformed encryption envelope header.")
        if prefix not in SUPPORTED_ENVELOPE_VERSIONS:
            raise UnsupportedEnvelopeError(
                f"Unsupported encryption envelope version: {prefix}"
            )
        if not remainder or ENVELOPE_PREFIX_SEPARATOR in remainder:
            raise MalformedEnvelopeError("Malformed encryption envelope body.")
        token_bytes = _validate_fernet_token_framing(remainder)
        version = prefix
    else:
        token_bytes = _validate_fernet_token_framing(text)
        version = LEGACY_ENVELOPE_VERSION

    if expected_version is not None and version != expected_version:
        raise UnsupportedEnvelopeError(
            "Encryption envelope version does not match recorded metadata.",
            reason_code="ENVELOPE_VERSION_MISMATCH",
        )

    return ParsedEnvelope(
        envelope_version=version,
        ciphertext_token=token_bytes,
        is_legacy=(version == LEGACY_ENVELOPE_VERSION),
    )


def format_versioned_envelope(
    fernet_token: bytes | str,
    envelope_version: str = CURRENT_ENVELOPE_VERSION,
) -> bytes:
    """Wrap a validated Fernet token in an explicit versioned envelope prefix."""
    if not isinstance(envelope_version, str) or envelope_version not in SUPPORTED_ENVELOPE_VERSIONS:
        raise UnsupportedEnvelopeError(
            f"Unsupported encryption envelope version: {envelope_version}"
        )

    parsed = inspect_envelope(fernet_token)
    if not parsed.is_legacy and parsed.envelope_version != envelope_version:
        raise UnsupportedEnvelopeError(
            "Cannot retag envelope across incompatible explicit versions.",
            reason_code="ENVELOPE_VERSION_MISMATCH",
        )
    return f"{envelope_version}{ENVELOPE_PREFIX_SEPARATOR}".encode("ascii") + parsed.ciphertext_token


def generate_dek(*, versioned: bool = False) -> Tuple[bytes, bytes]:
    """Generates a Data Encryption Key (DEK) and its encrypted form (using a Master Key)."""
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        master_key_b64 = Fernet.generate_key().decode()
    f = Fernet(master_key_b64.encode())

    dek = Fernet.generate_key()
    encrypted_dek = f.encrypt(dek)
    if versioned:
        encrypted_dek = format_versioned_envelope(encrypted_dek, CURRENT_ENVELOPE_VERSION)

    return dek, encrypted_dek


def generate_versioned_dek(
    envelope_version: str = CURRENT_ENVELOPE_VERSION,
) -> Tuple[bytes, bytes, str]:
    """Generate a DEK and return `(dek, versioned_encrypted_dek, envelope_version)`."""
    if envelope_version != CURRENT_ENVELOPE_VERSION:
        raise UnsupportedEnvelopeError(
            f"New evidence envelopes cannot be created with version: {envelope_version}"
        )
    dek, raw_encrypted_dek = generate_dek(versioned=False)
    wrapped = format_versioned_envelope(raw_encrypted_dek, envelope_version)
    return dek, wrapped, envelope_version


def decrypt_dek(
    encrypted_dek: bytes | str,
    *,
    expected_version: str | None = None,
    cipher_factory: Callable[[bytes], Fernet] = Fernet,
) -> bytes:
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        raise ValueError("MASTER_ENCRYPTION_KEY is not set")
    parsed = inspect_envelope(encrypted_dek, expected_version=expected_version)
    f = cipher_factory(master_key_b64.encode())
    return f.decrypt(parsed.ciphertext_token)


def get_encryptor(dek: bytes):
    return Fernet(dek)


def encrypt_evidence_payload(
    plaintext: bytes,
    dek: bytes,
    *,
    envelope_version: str = CURRENT_ENVELOPE_VERSION,
) -> bytes:
    """Encrypt evidence bytes with `dek` and attach an explicit envelope version."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if envelope_version != CURRENT_ENVELOPE_VERSION:
        raise UnsupportedEnvelopeError(
            f"New evidence payloads cannot use envelope version: {envelope_version}"
        )
    token = get_encryptor(dek).encrypt(plaintext)
    return format_versioned_envelope(token, envelope_version)


def decrypt_evidence_payload(
    payload: bytes | str,
    dek: bytes,
    *,
    expected_version: str | None = None,
    cipher_factory: Callable[[bytes], Fernet] = Fernet,
) -> bytes:
    """Validate envelope version/framing before decrypting evidence bytes with `dek`."""
    parsed = inspect_envelope(payload, expected_version=expected_version)
    cipher = cipher_factory(dek)
    return cipher.decrypt(parsed.ciphertext_token)


def record_blob(
    content_hash: str,
    encrypted_dek: bytes,
    size_bytes: int,
    storage_path: str,
    *,
    envelope_version: str | None = None,
):
    stored_dek = encrypted_dek
    if envelope_version is not None:
        stored_dek = format_versioned_envelope(encrypted_dek, envelope_version)

    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                insert into blobs (content_hash, encrypted_dek, size_bytes, storage_path)
                values (%s, %s, %s, %s)
                on conflict (content_hash) do nothing
                """,
                (content_hash, stored_dek.decode(), size_bytes, storage_path)
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


def get_blob_info(
    content_hash: str,
    *,
    include_envelope_version: bool = False,
) -> dict | None:
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select encrypted_dek, storage_path from blobs where content_hash = %s", (content_hash,))
            row = cursor.fetchone()
            if not row:
                return None
            info = (
                dict(row)
                if isinstance(row, dict)
                else {"encrypted_dek": row[0], "storage_path": row[1]}
            )
            if include_envelope_version:
                parsed = inspect_envelope(info["encrypted_dek"])
                info["envelope_version"] = parsed.envelope_version
                info["is_legacy_envelope"] = parsed.is_legacy
            return info


def get_blob_metadata(content_hash: str) -> dict | None:
    """Return blob metadata with validated encryption envelope version details."""
    return get_blob_info(content_hash, include_envelope_version=True)
