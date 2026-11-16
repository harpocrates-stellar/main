"""Bounded-chunk streaming upload helpers with concurrent SHA-256 hashing.

Trust boundary
--------------
Upload bytes cross the public HTTP boundary into temporary disk under a
hard size limit.  Hashing happens while bytes are copied so callers never
need a second full-file read.  Failure messages are stable and never echo
payload bytes, filenames beyond what Flask already accepted, or secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, Optional, Tuple, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from flask import g
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge

# ---------------------------------------------------------------------------
# Bounded chunk sizing
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_BYTES = 65_536  # 64 KiB
MIN_CHUNK_BYTES = 4_096  # 4 KiB
MAX_CHUNK_BYTES = 1_048_576  # 1 MiB
MAX_SESSION_CHUNKS = 1_024
ENCRYPTED_CHUNK_MAGIC = b"HPX1"
ENCRYPTED_NONCE_BYTES = 16
ENCRYPTED_MAC_BYTES = 32
SESSION_PROGRESS_FILENAME = "session-progress.json"
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class UploadOwnershipError(Exception):
    """Raised when a caller attempts to access an upload session owned by another principal."""


class UploadContentHashMismatchError(Exception):
    """Raised when assembled upload content or encrypted chunk integrity fails verification."""


def normalize_sha256_hex(raw: object) -> Optional[str]:
    """Validate and lowercase an optional 64-character SHA-256 hex digest."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError("expectedSha256 must be a 64-character hex SHA-256 digest")
    cleaned = raw.strip().lower()
    if not cleaned:
        return None
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not _SHA256_HEX_RE.fullmatch(cleaned):
        raise ValueError("expectedSha256 must be a 64-character hex SHA-256 digest")
    return cleaned


class ResumableEncryptedSessionStore:
    """Manages explicit session ownership, encrypted chunk persistence, and bounded resume state."""

    def __init__(self, *, max_chunks: int = MAX_SESSION_CHUNKS) -> None:
        self.max_chunks = max(1, int(max_chunks))
        self._lock = threading.Lock()
        # Maps session_id -> zeroizable 64-byte bytearray (32B AES-256 key + 32B HMAC key)
        self._keys: Dict[str, bytearray] = {}

    def _progress_path(self, session_dir: Union[str, Path]) -> Path:
        return Path(session_dir) / SESSION_PROGRESS_FILENAME

    def _get_or_create_key_unlocked(self, session_id: str) -> Tuple[bytes, bytes]:
        key_buf = self._keys.get(session_id)
        if key_buf is None:
            key_buf = bytearray(os.urandom(64))
            self._keys[session_id] = key_buf
        raw = bytes(key_buf)
        return raw[:32], raw[32:]

    def _get_existing_key(self, session_id: str) -> Tuple[bytes, bytes]:
        with self._lock:
            key_buf = self._keys.get(session_id)
            if key_buf is None:
                raise UploadContentHashMismatchError(
                    "encrypted upload session key is unavailable"
                )
            raw = bytes(key_buf)
            return raw[:32], raw[32:]

    def _zeroize_key_unlocked(self, session_id: str) -> None:
        key_buf = self._keys.pop(session_id, None)
        if key_buf is not None:
            for idx in range(len(key_buf)):
                key_buf[idx] = 0

    @staticmethod
    def _check_owner(record_owner: Optional[str], caller_owner: Optional[str]) -> None:
        if record_owner is None:
            if caller_owner is not None:
                raise UploadOwnershipError("caller is not authorized for this upload session")
            return
        if caller_owner is None:
            raise UploadOwnershipError("caller is not authorized for this upload session")
        if not hmac.compare_digest(
            record_owner.encode("utf-8"),
            caller_owner.encode("utf-8"),
        ):
            raise UploadOwnershipError("caller is not authorized for this upload session")

    def _write_manifest_unlocked(
        self,
        session_dir: Union[str, Path],
        manifest: Dict[str, Any],
    ) -> None:
        target = self._progress_path(session_dir)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(manifest, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp, target)

    def _read_manifest_unlocked(
        self,
        session_id: str,
        session_dir: Union[str, Path],
    ) -> Optional[Dict[str, Any]]:
        target = self._progress_path(session_dir)
        if not target.exists():
            return None
        data = json.loads(target.read_text(encoding="utf-8"))
        if data.get("sessionId") != session_id:
            raise UploadOwnershipError("upload session identity mismatch")
        return data

    def create_session(
        self,
        session_id: str,
        session_dir: Union[str, Path],
        *,
        owner: Optional[str],
        expected_sha256: Optional[str] = None,
    ) -> Dict[str, Any]:
        normalized_expected = normalize_sha256_hex(expected_sha256)
        path = Path(session_dir)
        path.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self._get_or_create_key_unlocked(session_id)
            manifest: Dict[str, Any] = {
                "sessionId": session_id,
                "owner": owner,
                "encrypted": True,
                "maxChunks": self.max_chunks,
                "expectedSha256": normalized_expected,
                "chunks": {},
            }
            self._write_manifest_unlocked(path, manifest)
            return self._public_progress_unlocked(manifest)

    def get_progress(
        self,
        session_id: str,
        session_dir: Union[str, Path],
        *,
        caller_owner: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        path = Path(session_dir)
        if not path.exists():
            return None
        with self._lock:
            manifest = self._read_manifest_unlocked(session_id, path)
            if manifest is None:
                return None
            self._check_owner(manifest.get("owner"), caller_owner)
            return self._public_progress_unlocked(manifest)

    def write_encrypted_chunk(
        self,
        session_id: str,
        session_dir: Union[str, Path],
        *,
        caller_owner: Optional[str],
        chunk_index: int,
        source: BinaryIO,
        chunk_size: Optional[int] = None,
        max_size: Optional[int] = None,
    ) -> Dict[str, Any]:
        if chunk_index < 0:
            raise ValueError("chunk_index must be non-negative")
        path = Path(session_dir)
        with self._lock:
            manifest = self._read_manifest_unlocked(session_id, path)
            if manifest is None:
                # Legacy directory created outside store: initialize unowned manifest.
                manifest = {
                    "sessionId": session_id,
                    "owner": caller_owner,
                    "encrypted": True,
                    "maxChunks": self.max_chunks,
                    "expectedSha256": None,
                    "chunks": {},
                }
                self._write_manifest_unlocked(path, manifest)
            self._check_owner(manifest.get("owner"), caller_owner)
            max_allowed = int(manifest.get("maxChunks", self.max_chunks))
            if chunk_index >= max_allowed:
                raise ValueError(f"chunk_index exceeds maxChunks ({max_allowed})")
            chunks_map = manifest.get("chunks", {})
            if str(chunk_index) not in chunks_map and len(chunks_map) >= max_allowed:
                raise ValueError(f"upload session reached maxChunks ({max_allowed})")
            enc_key, mac_key = self._get_or_create_key_unlocked(session_id)

        bounded = resolve_chunk_bytes(chunk_size)
        limit = resolve_max_bytes(max_size)
        nonce = os.urandom(ENCRYPTED_NONCE_BYTES)
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        plain_hasher = hashlib.sha256()
        mac = hmac.new(mac_key, digestmod=hashlib.sha256)
        aad = f"{session_id}:{chunk_index}:".encode("utf-8")
        mac.update(ENCRYPTED_CHUNK_MAGIC)
        mac.update(nonce)
        mac.update(aad)

        enc_dest = path / f"chunk-{chunk_index}.enc"
        fd, tmp_name = tempfile.mkstemp(prefix=".enc-chunk-", dir=str(path))
        tmp_path: Optional[Path] = Path(tmp_name)
        bytes_written = 0

        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(ENCRYPTED_CHUNK_MAGIC)
                handle.write(nonce)
                while True:
                    plain = source.read(bounded)
                    if not plain:
                        break
                    if limit > 0 and bytes_written + len(plain) > limit:
                        raise RequestEntityTooLarge("Upload exceeds size limit")
                    plain_hasher.update(plain)
                    ciphertext = encryptor.update(plain)
                    mac.update(ciphertext)
                    handle.write(ciphertext)
                    bytes_written += len(plain)
                tail = encryptor.finalize()
                if tail:
                    mac.update(tail)
                    handle.write(tail)
                handle.write(mac.digest())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, enc_dest)
            tmp_path = None
        except Exception:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

        plain_sha256 = plain_hasher.hexdigest()
        with self._lock:
            manifest = self._read_manifest_unlocked(session_id, path)
            if manifest is None:
                raise FileNotFoundError("session not found")
            self._check_owner(manifest.get("owner"), caller_owner)
            manifest["chunks"][str(chunk_index)] = {
                "bytes": bytes_written,
                "sha256": plain_sha256,
            }
            self._write_manifest_unlocked(path, manifest)
            progress = self._public_progress_unlocked(manifest)

        return {
            "ok": True,
            "bytes": bytes_written,
            "sha256": plain_sha256,
            "chunkIndex": chunk_index,
            "encrypted": True,
            "receivedChunks": progress["receivedChunks"],
            "nextChunkIndex": progress["nextChunkIndex"],
        }

    def _decrypt_one_chunk(
        self,
        *,
        session_id: str,
        chunk_index: int,
        enc_path: Path,
        expected_chunk_sha256: str,
        expected_chunk_bytes: int,
        enc_key: bytes,
        mac_key: bytes,
        bounded: int,
        sink: Optional[BinaryIO],
        overall_hasher: "hashlib._Hash",
        current_total: int,
        limit: int,
    ) -> int:
        if not enc_path.exists():
            raise UploadContentHashMismatchError("encrypted upload chunk is missing")
        total_file_size = enc_path.stat().st_size
        header_len = len(ENCRYPTED_CHUNK_MAGIC) + ENCRYPTED_NONCE_BYTES
        min_len = header_len + ENCRYPTED_MAC_BYTES
        if total_file_size < min_len:
            raise UploadContentHashMismatchError("encrypted upload chunk is truncated")
        ciphertext_len = total_file_size - min_len

        aad = f"{session_id}:{chunk_index}:".encode("utf-8")
        # Pass 1: constant-time HMAC verification BEFORE trusting decrypted bytes.
        with enc_path.open("rb") as handle:
            magic = handle.read(len(ENCRYPTED_CHUNK_MAGIC))
            nonce = handle.read(ENCRYPTED_NONCE_BYTES)
            if magic != ENCRYPTED_CHUNK_MAGIC or len(nonce) != ENCRYPTED_NONCE_BYTES:
                raise UploadContentHashMismatchError("encrypted upload chunk header is invalid")
            mac = hmac.new(mac_key, digestmod=hashlib.sha256)
            mac.update(magic)
            mac.update(nonce)
            mac.update(aad)
            remaining = ciphertext_len
            while remaining > 0:
                piece = handle.read(min(bounded, remaining))
                if not piece:
                    raise UploadContentHashMismatchError("encrypted upload chunk read truncated")
                mac.update(piece)
                remaining -= len(piece)
            stored_tag = handle.read(ENCRYPTED_MAC_BYTES)
            if len(stored_tag) != ENCRYPTED_MAC_BYTES or not hmac.compare_digest(
                mac.digest(), stored_tag
            ):
                raise UploadContentHashMismatchError(
                    "encrypted upload chunk failed integrity check"
                )

        # Pass 2: bounded streaming decryption + SHA-256 verification.
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        chunk_hasher = hashlib.sha256()
        chunk_plain_bytes = 0
        with enc_path.open("rb") as handle:
            handle.seek(header_len)
            remaining = ciphertext_len
            while remaining > 0:
                piece = handle.read(min(bounded, remaining))
                if not piece:
                    break
                remaining -= len(piece)
                plain = decryptor.update(piece)
                next_total = current_total + chunk_plain_bytes + len(plain)
                if limit > 0 and next_total > limit:
                    raise RequestEntityTooLarge("Upload exceeds size limit")
                chunk_hasher.update(plain)
                overall_hasher.update(plain)
                if sink is not None:
                    sink.write(plain)
                chunk_plain_bytes += len(plain)
            tail = decryptor.finalize()
            if tail:
                chunk_hasher.update(tail)
                overall_hasher.update(tail)
                if sink is not None:
                    sink.write(tail)
                chunk_plain_bytes += len(tail)

        if (
            chunk_plain_bytes != expected_chunk_bytes
            or chunk_hasher.hexdigest() != expected_chunk_sha256
        ):
            raise UploadContentHashMismatchError("decrypted chunk digest mismatch")
        return current_total + chunk_plain_bytes

    def verify_assembled_sha256(
        self,
        session_id: str,
        session_dir: Union[str, Path],
        *,
        caller_owner: Optional[str],
        expected_sha256: Optional[str] = None,
        chunk_size: Optional[int] = None,
        max_size: Optional[int] = None,
    ) -> Tuple[str, int]:
        """Authenticate owner & stream-verify final SHA-256 without writing plaintext or acquiring capacity."""
        normalized_expected = normalize_sha256_hex(expected_sha256)
        path = Path(session_dir)
        with self._lock:
            manifest = self._read_manifest_unlocked(session_id, path)
            if manifest is None:
                raise FileNotFoundError("session not found")
            self._check_owner(manifest.get("owner"), caller_owner)
            bound_expected = manifest.get("expectedSha256")
            chunks_map = dict(manifest.get("chunks", {}))

        if bound_expected and normalized_expected and bound_expected != normalized_expected:
            raise UploadContentHashMismatchError(
                "commit expectedSha256 conflicts with session expectedSha256"
            )
        effective_expected = normalized_expected or bound_expected

        if not chunks_map:
            raise ValueError("session has no chunks")

        indices = sorted(int(idx) for idx in chunks_map)
        if indices != list(range(len(indices))):
            raise ValueError("upload session is missing contiguous chunks")

        enc_key, mac_key = self._get_existing_key(session_id)
        bounded = resolve_chunk_bytes(chunk_size)
        limit = resolve_max_bytes(max_size)
        overall_hasher = hashlib.sha256()
        total_bytes = 0

        for idx in indices:
            meta = chunks_map[str(idx)]
            total_bytes = self._decrypt_one_chunk(
                session_id=session_id,
                chunk_index=idx,
                enc_path=path / f"chunk-{idx}.enc",
                expected_chunk_sha256=str(meta["sha256"]),
                expected_chunk_bytes=int(meta["bytes"]),
                enc_key=enc_key,
                mac_key=mac_key,
                bounded=bounded,
                sink=None,
                overall_hasher=overall_hasher,
                current_total=total_bytes,
                limit=limit,
            )

        computed = overall_hasher.hexdigest()
        if effective_expected is not None and not hmac.compare_digest(
            computed, effective_expected
        ):
            raise UploadContentHashMismatchError(
                "assembled upload content hash does not match expectedSha256"
            )
        return computed, total_bytes

    def materialize_verified_plaintext(
        self,
        session_id: str,
        session_dir: Union[str, Path],
        destination: Union[str, Path],
        *,
        caller_owner: Optional[str],
        verified_sha256: str,
        chunk_size: Optional[int] = None,
        max_size: Optional[int] = None,
    ) -> Tuple[str, int]:
        """Stream-decrypt verified session chunks into *destination* after admission is granted."""
        path = Path(session_dir)
        dest = Path(destination)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            manifest = self._read_manifest_unlocked(session_id, path)
            if manifest is None:
                raise FileNotFoundError("session not found")
            self._check_owner(manifest.get("owner"), caller_owner)
            chunks_map = dict(manifest.get("chunks", {}))

        indices = sorted(int(idx) for idx in chunks_map)
        enc_key, mac_key = self._get_existing_key(session_id)
        bounded = resolve_chunk_bytes(chunk_size)
        limit = resolve_max_bytes(max_size)
        overall_hasher = hashlib.sha256()
        total_bytes = 0

        fd, tmp_name = tempfile.mkstemp(prefix="harpocrates-dec-", dir=str(dest.parent))
        tmp_path: Optional[Path] = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                for idx in indices:
                    meta = chunks_map[str(idx)]
                    total_bytes = self._decrypt_one_chunk(
                        session_id=session_id,
                        chunk_index=idx,
                        enc_path=path / f"chunk-{idx}.enc",
                        expected_chunk_sha256=str(meta["sha256"]),
                        expected_chunk_bytes=int(meta["bytes"]),
                        enc_key=enc_key,
                        mac_key=mac_key,
                        bounded=bounded,
                        sink=out,
                        overall_hasher=overall_hasher,
                        current_total=total_bytes,
                        limit=limit,
                    )
                out.flush()
                os.fsync(out.fileno())
            computed = overall_hasher.hexdigest()
            if not hmac.compare_digest(computed, verified_sha256):
                raise UploadContentHashMismatchError(
                    "assembled upload content hash changed during staging"
                )
            os.replace(tmp_path, dest)
            tmp_path = None
            return computed, total_bytes
        except Exception:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            dest.unlink(missing_ok=True)
            raise

    def destroy_session(self, session_id: str, session_dir: Union[str, Path]) -> None:
        with self._lock:
            self._zeroize_key_unlocked(session_id)
        shutil.rmtree(session_dir, ignore_errors=True)

    @staticmethod
    def _public_progress_unlocked(manifest: Dict[str, Any]) -> Dict[str, Any]:
        chunks_map = manifest.get("chunks", {})
        received = sorted(int(idx) for idx in chunks_map)
        next_index = 0
        for idx in received:
            if idx == next_index:
                next_index += 1
            else:
                break
        total_bytes = sum(int(entry["bytes"]) for entry in chunks_map.values())
        return {
            "ok": True,
            "sessionId": manifest["sessionId"],
            "owner": manifest.get("owner"),
            "encrypted": True,
            "maxChunks": int(manifest.get("maxChunks", MAX_SESSION_CHUNKS)),
            "receivedChunks": received,
            "chunkCount": len(received),
            "nextChunkIndex": next_index,
            "totalBytes": total_bytes,
            "expectedSha256": manifest.get("expectedSha256"),
        }


def clamp_chunk_bytes(value: int | None, *, enforce_min: bool = False) -> int:
    """Return a positive chunk size capped at ``MAX_CHUNK_BYTES``.

    When *enforce_min* is true (config/env path), values below ``MIN_CHUNK_BYTES``
    are raised to the minimum so operators cannot accidentally configure tiny
    reads. Explicit API callers may pass smaller sizes for tests.
    """
    if value is None:
        return DEFAULT_CHUNK_BYTES
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return DEFAULT_CHUNK_BYTES
    if parsed <= 0:
        return DEFAULT_CHUNK_BYTES
    if enforce_min and parsed < MIN_CHUNK_BYTES:
        return MIN_CHUNK_BYTES
    if parsed > MAX_CHUNK_BYTES:
        return MAX_CHUNK_BYTES
    return parsed


def _upload_config():
    try:
        return getattr(g, "upload_config", None)
    except RuntimeError:
        return None


def resolve_chunk_bytes(explicit: int | None = None) -> int:
    """Resolve chunk size from an explicit value, Flask ``g``, or the default."""
    if explicit is not None:
        return clamp_chunk_bytes(explicit, enforce_min=False)
    config = _upload_config()
    if config is not None:
        return clamp_chunk_bytes(
            getattr(config, "upload_chunk_bytes", None), enforce_min=True
        )
    return DEFAULT_CHUNK_BYTES


def resolve_max_bytes(explicit: int | None = None) -> int:
    """Resolve the hard upload size limit (0 = unlimited, not recommended)."""
    if explicit is not None:
        return max(0, int(explicit))
    config = _upload_config()
    if config is not None:
        for attr in ("upload_max_bytes", "max_video_bytes"):
            value = getattr(config, attr, None)
            if value is not None:
                return max(0, int(value))
    return 0


def resolve_temp_dir(explicit: str | Path | None = None) -> Optional[str]:
    if explicit is not None:
        return str(explicit)
    config = _upload_config()
    if config is not None:
        value = getattr(config, "upload_temp_dir", None)
        if value:
            return str(value)
    return None


def hash_stream_to_path(
    source: BinaryIO,
    destination: Union[str, Path],
    *,
    chunk_size: int | None = None,
    max_size: int | None = None,
    temp_dir: str | Path | None = None,
) -> Tuple[str, int]:
    """Copy *source* to *destination* in bounded chunks while hashing SHA-256.

    Returns ``(hex_digest, bytes_written)``.
    Raises ``RequestEntityTooLarge`` when *max_size* is exceeded mid-stream.
    Temporary files are cleaned up on failure; destination is not left partial
    unless an OS error occurs after the final rename.
    """
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256()
    bytes_written = 0
    tmp_path: Optional[Path] = None

    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix="harpocrates-stream-",
            dir=resolve_temp_dir(temp_dir),
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as tmp_file:
            while True:
                chunk = source.read(bounded)
                if not chunk:
                    break
                if limit > 0 and bytes_written + len(chunk) > limit:
                    raise RequestEntityTooLarge("Upload exceeds size limit")
                tmp_file.write(chunk)
                hasher.update(chunk)
                bytes_written += len(chunk)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        # Atomic-ish replace into the final destination.
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        return hasher.hexdigest(), bytes_written
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        if dest.exists():
            # Do not leave a partial final artifact after a size abort.
            try:
                dest.unlink()
            except OSError:
                pass
        raise


def hash_paths_concat(
    paths: Iterable[Union[str, Path]],
    destination: Union[str, Path],
    *,
    chunk_size: int | None = None,
    max_size: int | None = None,
) -> Tuple[str, int]:
    """Concatenate *paths* into *destination* with bounded-chunk SHA-256 hashing."""
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256()
    bytes_written = 0
    tmp_path: Optional[Path] = None

    try:
        fd, tmp_name = tempfile.mkstemp(prefix="harpocrates-concat-")
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as out:
            for path in paths:
                with Path(path).open("rb") as handle:
                    while True:
                        chunk = handle.read(bounded)
                        if not chunk:
                            break
                        if limit > 0 and bytes_written + len(chunk) > limit:
                            raise RequestEntityTooLarge("Upload exceeds size limit")
                        out.write(chunk)
                        hasher.update(chunk)
                        bytes_written += len(chunk)
            out.flush()
            os.fsync(out.fileno())
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        return hasher.hexdigest(), bytes_written
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        if dest.exists():
            try:
                dest.unlink()
            except OSError:
                pass
        raise


def sha256_path_bounded(
    path: Union[str, Path],
    *,
    chunk_size: int | None = None,
) -> str:
    """SHA-256 a file using bounded chunk reads (no full-file buffering)."""
    bounded = resolve_chunk_bytes(chunk_size)
    hasher = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(bounded)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


class StreamingFileStorage(FileStorage):
    """FileStorage that streams to disk in bounded chunks while hashing."""

    def __init__(
        self,
        stream: BinaryIO,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        max_size: int = 0,
        chunk_size: int | None = None,
        temp_dir: str | Path | None = None,
    ):
        super().__init__(stream, filename, content_type=content_type)
        self._max_size = max_size
        self._chunk_size = resolve_chunk_bytes(chunk_size)
        self._temp_dir = resolve_temp_dir(temp_dir)
        self._materialized_path: Optional[Path] = None
        self._bytes_written = 0
        self._hash_computed = False
        self._digest: Optional[str] = None

    @property
    def chunk_size(self) -> int:
        return self._chunk_size

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @property
    def computed_hash(self) -> Optional[str]:
        """Hex SHA-256 digest once the stream has been fully consumed."""
        return self._digest if self._hash_computed else None

    
    def save(self, dst, buffer_size: int = 16384) -> None:  # noqa: ARG002
        """Stream the upload to *dst* with bounded chunks and concurrent hashing.

        ``buffer_size`` is accepted for FileStorage API compatibility but the
        configured bounded chunk size always wins.
        """
        destination = Path(dst)
        if self._hash_computed and self._materialized_path and self._materialized_path.exists():
            shutil.copyfile(self._materialized_path, destination)
            return

        digest, written = hash_stream_to_path(
            self.stream,
            destination,
            chunk_size=self._chunk_size,
            max_size=self._max_size,
            temp_dir=self._temp_dir,
        )
        self._bytes_written = written
        self._digest = digest
        self._hash_computed = True
        self._materialized_path = destination

    def close(self) -> None:
        try:
            super().close()
        finally:
            # Only remove temp artifacts we own (not caller destinations).
            pass


def create_streaming_file_storage(field_storage: FileStorage) -> StreamingFileStorage:
    """Wrap a Werkzeug ``FileStorage`` with bounded-chunk streaming hashing."""
    config = _upload_config()
    max_size = resolve_max_bytes(
        getattr(config, "upload_max_bytes", None)
        if config is not None
        else None
    )
    if max_size == 0 and config is not None:
        max_size = int(getattr(config, "max_video_bytes", 0) or 0)
    chunk_size = resolve_chunk_bytes(
        getattr(config, "upload_chunk_bytes", None) if config is not None else None
    )
    temp_dir = resolve_temp_dir(
        getattr(config, "upload_temp_dir", None) if config is not None else None
    )
    return StreamingFileStorage(
        stream=field_storage.stream,
        filename=field_storage.filename,
        content_type=field_storage.content_type,
        max_size=max_size,
        chunk_size=chunk_size,
        temp_dir=temp_dir,
    )
