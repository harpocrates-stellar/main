from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import tempfile
from pathlib import Path
from typing import BinaryIO, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

class StorageError(Exception):
    pass

class EnvelopeEncryption:
    """Handles envelope encryption/decryption of artifacts."""

    def __init__(self, master_key_hex: Optional[str] = None):
        if not master_key_hex:
            # Fallback for dev: transient key
            self.master_key = os.urandom(32)
        else:
            try:
                self.master_key = bytes.fromhex(master_key_hex)
                if len(self.master_key) != 32:
                    raise ValueError("Master key must be 32 bytes")
            except ValueError as e:
                raise ValueError(f"Invalid master key: {e}")

    def generate_dek(self) -> bytes:
        return os.urandom(32)

    def encrypt_dek(self, dek: bytes, tenant_id: str) -> bytes:
        """Encrypts DEK using Master Key and tenant_id as associated data."""
        aesgcm = AESGCM(self.master_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, dek, tenant_id.encode('utf-8'))
        return nonce + ct

    def decrypt_dek(self, encrypted_dek: bytes, tenant_id: str) -> bytes:
        """Decrypts DEK using Master Key and tenant_id as associated data."""
        if len(encrypted_dek) < 12 + 16:
            raise StorageError("Invalid encrypted DEK")
        aesgcm = AESGCM(self.master_key)
        nonce = encrypted_dek[:12]
        ct = encrypted_dek[12:]
        try:
            return aesgcm.decrypt(nonce, ct, tenant_id.encode('utf-8'))
        except Exception as e:
            raise StorageError(f"Failed to decrypt DEK for tenant {tenant_id}: {e}")

class ContentAddressableStorage:
    """Durable, content-addressed, encrypted blob store."""

    def __init__(self, base_path: str, master_key_hex: Optional[str] = None):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.envelope = EnvelopeEncryption(master_key_hex)

    def _get_path(self, sha256_hash: str) -> Path:
        """Derives the file path from hash, using a 2-level directory structure to avoid directory size limits."""
        if len(sha256_hash) != 64:
            raise StorageError("Invalid SHA-256 hash")
        dir_path = self.base_path / sha256_hash[:2] / sha256_hash[2:4]
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path / sha256_hash

    def write_stream(self, stream: BinaryIO, tenant_id: str) -> tuple[str, bytes]:
        """
        Encrypts and writes the stream to a temporary file, computes SHA-256,
        then moves it to the content-addressed location.
        Returns the SHA-256 hash and the encrypted DEK.
        """
        dek = self.envelope.generate_dek()
        encrypted_dek = self.envelope.encrypt_dek(dek, tenant_id)
        
        hasher = hashlib.sha256()
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(dek), modes.CTR(nonce))
        encryptor = cipher.encryptor()

        # Temporary file
        fd, temp_path = tempfile.mkstemp(dir=self.base_path)
        try:
            with open(fd, 'wb') as f:
                f.write(nonce)
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    f.write(encryptor.update(chunk))
                f.write(encryptor.finalize())
            
            sha256_hash = hasher.hexdigest()
            final_path = self._get_path(sha256_hash)
            
            # Move atomically if possible, or copy if not
            if final_path.exists():
                # Deduplication: already exists, we can discard the temp file
                pass
            else:
                shutil.move(temp_path, final_path)
                # Ensure permissions are restrictive
                os.chmod(final_path, 0o600)
                
            return sha256_hash, encrypted_dek
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def read_stream(self, sha256_hash: str, encrypted_dek: bytes, tenant_id: str, dest_stream: BinaryIO) -> None:
        """
        Reads the encrypted content-addressed file, decrypts it, and writes to dest_stream.
        Verifies integrity during read.
        """
        dek = self.envelope.decrypt_dek(encrypted_dek, tenant_id)
        file_path = self._get_path(sha256_hash)
        
        if not file_path.exists():
            raise StorageError(f"Artifact {sha256_hash} not found")

        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            nonce = f.read(16)
            if len(nonce) != 16:
                raise StorageError("Invalid encrypted file format")
            
            cipher = Cipher(algorithms.AES(dek), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                decrypted_chunk = decryptor.update(chunk)
                hasher.update(decrypted_chunk)
                dest_stream.write(decrypted_chunk)
            
            final_chunk = decryptor.finalize()
            if final_chunk:
                hasher.update(final_chunk)
                dest_stream.write(final_chunk)
                
        computed_hash = hasher.hexdigest()
        if computed_hash != sha256_hash:
            raise StorageError("Integrity check failed: hash mismatch")

    def secure_delete(self, sha256_hash: str) -> None:
        """Securely deletes the file by overwriting it before unlinking."""
        file_path = self._get_path(sha256_hash)
        if not file_path.exists():
            return
            
        file_size = file_path.stat().st_size
        with open(file_path, 'r+b') as f:
            # Overwrite with random data
            chunk_size = 65536
            written = 0
            while written < file_size:
                size = min(chunk_size, file_size - written)
                f.write(os.urandom(size))
                written += size
            f.flush()
            os.fsync(f.fileno())
        
        file_path.unlink(missing_ok=True)
