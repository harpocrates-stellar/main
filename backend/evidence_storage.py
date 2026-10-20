import os
import hashlib
from typing import Tuple
from cryptography.fernet import Fernet
import db


def _load_master_fernet() -> Fernet:
    """Load and validate the master encryption key from MASTER_ENCRYPTION_KEY.

    Raises ValueError with a safe message (never logging or exposing key material)
    when the variable is unset, blank, or not valid Fernet base64.
    """
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64 or not master_key_b64.strip():
        raise ValueError("MASTER_ENCRYPTION_KEY is not set")
    try:
        return Fernet(master_key_b64.strip().encode("ascii"))
    except Exception as exc:
        raise ValueError(
            "MASTER_ENCRYPTION_KEY must be a valid 32-byte url-safe base64-encoded key"
        ) from None


def check_master_key() -> bool:
    """Return True if MASTER_ENCRYPTION_KEY is present and valid Fernet base64."""
    try:
        _load_master_fernet()
        return True
    except ValueError:
        return False


def generate_dek() -> Tuple[bytes, bytes]:
    """Generates a Data Encryption Key (DEK) and its encrypted form (using a Master Key)."""
    f = _load_master_fernet()

    dek = Fernet.generate_key()
    encrypted_dek = f.encrypt(dek)

    return dek, encrypted_dek


def decrypt_dek(encrypted_dek: bytes) -> bytes:
    f = _load_master_fernet()
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

def get_blob_info(content_hash: str) -> dict | None:
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select encrypted_dek, storage_path from blobs where content_hash = %s", (content_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None
