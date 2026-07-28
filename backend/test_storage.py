import io
import os
import tempfile
import pytest

from backend.storage import EnvelopeEncryption, ContentAddressableStorage, StorageError

def test_envelope_encryption():
    env = EnvelopeEncryption()
    dek = env.generate_dek()
    tenant_id = "test_tenant"
    
    encrypted_dek = env.encrypt_dek(dek, tenant_id)
    assert len(encrypted_dek) > len(dek)
    
    decrypted_dek = env.decrypt_dek(encrypted_dek, tenant_id)
    assert dek == decrypted_dek
    
    with pytest.raises(StorageError):
        env.decrypt_dek(encrypted_dek, "wrong_tenant")

def test_content_addressable_storage():
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = ContentAddressableStorage(base_path=tmpdir)
        tenant_id = "tenant1"
        data = b"hello world this is evidence"
        
        stream = io.BytesIO(data)
        sha256_hash, encrypted_dek = storage.write_stream(stream, tenant_id)
        
        # Verify deduplication
        stream2 = io.BytesIO(data)
        sha256_hash2, encrypted_dek2 = storage.write_stream(stream2, tenant_id)
        assert sha256_hash == sha256_hash2
        
        # Verify reading
        out_stream = io.BytesIO()
        storage.read_stream(sha256_hash, encrypted_dek, tenant_id, out_stream)
        assert out_stream.getvalue() == data
        
        # Verify integrity check on read (tampering)
        file_path = storage._get_path(sha256_hash)
        with open(file_path, 'r+b') as f:
            f.seek(16) # Skip nonce
            f.write(b"tampered")
            
        out_stream2 = io.BytesIO()
        with pytest.raises(StorageError):
            storage.read_stream(sha256_hash, encrypted_dek, tenant_id, out_stream2)
            
        # Verify secure deletion
        storage.secure_delete(sha256_hash)
        assert not file_path.exists()
