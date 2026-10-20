import logging
import pytest
from cryptography.fernet import Fernet

import evidence_storage
from readiness import ReadinessManager, check_evidence_storage


def test_generate_dek_missing_master_key_raises(monkeypatch, caplog):
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ValueError, match="MASTER_ENCRYPTION_KEY is not set"):
            evidence_storage.generate_dek()


def test_decrypt_dek_missing_master_key_raises(monkeypatch):
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)

    with pytest.raises(ValueError, match="MASTER_ENCRYPTION_KEY is not set"):
        evidence_storage.decrypt_dek(b"ciphertext")


@pytest.mark.parametrize(
    "malformed_key",
    [
        "   ",
        "not-valid-base64!!!",
        "c2hvcnQ=",  # valid base64 ("short"), wrong length for Fernet
        "a" * 44,    # 44 chars, not valid urlsafe base64 decoding to 32 bytes
    ],
)
def test_malformed_master_key_raises_without_leaking_key(monkeypatch, caplog, malformed_key):
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", malformed_key)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ValueError) as gen_exc:
            evidence_storage.generate_dek()
        with pytest.raises(ValueError) as dec_exc:
            evidence_storage.decrypt_dek(b"ciphertext")

    assert str(gen_exc.value) == str(dec_exc.value)
    stripped = malformed_key.strip()
    if stripped:
        assert stripped not in str(gen_exc.value)
        assert stripped not in caplog.text


def test_generate_and_decrypt_dek_round_trip(monkeypatch, caplog):
    master_key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", master_key)

    with caplog.at_level(logging.DEBUG):
        dek, encrypted_dek = evidence_storage.generate_dek()
        assert isinstance(dek, bytes)
        assert isinstance(encrypted_dek, bytes)
        assert dek != encrypted_dek

        recovered_dek = evidence_storage.decrypt_dek(encrypted_dek)
        assert recovered_dek == dek

        # Verify the DEK itself is a valid Fernet key that can encrypt/decrypt a blob
        encryptor = evidence_storage.get_encryptor(recovered_dek)
        payload = b"evidence-blob-bytes"
        assert encryptor.decrypt(encryptor.encrypt(payload)) == payload

    assert master_key not in caplog.text
    assert dek.decode("ascii") not in caplog.text


def test_readiness_surfaces_evidence_storage_when_enabled(monkeypatch):
    monkeypatch.setenv("EVIDENCE_STORAGE_ENABLED", "true")
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)

    manager = ReadinessManager(timeout_seconds=0.5, cache_ttl_seconds=0.0)
    status_missing = manager.check()
    assert status_missing["ok"] is False
    assert status_missing["evidence_storage"] == "not_configured"

    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", "malformed-key")
    status_malformed = manager.check()
    assert status_malformed["ok"] is False
    assert status_malformed["evidence_storage"] == "not_configured"

    valid_key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", valid_key)
    status_valid = manager.check()
    assert status_valid["ok"] is True
    assert status_valid["evidence_storage"] == "connected"


def test_readiness_ignores_evidence_storage_when_disabled(monkeypatch):
    monkeypatch.delenv("EVIDENCE_STORAGE_ENABLED", raising=False)
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)

    manager = ReadinessManager(timeout_seconds=0.5, cache_ttl_seconds=0.0)
    status = manager.check()
    assert status["ok"] is True
    assert "evidence_storage" not in status
    assert check_evidence_storage() is False
