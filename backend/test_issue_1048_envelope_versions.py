"""Focused regression and boundary tests for issue #1048:
record encryption envelope versions with stored evidence metadata.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken

sys.path.insert(0, str(Path(__file__).resolve().parent))

import evidence_storage  # noqa: E402
import storage  # noqa: E402


class _InMemoryBlobDB:
    def __init__(self) -> None:
        self.blobs: dict[str, dict[str, object]] = {}
        self.commits = 0
        self._row: dict[str, object] | None = None

    @contextmanager
    def connection(self):
        yield self

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return None

    def execute(self, sql: str, params: tuple = ()) -> None:
        normalized = " ".join(sql.lower().split())
        self._row = None
        if normalized.startswith("insert into blobs"):
            content_hash, encrypted_dek, size_bytes, storage_path = params
            if content_hash not in self.blobs:
                self.blobs[content_hash] = {
                    "encrypted_dek": encrypted_dek,
                    "size_bytes": size_bytes,
                    "storage_path": storage_path,
                }
        elif normalized.startswith("select encrypted_dek, storage_path from blobs"):
            (content_hash,) = params
            blob = self.blobs.get(content_hash)
            if blob is not None:
                self._row = {
                    "encrypted_dek": blob["encrypted_dek"],
                    "storage_path": blob["storage_path"],
                }

    def fetchone(self):
        return self._row

    def commit(self) -> None:
        self.commits += 1


class EnvelopeVersioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.master_key = Fernet.generate_key().decode("ascii")
        self._env_patch = patch.dict(
            os.environ,
            {"MASTER_ENCRYPTION_KEY": self.master_key},
            clear=False,
        )
        self._env_patch.start()
        self.fake_db = _InMemoryBlobDB()
        self._db_patch = patch.object(
            evidence_storage.db,
            "get_connection",
            self.fake_db.connection,
        )
        self._db_patch.start()

    def tearDown(self) -> None:
        self._db_patch.stop()
        self._env_patch.stop()

    def test_generate_versioned_dek_and_record_blob_metadata(self) -> None:
        dek, wrapped_dek, version = evidence_storage.generate_versioned_dek()
        self.assertEqual(version, evidence_storage.CURRENT_ENVELOPE_VERSION)
        self.assertTrue(wrapped_dek.startswith(b"hpx-fernet-v1:"))

        content_hash = "a" * 64
        evidence_storage.record_blob(
            content_hash,
            wrapped_dek,
            2048,
            "/synthetic/blobs/aa",
            envelope_version=version,
        )

        # Default get_blob_info remains 100% compatible with legacy two-key callers.
        basic_info = evidence_storage.get_blob_info(content_hash)
        self.assertEqual(
            basic_info,
            {
                "encrypted_dek": wrapped_dek.decode("ascii"),
                "storage_path": "/synthetic/blobs/aa",
            },
        )

        # Extended metadata exposes the validated envelope version.
        meta = evidence_storage.get_blob_metadata(content_hash)
        assert meta is not None
        self.assertEqual(meta["envelope_version"], "hpx-fernet-v1")
        self.assertFalse(meta["is_legacy_envelope"])
        self.assertEqual(evidence_storage.decrypt_dek(meta["encrypted_dek"]), dek)

    def test_distinguishes_known_legacy_envelope_from_current_and_unsupported(self) -> None:
        dek, legacy_encrypted_dek = evidence_storage.generate_dek()
        self.assertNotIn(b":", legacy_encrypted_dek)

        parsed_legacy = evidence_storage.inspect_envelope(legacy_encrypted_dek)
        self.assertEqual(parsed_legacy.envelope_version, "legacy-fernet-v0")
        self.assertTrue(parsed_legacy.is_legacy)
        self.assertEqual(evidence_storage.decrypt_dek(legacy_encrypted_dek), dek)

        content_hash = "b" * 64
        evidence_storage.record_blob(content_hash, legacy_encrypted_dek, 512, "/synthetic/blobs/bb")
        legacy_meta = evidence_storage.get_blob_metadata(content_hash)
        assert legacy_meta is not None
        self.assertEqual(legacy_meta["envelope_version"], "legacy-fernet-v0")
        self.assertTrue(legacy_meta["is_legacy_envelope"])

        # Recording a legacy token with an explicit v1 target upgrades the stored metadata header.
        upgraded_hash = "c" * 64
        evidence_storage.record_blob(
            upgraded_hash,
            legacy_encrypted_dek,
            512,
            "/synthetic/blobs/cc",
            envelope_version="hpx-fernet-v1",
        )
        upgraded_meta = evidence_storage.get_blob_metadata(upgraded_hash)
        assert upgraded_meta is not None
        self.assertEqual(upgraded_meta["envelope_version"], "hpx-fernet-v1")
        self.assertFalse(upgraded_meta["is_legacy_envelope"])
        self.assertEqual(evidence_storage.decrypt_dek(upgraded_meta["encrypted_dek"]), dek)

    def test_unsupported_envelope_versions_fail_closed_without_invoking_cipher(self) -> None:
        _, valid_token = evidence_storage.generate_dek()
        cipher_calls = 0

        def forbidden_cipher(_key: bytes) -> Fernet:
            nonlocal cipher_calls
            cipher_calls += 1
            raise AssertionError("Cipher must not be constructed for unsupported envelopes")

        unsupported_samples = [
            b"hpx-aesgcm-v2:" + valid_token,
            b"chacha20-poly1305-v1:nonce:ciphertext",
            b"fernet-v99:" + valid_token,
        ]
        for sample in unsupported_samples:
            with self.assertRaises(evidence_storage.UnsupportedEnvelopeError) as ctx:
                evidence_storage.decrypt_dek(sample, cipher_factory=forbidden_cipher)
            self.assertEqual(ctx.exception.reason_code, "UNSUPPORTED_ENVELOPE_VERSION")
            self.assertIsInstance(ctx.exception, InvalidToken)

        # Mismatched expected_version must also fail closed before touching cipher.
        with self.assertRaises(evidence_storage.UnsupportedEnvelopeError) as mismatch_ctx:
            evidence_storage.decrypt_dek(
                valid_token,
                expected_version="hpx-fernet-v1",
                cipher_factory=forbidden_cipher,
            )
        self.assertEqual(mismatch_ctx.exception.reason_code, "ENVELOPE_VERSION_MISMATCH")

        with self.assertRaises(evidence_storage.UnsupportedEnvelopeError):
            evidence_storage.decrypt_dek(
                valid_token,
                expected_version="unknown-v7",
                cipher_factory=forbidden_cipher,
            )

        self.assertEqual(cipher_calls, 0)

    def test_malformed_ciphertext_never_triggers_algorithm_guessing(self) -> None:
        cipher_calls = 0

        def forbidden_cipher(_key: bytes) -> Fernet:
            nonlocal cipher_calls
            cipher_calls += 1
            raise AssertionError("Cipher must never be invoked on malformed ciphertext")

        # Construct structurally invalid binary frames that might tempt naive base64 decoders:
        wrong_version_frame = base64.urlsafe_b64encode(b"\x81" + (b"\x00" * 72))
        unaligned_block_frame = base64.urlsafe_b64encode(b"\x80" + (b"\x00" * 70))
        truncated_frame = base64.urlsafe_b64encode(b"\x80" + (b"\x00" * 40))

        malformed_inputs: list[bytes | str] = [
            b"",
            b"   ",
            b"\x80\xff\x00\x11raw-binary-bytes",
            b"completely-corrupted-token",
            b":missing-prefix",
            b"BAD HEADER:" + wrong_version_frame,
            b"hpx-fernet-v1:",
            b"hpx-fernet-v1:extra:colon",
            b"hpx-fernet-v1:not-valid-fernet",
            wrong_version_frame,
            unaligned_block_frame,
            truncated_frame,
            "hpx-fernet-v1:abcde",  # len % 4 == 1 invalid base64
            "hpx-fernet-v1:====",
        ]

        for bad_input in malformed_inputs:
            with self.assertRaises(evidence_storage.MalformedEnvelopeError) as ctx:
                evidence_storage.decrypt_dek(bad_input, cipher_factory=forbidden_cipher)
            self.assertEqual(ctx.exception.reason_code, "MALFORMED_ENVELOPE")
            self.assertIsInstance(ctx.exception, InvalidToken)

        self.assertEqual(cipher_calls, 0)

    def test_evidence_payload_encryption_and_decryption_envelopes(self) -> None:
        dek = Fernet.generate_key()
        plaintext = b"synthetic-evidence-frame-0001"

        versioned_blob = evidence_storage.encrypt_evidence_payload(plaintext, dek)
        self.assertTrue(versioned_blob.startswith(b"hpx-fernet-v1:"))
        self.assertEqual(
            evidence_storage.decrypt_evidence_payload(
                versioned_blob,
                dek,
                expected_version="hpx-fernet-v1",
            ),
            plaintext,
        )

        # Legacy unprefixed Fernet blob payloads remain readable when valid.
        legacy_blob = evidence_storage.get_encryptor(dek).encrypt(plaintext)
        self.assertEqual(
            evidence_storage.decrypt_evidence_payload(legacy_blob, dek),
            plaintext,
        )

        # Malformed or unsupported payload ciphertexts never invoke the DEK cipher.
        invoked = False

        def spy_cipher(_dek: bytes) -> Fernet:
            nonlocal invoked
            invoked = True
            return Fernet(_dek)

        with self.assertRaises(evidence_storage.MalformedEnvelopeError):
            evidence_storage.decrypt_evidence_payload(
                b"corrupted-evidence-bytes",
                dek,
                cipher_factory=spy_cipher,
            )
        with self.assertRaises(evidence_storage.UnsupportedEnvelopeError):
            evidence_storage.decrypt_evidence_payload(
                b"aes-256-gcm-v3:" + legacy_blob,
                dek,
                cipher_factory=spy_cipher,
            )
        self.assertFalse(invoked)

    def test_storage_sidecar_envelope_metadata_roundtrip_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = Path(tmp_dir) / "job_42_input"
            artifact.write_bytes(b"encrypted-synthetic-payload")
            digest = "d" * 64

            self.assertIsNone(storage.read_envelope_metadata(artifact))

            sidecar = storage.write_envelope_metadata(
                artifact,
                envelope_version="hpx-fernet-v1",
                content_hash=digest,
                size_bytes=27,
            )
            self.assertTrue(sidecar.exists())
            loaded = storage.read_envelope_metadata(artifact)
            self.assertEqual(
                loaded,
                {
                    "schema": storage.ENVELOPE_METADATA_SCHEMA,
                    "envelope_version": "hpx-fernet-v1",
                    "is_legacy_envelope": False,
                    "content_hash": digest,
                    "size_bytes": 27,
                },
            )

            with self.assertRaises(evidence_storage.UnsupportedEnvelopeError):
                storage.write_envelope_metadata(artifact, envelope_version="aes-gcm-v9")

            # Unsupported version persisted on disk fails closed on read.
            sidecar.write_text(
                '{"schema": "hpx-evidence-envelope/1", "envelope_version": "aes-gcm-v9"}',
                encoding="utf-8",
            )
            with self.assertRaises(evidence_storage.UnsupportedEnvelopeError):
                storage.read_envelope_metadata(artifact)

            # Corrupted JSON fails closed with MalformedEnvelopeError.
            sidecar.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(evidence_storage.MalformedEnvelopeError):
                storage.read_envelope_metadata(artifact)


if __name__ == "__main__":
    unittest.main()
