"""Tests for shared canonical JSON and hex validation helpers."""

from __future__ import annotations

import hashlib
import json
import unittest

from canonical import canonical_json_bytes, is_hex
from envelope import canonical_metadata_hash
from capture_attestation import (
    AppIdentity,
    CaptureAttestation,
    CameraPipeline,
    SecureTime,
    canonical_attestation_hash,
    encode_attestation,
)
from time_attestation import (
    TimeAttestation,
    canonical_time_attestation_hash,
    encode_time_attestation,
)
from c2pa import export_c2pa_manifest, parse_c2pa_manifest
from issuer_key_transparency import (
    IssuerKey,
    IssuerManifest,
    canonicalize_manifest,
    manifest_hash,
)


class TestCanonicalJson(unittest.TestCase):
    def test_key_ordering_independence(self):
        """Objects with keys inserted in different orders must produce identical canonical bytes."""
        obj1 = {"z": 1, "a": 2, "m": {"c": 3, "b": 4}}
        obj2 = {"a": 2, "m": {"b": 4, "c": 3}, "z": 1}
        obj3 = {"m": {"c": 3, "b": 4}, "z": 1, "a": 2}

        bytes1 = canonical_json_bytes(obj1)
        bytes2 = canonical_json_bytes(obj2)
        bytes3 = canonical_json_bytes(obj3)

        self.assertEqual(bytes1, bytes2)
        self.assertEqual(bytes2, bytes3)
        self.assertEqual(bytes1, b'{"a":2,"m":{"b":4,"c":3},"z":1}')

    def test_unicode_preservation_ensure_ascii_false(self):
        """Non-ASCII Unicode characters must be preserved as UTF-8 without \\u escapes."""
        obj = {
            "greeting": "Héllo Wörld ✨",
            "chinese": "你好世界",
            "symbols": "αβγδε ⭐ 🔒",
        }
        res = canonical_json_bytes(obj)
        self.assertNotIn(b"\\u", res)
        self.assertEqual(json.loads(res.decode("utf-8")), obj)
        expected_str = '{"chinese":"你好世界","greeting":"Héllo Wörld ✨","symbols":"αβγδε ⭐ 🔒"}'
        self.assertEqual(res, expected_str.encode("utf-8"))

    def test_compact_separators_no_whitespace(self):
        """Compact separators (',', ':') with no extraneous spaces."""
        obj = {"list": [1, 2, "three"], "nested": {"key": "value"}}
        res = canonical_json_bytes(obj)
        self.assertEqual(res, b'{"list":[1,2,"three"],"nested":{"key":"value"}}')

    def test_nested_structures(self):
        """Deeply nested structures with lists and dicts are deterministically serialized."""
        obj = {
            "level1": {
                "level2": {
                    "level3": [
                        {"z": 1, "a": 2},
                        {"y": 3, "b": 4},
                    ]
                }
            }
        }
        res = canonical_json_bytes(obj)
        self.assertEqual(
            res,
            b'{"level1":{"level2":{"level3":[{"a":2,"z":1},{"b":4,"y":3}]}}}',
        )


class TestIsHex(unittest.TestCase):
    def test_valid_hex(self):
        self.assertTrue(is_hex("0123456789abcdefABCDEF"))
        self.assertTrue(is_hex("ab" * 32, length=64))
        self.assertTrue(is_hex("AB" * 32, length=64))
        self.assertTrue(is_hex("0" * 64, length=64))

    def test_invalid_length(self):
        self.assertFalse(is_hex("ab" * 31, length=64))
        self.assertFalse(is_hex("ab" * 33, length=64))
        self.assertFalse(is_hex("", length=64))
        self.assertFalse(is_hex(""))

    def test_invalid_characters(self):
        self.assertFalse(is_hex("xyz"))
        self.assertFalse(is_hex("0x" + "a" * 62, length=64))
        self.assertFalse(is_hex(" " + "a" * 63, length=64))
        self.assertFalse(is_hex("a" * 63 + " ", length=64))
        self.assertFalse(is_hex("g" * 64, length=64))

    def test_non_string_types(self):
        self.assertFalse(is_hex(None))
        self.assertFalse(is_hex(123))
        self.assertFalse(is_hex(["a" * 64]))
        self.assertFalse(is_hex({"hex": "a" * 64}))


class TestSharedFixtureDigestInvariance(unittest.TestCase):
    """Assert every module's digest/hash behavior for a shared fixture remains unchanged."""

    def test_shared_fixture_canonical_json_bytes(self):
        fixture = {
            "sourceHash": "aa" * 32,
            "proofId": "bb" * 32,
            "tier": "seal",
            "timestamp": "2026-10-27T12:00:00Z",
            "version": 2,
            "extra": {"note": "Unicode \u00e9\u00e0\u00fc \u2714\ufe0f", "count": 42},
        }
        expected_bytes = canonical_json_bytes(fixture)
        expected_sha256 = hashlib.sha256(expected_bytes).hexdigest()

        # 1. envelope.py
        envelope_hash = canonical_metadata_hash(fixture)
        self.assertEqual(envelope_hash, expected_sha256)

        # 2. issuer_key_transparency.py
        key = IssuerKey(
            key_id="k1",
            public_key_hash="01" * 32,
            algorithm="ed25519",
            valid_from=1000,
        )
        manifest = IssuerManifest(
            organization_identity_hash="aa" * 32,
            issuer_address="bb" * 32,
            active_keys=[key],
            policy_hash="cc" * 32,
            valid_from=2000,
            predecessor_manifest_hash="00" * 32,
        )
        m_dict = manifest.to_dict()
        m_dict.pop("signatureHash", None)
        manifest_bytes = canonical_json_bytes(m_dict)
        self.assertEqual(manifest_hash(manifest), hashlib.sha256(manifest_bytes).hexdigest())

        # 3. time_attestation.py
        time_att = TimeAttestation(
            version=1,
            protocol="harpocrates-time-attestation/v1",
            evidence_digest="cc" * 32,
            stellar_anchors=[],
            rfc3161_anchors=[],
        )
        time_hash = canonical_time_attestation_hash(time_att)
        time_encoded = encode_time_attestation(time_att)
        self.assertEqual(time_hash, hashlib.sha256(canonical_json_bytes(time_encoded)).hexdigest())

        # 4. capture_attestation.py
        capture_att = CaptureAttestation(
            version=1,
            trust_level=2,
            capture_nonce="dd" * 32,
            app_identity=AppIdentity(package_name="com.example", version_code="1"),
            device_commitment="ee" * 32,
            privacy_scope="per_session",
            evidence_digest_binding="cc" * 32,
            secure_time=SecureTime(
                unix_ms=1700000000000,
                source="hardware_clock",
                drift_ms=10,
            ),
            camera_pipeline=CameraPipeline(
                sensor_orientation=90,
                has_watermark=False,
            ),
        )
        cap_hash = canonical_attestation_hash(capture_att)
        cap_encoded = encode_attestation(capture_att)
        self.assertEqual(cap_hash, hashlib.sha256(canonical_json_bytes(cap_encoded)).hexdigest())

        # 5. c2pa.py
        exported = export_c2pa_manifest(
            video_hash="aa" * 32,
            metadata_hash="bb" * 32,
            proof_id="cc" * 32,
            tier="seal",
            network="stellar_testnet",
            contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        parsed = parse_c2pa_manifest(canonical_json_bytes(exported.manifest))
        self.assertEqual(parsed.binding.video_hash, "aa" * 32)
        self.assertEqual(parsed.binding.metadata_hash, "bb" * 32)
        self.assertEqual(
            exported.digest,
            hashlib.sha256(canonical_json_bytes(exported.manifest)).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
