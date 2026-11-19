"""Focused tests for attestation profile and critical-extension validation."""

from __future__ import annotations

import hashlib
import unittest

from capture_attestation import (
    AppIdentity,
    AttestationProfileValidationError,
    CameraPipeline,
    CaptureAttestation,
    SecureTime,
    decode_attestation,
    encode_attestation,
    inspect_attestation_profile_metadata,
    make_device_commitment,
)
from issuer_key_transparency import IssuerKey, IssuerManifest, TransparencyError


def _valid_attestation() -> CaptureAttestation:
    nonce = hashlib.sha256(b"profile-validation-nonce").hexdigest()
    return CaptureAttestation(
        version=1,
        trust_level=1,
        capture_nonce=nonce,
        app_identity=AppIdentity(
            package_name="com.harpocrates.camera",
            version_code="12",
            build_fingerprint="harpocrates/synthetic:14",
        ),
        device_commitment=make_device_commitment(
            nonce, hashlib.sha256(b"profile-validation-key").digest()
        ),
        privacy_scope="per_session",
        evidence_digest_binding=hashlib.sha256(
            b"synthetic-evidence"
        ).hexdigest(),
        secure_time=SecureTime(
            unix_ms=1_721_971_200_000,
            source="ntp_synchronized",
            drift_ms=25,
        ),
        camera_pipeline=CameraPipeline(
            sensor_orientation=90,
            has_watermark=False,
            claimed_integrity="raw_sensor",
        ),
        platform_claims={"bootloaderLocked": True},
        critical_fields=("secureTime", "cameraPipeline"),
        critical_extensions=(
            "harpocrates.evidence-binding/v1",
            "harpocrates.per-session-commitment/v1",
        ),
        optional_metadata={
            "lensProfile": "wide-24mm",
            "osPatchLevel": "2026-10-01",
            "captureMode": "still_burst",
        },
    )


class TestKnownOptionalMetadata(unittest.TestCase):
    def test_round_trip_preserves_known_optional_metadata_without_raising_trust(self):
        encoded = encode_attestation(_valid_attestation())
        decoded = decode_attestation(encoded)

        self.assertEqual(
            decoded.optional_metadata,
            {
                "lensProfile": "wide-24mm",
                "osPatchLevel": "2026-10-01",
                "captureMode": "still_burst",
            },
        )
        self.assertEqual(
            set(decoded.critical_fields), {"secureTime", "cameraPipeline"}
        )
        self.assertEqual(
            decoded.critical_extensions,
            (
                "harpocrates.evidence-binding/v1",
                "harpocrates.per-session-commitment/v1",
            ),
        )
        self.assertEqual(decoded.platform_claims, {"bootloaderLocked": True})
        self.assertEqual(decoded.trust_level, 1)

        report = inspect_attestation_profile_metadata(decoded)
        self.assertFalse(report["optionalMetadataVerified"])
        self.assertFalse(report["broadTrustAssumed"])
        self.assertEqual(report["trustLevelLabel"], "software_attested")
        self.assertEqual(report["platformClaimKeys"], ["bootloaderLocked"])


class TestUnknownRequiredDeclarations(unittest.TestCase):
    def test_rejects_unknown_top_level_field(self):
        encoded = encode_attestation(_valid_attestation())
        tampered = {**encoded, "quantumHardwareSeal": {"required": True}}

        with self.assertRaisesRegex(
            AttestationProfileValidationError, "unknown top-level"
        ):
            decode_attestation(tampered)

    def test_rejects_unknown_critical_field(self):
        encoded = encode_attestation(_valid_attestation())
        tampered = {**encoded, "criticalFields": ["biometricLivenessGate"]}

        with self.assertRaisesRegex(
            AttestationProfileValidationError, "unknown required field"
        ):
            decode_attestation(tampered)

    def test_rejects_omitted_declared_critical_field(self):
        encoded = encode_attestation(_valid_attestation())
        tampered = {key: value for key, value in encoded.items() if key != "secureTime"}
        tampered["criticalFields"] = ["secureTime"]

        with self.assertRaisesRegex(
            AttestationProfileValidationError, "omits a field"
        ):
            decode_attestation(tampered)

    def test_rejects_unsupported_critical_extension(self):
        encoded = encode_attestation(_valid_attestation())
        tampered = {
            **encoded,
            "criticalExtensions": ["vendor.proprietary.enclave/v2"],
        }

        with self.assertRaisesRegex(
            AttestationProfileValidationError, "unsupported critical extension"
        ):
            decode_attestation(tampered)

    def test_rejects_platform_claim_that_declares_itself_critical(self):
        encoded = encode_attestation(_valid_attestation())

        for marker in ({"critical": True}, {"critical": 1}, {"required": "yes"}):
            with self.subTest(marker=marker):
                tampered = {
                    **encoded,
                    "platformClaims": {"customGate": {**marker, "value": "x"}},
                }

                with self.assertRaisesRegex(
                    AttestationProfileValidationError, "platformClaims"
                ):
                    decode_attestation(tampered)

    def test_accepts_explicitly_false_platform_markers(self):
        encoded = encode_attestation(_valid_attestation())
        tampered = {
            **encoded,
            "platformClaims": {
                "customGate": {"critical": False, "required": False, "value": "x"}
            },
        }

        decoded = decode_attestation(tampered)
        self.assertEqual(
            decoded.platform_claims,
            {
                "customGate": {"critical": False, "required": False, "value": "x"}
            },
        )

    def test_rejects_unknown_optional_metadata_key_and_unbounded_value(self):
        encoded = encode_attestation(_valid_attestation())

        with self.assertRaisesRegex(
            AttestationProfileValidationError, "unknown metadata field"
        ):
            decode_attestation({**encoded, "optionalMetadata": {"imei": "0"}})

        with self.assertRaisesRegex(
            AttestationProfileValidationError, "bounded scalar"
        ):
            decode_attestation(
                {**encoded, "optionalMetadata": {"lensProfile": {"nested": True}}}
            )

    def test_rejects_empty_container_declared_critical(self):
        encoded = encode_attestation(_valid_attestation())
        tampered = {
            **encoded,
            "cameraPipeline": {},
            "criticalFields": ["cameraPipeline"],
        }

        with self.assertRaisesRegex(
            AttestationProfileValidationError, "omits a field"
        ):
            decode_attestation(tampered)

    def test_accepts_zero_trust_level_declared_critical(self):
        encoded = encode_attestation(_valid_attestation())
        tampered = {**encoded, "trustLevel": 0, "criticalFields": ["trustLevel"]}

        decoded = decode_attestation(tampered)
        self.assertEqual(decoded.trust_level, 0)

    def test_rejects_unknown_nested_fields(self):
        encoded = encode_attestation(_valid_attestation())

        for section in ("appIdentity", "secureTime", "cameraPipeline"):
            with self.subTest(section=section):
                tampered = {
                    **encoded,
                    section: {**encoded[section], "unknownRequiredSub": "x"},
                }

                with self.assertRaisesRegex(
                    AttestationProfileValidationError, section
                ):
                    decode_attestation(tampered)

    def test_rejects_non_list_critical_declarations(self):
        encoded = encode_attestation(_valid_attestation())

        for key in ("criticalFields", "criticalExtensions"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    AttestationProfileValidationError, "must be a list"
                ):
                    decode_attestation({**encoded, key: "not-a-list"})


class TestProfileVersionValidation(unittest.TestCase):
    def test_rejects_boolean_and_unsupported_versions(self):
        encoded = encode_attestation(_valid_attestation())

        with self.assertRaisesRegex(ValueError, "Unsupported attestation version"):
            decode_attestation({**encoded, "version": True})

        with self.assertRaisesRegex(ValueError, "Unsupported attestation version"):
            decode_attestation({**encoded, "version": 99})

    def test_rejects_profile_that_disagrees_with_version(self):
        encoded = encode_attestation(_valid_attestation())

        with self.assertRaisesRegex(ValueError, "profile must be"):
            decode_attestation(
                {**encoded, "profile": "harpocrates-capture-attestation/v2"}
            )


class TestIssuerManifestDeclarations(unittest.TestCase):
    def _manifest(self) -> dict:
        return IssuerManifest(
            organization_identity_hash="a" * 64,
            issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            active_keys=[IssuerKey("k1", "c" * 64, "ed25519", 1_000)],
            policy_hash="b" * 64,
            valid_from=1_000,
        ).to_dict()

    def test_rejects_unknown_manifest_critical_extension(self):
        manifest = self._manifest()

        with self.assertRaisesRegex(
            TransparencyError, "unsupported critical extension"
        ):
            IssuerManifest.from_dict(
                {**manifest, "criticalExtensions": ["unknown.manifest.ext/v1"]}
            )

    def test_rejects_boolean_manifest_version(self):
        manifest = self._manifest()

        with self.assertRaisesRegex(TransparencyError, "version"):
            IssuerManifest.from_dict({**manifest, "version": True})

    def test_rejects_non_list_manifest_critical_extension(self):
        manifest = self._manifest()

        with self.assertRaisesRegex(
            TransparencyError, "unsupported critical extension"
        ):
            IssuerManifest.from_dict(
                {**manifest, "criticalExtensions": "unknown.manifest.ext/v1"}
            )

    def test_accepts_empty_manifest_critical_extension_list(self):
        manifest = self._manifest()

        parsed = IssuerManifest.from_dict({**manifest, "criticalExtensions": []})
        self.assertEqual(parsed.version, manifest["version"])


if __name__ == "__main__":
    unittest.main()
