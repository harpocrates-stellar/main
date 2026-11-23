"""Focused tests for #1214: signed circuit artifact release manifest."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parents[1] / "zk" / "tools"
sys.path.insert(0, str(_TOOLS))

from artifact_manifest import (  # noqa: E402
    ManifestVerificationError,
    load_verified_artifacts,
    sign_manifest,
    verify_manifest,
)

KEY = b"release-key-for-tests"
TOOLCHAIN = {"nargo": "0.0.0", "barretenberg": "0.0.0", "proving_scheme": "ultra_honk", "oracle_hash": "keccak"}


def _signed(artifacts=None, source_revision="rev-A"):
    return sign_manifest(
        toolchain=TOOLCHAIN,
        source_revision=source_revision,
        artifacts=artifacts or {"proof.bin": "0" * 64},
        signing_key=KEY,
    )


def test_sign_verify_roundtrip():
    m = _signed()
    verify_manifest(m, KEY)


def test_verify_offline_works(tmp_path: Path):
    m = _signed()
    (tmp_path / "no-manifest").write_text("ignored")
    verify_manifest(m, KEY)


def test_tampered_artifact_digest_fails():
    m = _signed()
    m["artifacts"]["proof.bin"] = "1" * 64
    with pytest.raises(ManifestVerificationError, match="signature mismatch"):
        verify_manifest(m, KEY)


def test_mutated_source_revision_fails():
    m = _signed()
    m["source_revision"] = "rev-B"
    with pytest.raises(ManifestVerificationError, match="signature mismatch"):
        verify_manifest(m, KEY)


def test_missing_signature_fails_closed():
    m = _signed()
    del m["signature"]
    with pytest.raises(ManifestVerificationError, match="unsupported signature scheme"):
        verify_manifest(m, KEY)


def test_wrong_key_fails():
    m = _signed()
    with pytest.raises(ManifestVerificationError, match="signature mismatch"):
        verify_manifest(m, b"different-key")


def test_load_verified_artifacts_loads_identical_bytes(tmp_path: Path):
    payload = b"artifact-bytes"
    from artifact_manifest import sha256_hex
    digest = sha256_hex(payload)
    (tmp_path / "proof.bin").write_bytes(payload)
    m = _signed({"proof.bin": digest})
    out = load_verified_artifacts(m, tmp_path, KEY)
    assert out["proof.bin"] == payload


def test_load_verified_artifacts_rejects_tampered_bytes(tmp_path: Path):
    (tmp_path / "proof.bin").write_bytes(b"tampered")
    m = _signed({"proof.bin": "0" * 64})
    with pytest.raises(ManifestVerificationError, match="digest mismatch"):
        load_verified_artifacts(m, tmp_path, KEY)


def test_load_verified_artifacts_fails_closed_before_read(tmp_path: Path):
    # No artifact on disk at all; verification should fail first.
    m = _signed()
    m["source_revision"] = "mutated"
    with pytest.raises(ManifestVerificationError, match="signature mismatch"):
        load_verified_artifacts(m, tmp_path, KEY)
