"""Focused tests for #1218: record and validate artifact byte sizes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parents[1] / "zk" / "tools"
sys.path.insert(0, str(_TOOLS))

from artifact_manifest import (  # noqa: E402
    ArtifactSizeMismatchError,
    Limits,
    Lock,
    build_manifest,
    compare_manifests,
    digest_artifact,
    serialize_manifest,
)


def _make_lock(tmp_path: Path, *, declared_size: int | None, artifact_bytes: bytes):
    """Minimal Lock with one artifact declared, optional expected size."""
    art = tmp_path / "release" / "proof.bin"
    art.parent.mkdir(parents=True)
    art.write_bytes(artifact_bytes)
    decl = {"path": "proof.bin", "kind": "binary", "role": "test", "required": True}
    if declared_size is not None:
        decl["size_bytes"] = declared_size
    raw = {
        "format": "harpocrates.zk-toolchain-lock",
        "version": 1,
        "toolchain": {
            "nargo": {"version": "0.0.0"},
            "barretenberg": {"version": "0.0.0"},
            "proving_scheme": "ultra_honk",
            "oracle_hash": "keccak",
        },
        "environment": {},
        "limits": {
            "max_artifact_bytes": 10_000_000,
            "max_artifacts": 100,
            "max_provenance_files": 100,
            "max_circuits": 100,
        },
        "normalization": {"json": {"volatile_keys": []}, "wasm": {"strip_custom_sections": []}},
        "artifacts": [decl],
        "provenance_sources": {"globs": []},
        "coverage": {"circuit_root": "zk/noir", "package_file": "Nargo.toml"},
    }
    return Lock(
        raw=raw,
        limits=Limits(10_000_000, 100, 100, 100),
        volatile_json_keys=frozenset(),
        strip_custom_sections=frozenset(),
        artifacts=(decl,),
        provenance_globs=(),
        circuit_root="zk/noir",
        package_file="Nargo.toml",
    ), tmp_path / "release"


def test_size_recorded_in_manifest(tmp_path: Path):
    lock, root = _make_lock(tmp_path, declared_size=None, artifact_bytes=b"hello")
    result = digest_artifact(lock.artifacts[0], lock, root)
    entry = result.to_entry()
    assert entry["size_bytes"] == 5
    assert entry["raw_bytes"] == 5


def test_declared_size_mismatch_rejected_before_hash(tmp_path: Path):
    lock, root = _make_lock(tmp_path, declared_size=999, artifact_bytes=b"hello")
    with pytest.raises(ArtifactSizeMismatchError) as exc:
        digest_artifact(lock.artifacts[0], lock, root)
    msg = str(exc.value)
    assert "proof.bin" in msg
    assert "999" in msg and "5" in msg
    assert str(tmp_path) not in msg


def test_declared_size_match_proceeds(tmp_path: Path):
    lock, root = _make_lock(tmp_path, declared_size=5, artifact_bytes=b"hello")
    result = digest_artifact(lock.artifacts[0], lock, root)
    assert result.raw_bytes == 5
    assert result.raw_sha256 is not None


def test_missing_size_declaration_is_legacy(tmp_path: Path):
    lock, root = _make_lock(tmp_path, declared_size=None, artifact_bytes=b"hello")
    result = digest_artifact(lock.artifacts[0], lock, root)
    assert result.raw_sha256 is not None


def test_manifest_roundtrip_includes_size(tmp_path: Path):
    lock, root = _make_lock(tmp_path, declared_size=5, artifact_bytes=b"hello")
    manifest, run = build_manifest(lock, root)
    text = serialize_manifest(manifest)
    parsed = json.loads(text)
    assert parsed["artifacts"][0]["size_bytes"] == 5


def test_compare_manifests_flags_size_drift():
    a = {"artifacts": [{"path": "x", "size_bytes": 5, "raw_sha256": "abc", "normalized_sha256": "abc"}]}
    b = {"artifacts": [{"path": "x", "size_bytes": 7, "raw_sha256": "abc", "normalized_sha256": "abc"}]}
    findings = compare_manifests(a, b)
    assert any("size 5 -> 7" in f for f in findings)
