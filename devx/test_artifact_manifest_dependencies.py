"""Focused tests for #1215: circuit build dependency graph + stale detection."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parents[1] / "zk" / "tools"
sys.path.insert(0, str(_TOOLS))

from artifact_manifest import (  # noqa: E402
    Limits,
    Lock,
    build_manifest,
    serialize_manifest,
    stale_artifacts,
)


def _make_lock(tmp_path: Path, *, artifact_bytes: bytes = b"proof", source_bytes: bytes = b"circuit"):
    art = tmp_path / "release" / "proof.bin"
    art.parent.mkdir(parents=True)
    art.write_bytes(artifact_bytes)
    src = tmp_path / "source.nr"
    src.write_bytes(source_bytes)
    decl = {"path": "proof.bin", "kind": "binary", "role": "test", "required": True}
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
        "provenance_sources": {"globs": [str(src)]},
        "coverage": {"circuit_root": "zk/noir", "package_file": "Nargo.toml"},
    }
    return Lock(
        raw=raw,
        limits=Limits(10_000_000, 100, 100, 100),
        volatile_json_keys=frozenset(),
        strip_custom_sections=frozenset(),
        artifacts=(decl,),
        provenance_globs=(str(src),),
        circuit_root="zk/noir",
        package_file="Nargo.toml",
    ), tmp_path


def test_manifest_includes_dependency_graph(tmp_path: Path):
    lock, root = _make_lock(tmp_path)
    manifest, _run = build_manifest(lock, root)
    assert "dependencies" in manifest
    assert "toolchain" in manifest["dependencies"]
    assert "sha256" in manifest["dependencies"]["toolchain"]
    assert isinstance(manifest["dependencies"]["sources"], dict)


def test_fresh_build_dependency_graph_roundtrips(tmp_path: Path):
    lock, root = _make_lock(tmp_path)
    manifest, _run = build_manifest(lock, root)
    text = serialize_manifest(manifest)
    parsed = json.loads(text)
    assert parsed["dependencies"] == manifest["dependencies"]


def test_changed_source_marks_artifact_stale(tmp_path: Path):
    lock, root = _make_lock(tmp_path)
    manifest, _run = build_manifest(lock, root)
    # Simulate a source change: current_inputs has a different digest.
    current = {"source.nr": "0" * 64}
    findings = stale_artifacts(manifest, current)
    assert any("source.nr" in f for f in findings)


def test_unchanged_rebuild_produces_identical_dependencies(tmp_path: Path):
    lock, root = _make_lock(tmp_path)
    m1, _ = build_manifest(lock, root)
    m2, _ = build_manifest(lock, root)
    assert m1["dependencies"] == m2["dependencies"]
