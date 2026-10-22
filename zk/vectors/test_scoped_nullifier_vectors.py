"""Generated scoped nullifiers agree with the committed synthetic fixture."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_vectors  # noqa: E402


def test_recompute_scoped_nullifier_matches_fixture():
    fixture = json.loads(generate_vectors.SCOPED_OUT_PATH.read_text(encoding="utf-8"))
    inputs = {
        name: int(fixture["witness"][name])
        for name in generate_vectors.SCOPED_INPUT_NAMES
    }
    [actual] = generate_vectors.compute_scoped_nullifiers([inputs])
    assert actual["credential_root"] == fixture["witness"]["credential_root"]
    assert actual["nullifier"] == fixture["witness"]["nullifier"]
    # Independently obtained with the pinned Noir helper, before implementation.
    assert int(actual["credential_root"]) == int(
        "1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9", 16
    )
    assert int(actual["nullifier"]) == int(
        "292551218b7ad1cd3d00ae7fa881741ef950814684498a81326c61213759bf33", 16
    )


def test_scoped_generator_is_byte_deterministic(tmp_path, monkeypatch):
    monkeypatch.setattr(generate_vectors, "OUT_PATH", tmp_path / "v1.json")
    monkeypatch.setattr(generate_vectors, "OUT_PATH_V2", tmp_path / "v2.json")
    monkeypatch.setattr(generate_vectors, "SCOPED_OUT_PATH", tmp_path / "scoped.json")
    generate_vectors.main([])
    first = generate_vectors.SCOPED_OUT_PATH.read_bytes()
    generate_vectors.main([])
    assert generate_vectors.SCOPED_OUT_PATH.read_bytes() == first
    committed = (
        Path(__file__).resolve().parents[1]
        / "noir/fixtures/scoped_nullifier_vectors.json"
    )
    assert first == committed.read_bytes()
    assert generate_vectors.main(["--check"]) == 0


def test_scoped_check_detects_tampering_without_writing(tmp_path, monkeypatch, capsys):
    committed = generate_vectors.SCOPED_OUT_PATH.read_bytes()
    tampered = committed.replace(
        b'"credential_secret": 12345', b'"credential_secret": 12346', 1
    )
    assert tampered != committed
    output = tmp_path / "scoped_nullifier_vectors.json"
    output.write_bytes(tampered)
    monkeypatch.setattr(generate_vectors, "SCOPED_OUT_PATH", output)
    with pytest.raises(SystemExit) as error:
        generate_vectors.main(["--check"])
    assert error.value.code == 1
    assert output.read_bytes() == tampered
    assert "scoped_nullifier_vectors.json is out of date" in capsys.readouterr().err


def test_calculated_variants_satisfy_fixture_relationships():
    fixture = json.loads(generate_vectors.SCOPED_OUT_PATH.read_text(encoding="utf-8"))
    for group in ("positive_cases", "negative_cases", "boundary_cases"):
        for case in fixture[group]:
            variants = case["derived"]
            assert variants, case["name"]
            nullifiers = [variant["nullifier"] for variant in variants]
            assert len(set(nullifiers)) == len(nullifiers), case["name"]
