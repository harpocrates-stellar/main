"""Tests for revocation witness Merkle-depth bounds (#357)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "zk" / "tools"))

import revocation_depth as rd  # noqa: E402


def test_depth_bounds() -> None:
    assert rd.MAX_REVOCATION_WITNESS_DEPTH == 16
    assert rd.MAX_REVOCATION_LEAVES == 65536
    for depth in range(rd.MIN_REVOCATION_WITNESS_DEPTH, rd.MAX_REVOCATION_WITNESS_DEPTH + 1):
        assert rd.validate_revocation_depth(depth) == depth
        leaf_count = 1 << depth
        assert rd.validate_revocation_leaf_count(leaf_count) == leaf_count
        assert rd.validate_revocation_witness_shape(depth, leaf_count) == (depth, leaf_count)


def test_max_depth_and_over_depth_rejection() -> None:
    assert rd.validate_revocation_depth(16) == 16
    assert rd.validate_revocation_leaf_count(65536) == 65536
    assert rd.validate_revocation_witness_shape(16, 65536) == (16, 65536)
    with pytest.raises(rd.RevocationDepthError) as exc:
        rd.validate_revocation_depth(17)
    assert exc.value.code == "depth_oversize"
    with pytest.raises(rd.RevocationDepthError) as exc:
        rd.validate_revocation_leaf_count(65537)
    assert exc.value.code == "depth_oversize"
    assert exc.value.signal() == {"rejectCode": "depth_oversize", "field": "depth"}

    with pytest.raises(rd.DepthBoundError) as exc_with_depth:
        rd.check_revocation_leaf_count(
            rd.MAX_REVOCATION_LEAVES + 1, rd.MAX_REVOCATION_WITNESS_DEPTH
        )
    assert exc_with_depth.value.code == "depth_oversize"
    assert exc_with_depth.value.signal() == {
        "rejectCode": "depth_oversize",
        "field": "depth",
    }


def test_rejects_leaf_count_mismatch_smaller_than_expected():
    for depth, smaller_count in [(2, 2), (2, 3), (3, 4), (3, 7)]:
        with pytest.raises(rd.DepthBoundError) as exc:
            rd.check_revocation_leaf_count(smaller_count, depth)
        assert exc.value.code == "leaf_count_mismatch"
        signal = exc.value.signal()
        assert signal == {"rejectCode": "leaf_count_mismatch", "field": "depth"}
        assert str(smaller_count) not in str(signal)
        assert "leaves" not in signal


def test_rejects_leaf_count_mismatch_larger_than_expected():
    for depth, larger_count in [(1, 4), (2, 6)]:
        with pytest.raises(rd.DepthBoundError) as exc:
            rd.check_revocation_leaf_count(larger_count, depth)
        assert exc.value.code == "leaf_count_mismatch"
        signal = exc.value.signal()
        assert signal == {"rejectCode": "leaf_count_mismatch", "field": "depth"}
        assert str(larger_count) not in str(signal)
        assert "leaves" not in signal


@pytest.mark.parametrize(
    ("depth", "code"),
    [
        (0, "depth_undersize"),
        (-1, "depth_undersize"),
        (rd.MAX_REVOCATION_WITNESS_DEPTH + 1, "depth_oversize"),
        (17, "depth_oversize"),
        (32, "depth_oversize"),
        (True, "depth_not_integer"),
        ("16", "depth_not_integer"),
    ],
)
def test_invalid_depths(depth: object, code: str) -> None:
    with pytest.raises(rd.RevocationDepthError) as exc:
        rd.validate_revocation_depth(depth)  # type: ignore[arg-type]
    assert exc.value.code == code


@pytest.mark.parametrize(
    ("leaf_count", "code"),
    [
        (0, "depth_undersize"),
        (1, "depth_undersize"),
        (3, "depth_non_power_of_two"),
        (6, "depth_non_power_of_two"),
        (9, "depth_non_power_of_two"),
        (65535, "depth_non_power_of_two"),
        (rd.MAX_REVOCATION_LEAVES + 1, "depth_oversize"),
        (1 << (rd.MAX_REVOCATION_WITNESS_DEPTH + 1), "depth_oversize"),
        (False, "depth_not_integer"),
    ],
)
def test_invalid_leaf_counts(leaf_count: object, code: str) -> None:
    with pytest.raises(rd.RevocationDepthError) as exc:
        rd.validate_revocation_leaf_count(leaf_count)  # type: ignore[arg-type]
    assert exc.value.code == code


def test_shape_mismatch_and_fixture_alignment() -> None:
    with pytest.raises(rd.RevocationDepthError) as exc:
        rd.validate_revocation_witness_shape(3, 4)
    assert exc.value.code == "depth_leaf_mismatch"
    with pytest.raises(rd.RevocationDepthError) as exc:
        rd.validate_revocation_witness_shape(16, 8)
    assert exc.value.code == "depth_leaf_mismatch"

    fixture = ROOT / "zk" / "noir" / "fixtures" / "revocation_vectors.json"
    data = json.loads(fixture.read_text(encoding="utf-8"))
    assert data["_max_revocation_witness_depth"] == rd.MAX_REVOCATION_WITNESS_DEPTH
    assert data["_max_revocation_leaves"] == rd.MAX_REVOCATION_LEAVES
    assert data["revocation_tree"]["max_depth"] == rd.MAX_REVOCATION_WITNESS_DEPTH
    assert data["revocation_tree"]["max_leaves"] == rd.MAX_REVOCATION_LEAVES
    rd.validate_revocation_witness_shape(
        data["revocation_tree"]["depth"],
        data["revocation_tree"]["leaf_count"],
    )
    max_depth_vectors = [
        v for v in data["positive_cases"] if v["name"] == "max_depth_non_revocation_witness"
    ]
    assert len(max_depth_vectors) == 1
    assert max_depth_vectors[0]["depth"] == rd.MAX_REVOCATION_WITNESS_DEPTH
    assert max_depth_vectors[0]["leaf_count"] == rd.MAX_REVOCATION_LEAVES
    over_depth_vectors = [
        v for v in data["negative_cases"] if v["name"] == "oversized_revocation_depth"
    ]
    assert len(over_depth_vectors) == 1
    assert over_depth_vectors[0]["depth"] == rd.MAX_REVOCATION_WITNESS_DEPTH + 1
    assert over_depth_vectors[0]["expected_error"] == "depth_oversize"


def test_constant_sync_across_layers() -> None:
    noir_src = (ROOT / "zk" / "noir" / "revocation_witness" / "src" / "main.nr").read_text(
        encoding="utf-8"
    )
    noir_depth = int(
        re.search(r"MAX_REVOCATION_WITNESS_DEPTH:\s*Field\s*=\s*(\d+)", noir_src).group(1)  # type: ignore[union-attr]
    )
    noir_leaves = int(
        re.search(r"MAX_REVOCATION_LEAVES:\s*Field\s*=\s*(\d+)", noir_src).group(1)  # type: ignore[union-attr]
    )

    rust_src = (
        ROOT / "contracts" / "contracts" / "harpocrates-registry" / "src" / "lib.rs"
    ).read_text(encoding="utf-8")
    rust_depth = int(
        re.search(r"MAX_REVOCATION_WITNESS_DEPTH:\s*u32\s*=\s*(\d+)", rust_src).group(1)  # type: ignore[union-attr]
    )
    rust_leaves = int(
        re.search(r"MAX_REVOCATION_LEAVES:\s*u32\s*=\s*([\d_]+)", rust_src)
        .group(1)  # type: ignore[union-attr]
        .replace("_", "")
    )

    ts_src = (ROOT / "frontend" / "src" / "verifierInputs.ts").read_text(encoding="utf-8")
    ts_depth = int(
        re.search(r"MAX_REVOCATION_WITNESS_DEPTH\s*=\s*(\d+)", ts_src).group(1)  # type: ignore[union-attr]
    )

    assert noir_depth == rust_depth == ts_depth == rd.MAX_REVOCATION_WITNESS_DEPTH
    assert noir_leaves == rust_leaves == rd.MAX_REVOCATION_LEAVES
