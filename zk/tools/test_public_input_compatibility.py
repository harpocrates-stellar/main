"""Tests for the cross-circuit public-input compatibility report."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import public_input_compatibility as compatibility


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_report_accepts_reviewed_baseline() -> None:
    report = compatibility.build_report(REPO_ROOT)

    assert report["errors"] == []
    statuses = {item["field"]: item["status"] for item in report["sharedEncodings"]}
    assert statuses["video_hash_hi"] == "identical"
    assert statuses["domain_tag"] == "identical"
    assert statuses["credential_root"] == "reviewed-difference"
    assert statuses["nullifier"] == "reviewed-difference"


def test_report_rejects_unreviewed_encoding_change() -> None:
    circuit_specs = deepcopy(compatibility.CIRCUITS)
    circuit_specs["selective_disclosure"]["encodings"]["credential_root"] = (
        "unexpected encoding"
    )

    report = compatibility.build_report(REPO_ROOT, circuit_specs=circuit_specs)

    assert any(
        "credential_root: unreviewed encoding difference" in error
        for error in report["errors"]
    )


def test_report_rejects_public_input_order_drift() -> None:
    circuit_specs = deepcopy(compatibility.CIRCUITS)
    circuit_specs["silent_witness"]["public_inputs"].reverse()

    report = compatibility.build_report(REPO_ROOT, circuit_specs=circuit_specs)

    assert any(
        "silent_witness: public-input order drift" in error
        for error in report["errors"]
    )