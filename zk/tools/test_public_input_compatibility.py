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


def test_layout_snapshot_rejects_breaking_change_without_version_bump() -> None:
    old_fields = ["video_hash_hi", "video_hash_lo", "domain_tag"]
    changed_fields = ["video_hash_hi", "domain_tag", "video_hash_lo"]
    before = {
        "layouts": {
            "silent_witness/v1": old_fields,
            "silent_witness/v2": old_fields,
        },
        "current_layout": old_fields,
        "circuit_version": 2,
    }
    after = {
        "layouts": {
            "silent_witness/v1": old_fields,
            "silent_witness/v2": changed_fields,
        },
        "current_layout": changed_fields,
        "circuit_version": 2,
    }

    findings = compatibility.compare_layout_snapshots(before, after)

    assert "silent_witness/v2: reviewed vector schema changed in place" in findings
    assert any("requires a circuit version greater than 2" in finding for finding in findings)


def test_layout_snapshot_accepts_new_version_and_preserved_history() -> None:
    old_fields = ["video_hash_hi", "video_hash_lo", "domain_tag"]
    new_fields = ["video_hash_hi", "domain_tag", "video_hash_lo", "circuit_version"]
    before = {
        "layouts": {
            "silent_witness/v1": old_fields,
            "silent_witness/v2": old_fields,
        },
        "current_layout": old_fields,
        "circuit_version": 2,
    }
    after = {
        "layouts": {
            "silent_witness/v1": old_fields,
            "silent_witness/v2": old_fields,
            "silent_witness/v3": new_fields,
        },
        "current_layout": new_fields,
        "circuit_version": 3,
    }

    assert compatibility.compare_layout_snapshots(before, after) == []


def test_layout_snapshot_rejects_descriptor_vector_mismatch() -> None:
    fields = ["video_hash_hi", "domain_tag", "video_hash_lo"]
    statement = {
        "id": "silent_witness/scoped-v2",
        "main": {
            "public_inputs": [
                {"name": name, "type": "Field", "visibility": "public"}
                for name in fields
            ]
        },
        "public_input_order": fields,
    }
    input_schema = {
        "public_frames": {"scoped_v2": fields},
        "artifact_abis": {"scoped_v2": {"circuit_version": 2}},
    }
    vectors = [
        {
            "schemas": {
                "silent_witness/v2": ["video_hash_hi", "video_hash_lo", "domain_tag"]
            }
        }
    ]

    _, findings = compatibility._snapshot_from_documents(
        statement, input_schema, vectors, circuit_version=2
    )

    assert any("does not match silent_witness/v2 vectors" in finding for finding in findings)


def test_layout_snapshot_keeps_older_versioned_vector_corpora() -> None:
    old_fields = ["video_hash_hi", "video_hash_lo", "domain_tag"]
    current_fields = old_fields + ["circuit_version"]
    statement = {
        "id": "silent_witness/scoped-v3",
        "main": {
            "public_inputs": [
                {"name": name, "type": "Field", "visibility": "public"}
                for name in current_fields
            ]
        },
        "public_input_order": current_fields,
    }
    input_schema = {
        "public_frames": {
            "unscoped_v1": old_fields,
            "scoped_v2": old_fields,
            "scoped_v3": current_fields,
        },
        "artifact_abis": {"scoped_v3": {"circuit_version": 3}},
    }
    vectors = [
        {"schemas": {"silent_witness/v1": old_fields}},
        {
            "schemas": {"silent_witness/v2": old_fields},
            "constants": {"expected_circuit_version": 2},
        },
        {
            "schemas": {"silent_witness/v3": current_fields},
            "constants": {"expected_circuit_version": 3},
        },
    ]

    _, findings = compatibility._snapshot_from_documents(
        statement, input_schema, vectors, circuit_version=3
    )

    assert findings == []


def test_circuit_interface_change_requires_version_increase() -> None:
    before = {
        "layouts": {"redacted_ancestry": [{"name": "domain_tag", "type": "Field"}]},
        "versions": {"redacted_ancestry": 1},
    }
    after = {
        "layouts": {
            "redacted_ancestry": [
                {"name": "circuit_version", "type": "Field"},
                {"name": "domain_tag", "type": "Field"},
            ]
        },
        "versions": {"redacted_ancestry": 1},
    }

    findings = compatibility.compare_circuit_interfaces(before, after)

    assert findings == [
        "redacted_ancestry: public-input layout changed without increasing "
        "the circuit version above 1"
    ]
    after["versions"]["redacted_ancestry"] = 2
    assert compatibility.compare_circuit_interfaces(before, after) == []