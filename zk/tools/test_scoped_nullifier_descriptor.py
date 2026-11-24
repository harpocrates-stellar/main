"""Tests for the scoped-nullifier public/private statement descriptor."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import scoped_nullifier_descriptor as descriptor


REPO_ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR_PATH = (
    REPO_ROOT
    / "zk"
    / "noir"
    / "fixtures"
    / "scoped_nullifier_statement_descriptor_v1.json"
)


def test_descriptor_matches_main_and_helper_signatures() -> None:
    generated = descriptor.build_descriptor(REPO_ROOT)
    recorded = json.loads(DESCRIPTOR_PATH.read_text(encoding="utf-8"))

    assert descriptor.compare_descriptors(generated, recorded) == []
    assert [item["name"] for item in generated["main"]["private_inputs"]] == [
        "credential_secret",
        "nullifier_secret",
    ]
    assert generated["public_input_order"] == [
        "video_hash_hi",
        "video_hash_lo",
        "credential_root",
        "nullifier",
        "verifier_scope",
        "epoch",
        "domain_tag",
        "circuit_version",
    ]
    assert all(
        item["visibility"] == "private"
        for item in generated["helper"]["private_inputs"]
    )


def test_descriptor_digest_rejects_visibility_tampering() -> None:
    generated = descriptor.build_descriptor(REPO_ROOT)
    tampered = copy.deepcopy(generated)
    tampered["main"]["private_inputs"][0]["visibility"] = "public"

    findings = descriptor.compare_descriptors(generated, tampered)

    assert "descriptor digest is invalid" in findings
    assert "main public/private input list drifted" in findings


def test_descriptor_binds_reviewed_artifact_digests() -> None:
    generated = descriptor.build_descriptor(REPO_ROOT)
    tampered = copy.deepcopy(generated)
    tampered["reviewed_artifact_bindings"][0]["normalized_sha256"] = "0" * 64

    findings = descriptor.compare_descriptors(generated, tampered)

    assert "reviewed artifact bindings drifted" in findings