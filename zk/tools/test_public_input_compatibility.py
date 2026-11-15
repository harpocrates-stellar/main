"""Tests for cross-circuit public-input compatibility reporting (#1213)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from zk.tools.public_input_compatibility import (
    DEFAULT_POLICY_PATH,
    EXIT_INCOMPATIBLE,
    EXIT_INVALID_INPUT,
    EXIT_OK,
    MAX_POLICY_BYTES,
    REPO_ROOT,
    TARGET_CIRCUITS,
    CompatibilityErrorCode,
    CompatibilityReportError,
    extract_circuit_profile,
    format_markdown_report,
    generate_compatibility_report,
    load_compatibility_policy,
    main,
)


def _stage_minimal_repo(tmp_path: Path) -> Path:
    """Copy only the circuit sources, policy, and codec needed for isolated tests."""
    rel_files = (
        "zk/noir/harpocrates_common/src/lib.nr",
        "zk/noir/silent_witness/src/main.nr",
        "zk/noir/redacted_ancestry/src/main.nr",
        "zk/noir/selective_disclosure/src/main.nr",
        "zk/noir/public_input_compatibility_v1.json",
        "backend/verifier_inputs.py",
    )
    for rel in rel_files:
        src = REPO_ROOT / rel
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    return tmp_path


def test_committed_cross_circuit_report_passes() -> None:
    report = generate_compatibility_report(
        repo_root=REPO_ROOT,
        policy_path=DEFAULT_POLICY_PATH,
    )
    assert report["ok"] is True
    assert report["normalization_policy"] == "forbid_silent_normalization"
    assert report["summary"]["circuits_checked"] == 3
    assert report["summary"]["unreviewed_difference_count"] == 0
    assert report["summary"]["drifted_review_count"] == 0
    assert report["summary"]["frame_drift_count"] == 0
    assert report["summary"]["compatible_count"] >= 3
    assert report["summary"]["reviewed_difference_count"] == 30


def test_circuit_profiles_match_exact_public_frames() -> None:
    sw = extract_circuit_profile("silent_witness", repo_root=REPO_ROOT)
    ra = extract_circuit_profile("redacted_ancestry", repo_root=REPO_ROOT)
    sd = extract_circuit_profile("selective_disclosure", repo_root=REPO_ROOT)

    assert sw.version_constant == "CURRENT_CIRCUIT_VERSION:u32=2"
    assert sw.public_frame_bytes == 256
    assert sw.public_field_names == (
        "video_hash_hi",
        "video_hash_lo",
        "credential_root",
        "nullifier",
        "verifier_scope",
        "epoch",
        "domain_tag",
        "circuit_version",
    )

    assert ra.version_constant == "CIRCUIT_VERSION:Field=1"
    assert ra.public_frame_bytes == 256
    assert ra.public_field_names == (
        "parent_commitment",
        "derivative_digest",
        "parameters_digest",
        "operation_type",
        "ancestry_root",
        "nullifier",
        "depth",
        "domain_tag",
    )

    assert sd.version_constant == "CURRENT_CIRCUIT_VERSION:u32=1"
    assert sd.public_frame_bytes == 352
    assert sd.public_field_names == (
        "schema_hash",
        "issuer_namespace",
        "schema_version",
        "credential_root",
        "nullifier",
        "video_hash_hi",
        "video_hash_lo",
        "verifier_digest",
        "circuit_version",
        "evidence_digest",
        "predicate_commitment",
    )


def test_shared_and_pairwise_encodings_reported_accurately() -> None:
    report = generate_compatibility_report(repo_root=REPO_ROOT)
    three_way = {
        (item["concept"], item["dimension"]): item["shared_encoding"]
        for item in report["compatible_encodings"]
    }
    assert three_way[("nullifier", "exposure")] == "public"
    assert three_way[("nullifier", "declaration")] == "nullifier:Field"
    assert three_way[("nullifier", "wire_encoding")] == "bn254_field_be32"

    pairwise = {
        (item["concept"], item["dimension"], tuple(item["circuits"])): item[
            "shared_encoding"
        ]
        for item in report["pairwise_shared_encodings"]
    }
    assert (
        pairwise[
            (
                "domain_separation",
                "circuit_derivation",
                ("silent_witness", "redacted_ancestry"),
            )
        ]
        == "pedersen([DOMAIN_PROTOCOL_FIELD,DOMAIN_VERSION_FIELD,DOMAIN_NETWORK_FIELD])"
    )
    assert (
        pairwise[
            (
                "credential_root",
                "declaration",
                ("silent_witness", "selective_disclosure"),
            )
        ]
        == "credential_root:Field"
    )


def test_unreviewed_difference_fails_closed(tmp_path: Path) -> None:
    staged = _stage_minimal_repo(tmp_path)
    policy_file = staged / "zk/noir/public_input_compatibility_v1.json"
    policy = json.loads(policy_file.read_text(encoding="utf-8"))
    # Drop one reviewed difference (nullifier slot_index)
    policy["reviewed_differences"] = [
        entry
        for entry in policy["reviewed_differences"]
        if not (
            entry["concept"] == "nullifier" and entry["dimension"] == "slot_index"
        )
    ]
    policy_file.write_text(json.dumps(policy, indent=2), encoding="utf-8")

    report = generate_compatibility_report(repo_root=staged, policy_path=policy_file)
    assert report["ok"] is False
    assert report["summary"]["unreviewed_difference_count"] == 1
    assert report["unreviewed_differences"][0]["concept"] == "nullifier"
    assert report["unreviewed_differences"][0]["dimension"] == "slot_index"

    rc = main(["--repo-root", str(staged), "--policy", str(policy_file), "--check"])
    assert rc == EXIT_INCOMPATIBLE


def test_no_silent_type_or_constant_normalization(tmp_path: Path) -> None:
    staged = _stage_minimal_repo(tmp_path)
    ra_main = staged / "zk/noir/redacted_ancestry/src/main.nr"
    original = ra_main.read_text(encoding="utf-8")
    # Change `global CIRCUIT_VERSION: Field = 1;` to `u32`: must NOT be silently normalized!
    mutated = original.replace(
        "global CIRCUIT_VERSION: Field = 1;",
        "global CIRCUIT_VERSION: u32 = 1;",
        1,
    )
    assert mutated != original
    ra_main.write_text(mutated, encoding="utf-8")

    report = generate_compatibility_report(repo_root=staged)
    assert report["ok"] is False
    assert report["summary"]["drifted_review_count"] == 1
    drift = report["drifted_reviews"][0]
    assert drift["concept"] == "circuit_version"
    assert drift["dimension"] == "version_constant"
    assert drift["reason"] == "reviewed_observation_drift"


def test_public_slot_reorder_and_new_shared_field_fail_closed(tmp_path: Path) -> None:
    staged = _stage_minimal_repo(tmp_path)
    ra_main = staged / "zk/noir/redacted_ancestry/src/main.nr"
    policy_file = staged / "zk/noir/public_input_compatibility_v1.json"

    # Append a new shared public parameter `epoch: pub Field` to redacted_ancestry.
    src = ra_main.read_text(encoding="utf-8")
    ra_main.write_text(
        src.replace(
            "domain_tag: pub Field,",
            "domain_tag: pub Field,\n    epoch: pub Field,",
            1,
        ),
        encoding="utf-8",
    )

    # First, without updating circuit_frames, frame_drift + unreviewed_differences trigger.
    report_before_frame = generate_compatibility_report(repo_root=staged)
    assert report_before_frame["ok"] is False
    assert report_before_frame["summary"]["frame_drift_count"] == 1
    assert report_before_frame["summary"]["unreviewed_difference_count"] >= 1

    # Even if circuit_frames is updated, the new cross-circuit `shared_field:epoch`
    # difference between silent_witness, redacted_ancestry, and selective_disclosure
    # remains unreviewed and fails closed!
    policy = json.loads(policy_file.read_text(encoding="utf-8"))
    policy["circuit_frames"]["redacted_ancestry"]["public_fields"].append("epoch")
    policy_file.write_text(json.dumps(policy, indent=2), encoding="utf-8")

    report_after_frame = generate_compatibility_report(repo_root=staged)
    assert report_after_frame["ok"] is False
    concepts = {u["concept"] for u in report_after_frame["unreviewed_differences"]}
    assert "shared_field:epoch" in concepts


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (
            lambda p: p.update({"normalize": True}),
            CompatibilityErrorCode.SILENT_NORMALIZATION_FORBIDDEN,
        ),
        (
            lambda p: p.update({"normalization_policy": "allow_silent_coercion"}),
            CompatibilityErrorCode.SILENT_NORMALIZATION_FORBIDDEN,
        ),
        (
            lambda p: p["reviewed_differences"][0].update({"status": "normalized"}),
            CompatibilityErrorCode.SILENT_NORMALIZATION_FORBIDDEN,
        ),
        (
            lambda p: p["reviewed_differences"][0].update({"status": "pending"}),
            CompatibilityErrorCode.INVALID_REVIEW_RECORD,
        ),
        (
            lambda p: p["reviewed_differences"][0].update({"rationale": "short"}),
            CompatibilityErrorCode.INVALID_REVIEW_RECORD,
        ),
        (
            lambda p: p["reviewed_differences"][0]["observed"].update(
                {"silent_witness": "*"}
            ),
            CompatibilityErrorCode.INVALID_REVIEW_RECORD,
        ),
    ],
)
def test_policy_rejects_silent_normalization_and_incomplete_reviews(
    tmp_path: Path,
    mutator: object,
    expected_code: CompatibilityErrorCode,
) -> None:
    policy_data = json.loads(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))
    assert callable(mutator)
    mutator(policy_data)
    bad_policy = tmp_path / "bad_policy.json"
    bad_policy.write_text(json.dumps(policy_data), encoding="utf-8")

    with pytest.raises(CompatibilityReportError) as exc_info:
        load_compatibility_policy(bad_policy, repo_root=tmp_path)
    assert exc_info.value.code == expected_code

    rc = main(["--repo-root", str(REPO_ROOT), "--policy", str(bad_policy), "--check"])
    assert rc == EXIT_INVALID_INPUT


def test_orphaned_review_entry_fails_closed(tmp_path: Path) -> None:
    staged = _stage_minimal_repo(tmp_path)
    policy_file = staged / "zk/noir/public_input_compatibility_v1.json"
    policy = json.loads(policy_file.read_text(encoding="utf-8"))
    policy["reviewed_differences"].append(
        {
            "difference_id": "ccpi-diff-999-orphaned",
            "concept": "nonexistent_concept",
            "dimension": "encoding",
            "observed": {c: f"enc_{c}" for c in TARGET_CIRCUITS},
            "status": "reviewed",
            "rationale": "Synthetic orphaned review entry to verify stale policy detection.",
            "reviewer_ref": "docs/zk-conformance-vectors.md",
        }
    )
    policy_file.write_text(json.dumps(policy, indent=2), encoding="utf-8")

    report = generate_compatibility_report(repo_root=staged, policy_path=policy_file)
    assert report["ok"] is False
    assert any(
        item["reason"] == "orphaned_review_entry" for item in report["drifted_reviews"]
    )


def test_oversized_and_malformed_inputs_are_privacy_safe(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    oversized = tmp_path / "oversized_policy.json"
    oversized.write_bytes(b"{" + (b" " * (MAX_POLICY_BYTES + 16)) + b"}")

    rc = main(["--repo-root", str(REPO_ROOT), "--policy", str(oversized), "--check"])
    assert rc == EXIT_INVALID_INPUT
    captured = capsys.readouterr()
    signal = json.loads(captured.err.strip())
    assert signal["error_code"] == CompatibilityErrorCode.OVERSIZED_INPUT.value

    staged = _stage_minimal_repo(tmp_path / "malformed_repo")
    secret_canary = "SUPER_SECRET_WITNESS_VALUE_987654321"
    sw_main = staged / "zk/noir/silent_witness/src/main.nr"
    sw_main.write_text(
        f"// broken source without main {secret_canary}\nglobal X: Field = 1;\n",
        encoding="utf-8",
    )

    rc_bad = main(["--repo-root", str(staged), "--check"])
    assert rc_bad == EXIT_INVALID_INPUT
    captured_bad = capsys.readouterr()
    assert secret_canary not in captured_bad.err
    assert secret_canary not in captured_bad.out


def test_cli_markdown_and_json_output_files(tmp_path: Path) -> None:
    md_out = tmp_path / "report.md"
    json_out = tmp_path / "report.json"

    assert (
        main(["--format", "markdown", "--output", str(md_out), "--check"]) == EXIT_OK
    )
    assert main(["--format", "json", "--output", str(json_out), "--check"]) == EXIT_OK

    md_text = md_out.read_text(encoding="utf-8")
    parsed_json = json.loads(json_out.read_text(encoding="utf-8"))
    assert "# Cross-Circuit Public-Input Compatibility Report" in md_text
    assert "- **Status:** `PASS`" in md_text
    assert format_markdown_report(parsed_json) == md_text
