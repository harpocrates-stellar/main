from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import nullifier_migration as nm


def test_noir_common_constants_match_migration_tool() -> None:
    lib_nr = (REPO_ROOT / "zk" / "noir" / "harpocrates_common" / "src" / "lib.nr").read_text(
        encoding="utf-8"
    )
    algo_match = re.search(r"DIGEST_ALGORITHM_SHA256:\s*Field\s*=\s*(\d+);", lib_nr)
    sep_match = re.search(
        r"SCOPED_NULLIFIER_V1:\s*Field\s*=\s*0x([0-9a-fA-F]+);",
        lib_nr,
    )
    assert algo_match is not None
    assert sep_match is not None
    assert int(algo_match.group(1), 10) == nm.DIGEST_ALGORITHM_SHA256
    assert int(sep_match.group(1), 16) == nm.SCOPED_NULLIFIER_V1


def test_legacy_unscoped_to_verifier_scoped_reduces_linkability_and_cuts_over() -> None:
    report = nm.analyze_policy_migration(
        "legacy_unscoped_v1",
        "verifier_scoped_v1",
        identity_count=3,
        video_count=2,
        scopes=("0", "v:verifier-a:p:default", "v:verifier-b:p:default"),
        epochs=(0, 1),
    )

    assert report["synthetic_only"] is True
    link = report["linkability"]
    replay = report["replay_boundaries"]

    assert link["old_cross_scope_nullifier_linkability_rate"] == 1.0
    assert link["new_cross_scope_nullifier_linkability_rate"] == 0.0
    assert link["old_cross_epoch_nullifier_linkability_rate"] == 1.0
    assert link["new_cross_epoch_nullifier_linkability_rate"] == 0.0
    assert link["cross_policy_exact_match_count"] == 0
    assert link["cross_policy_shared_nullifier_set_size"] == 0
    assert link["credential_root_persistent_linkability"] is True
    assert link["nullifier_linkability_delta"] == "reduced"

    assert replay["same_context_replay_blocked"] is True
    assert replay["old_cross_scope_distinct_nullifiers"] is False
    assert replay["new_cross_scope_distinct_nullifiers"] is True
    assert replay["old_epoch_rotation_allows_fresh_nullifier"] is False
    assert replay["new_epoch_rotation_allows_fresh_nullifier"] is True
    assert replay["transition_dual_registration_possible"] is True
    assert replay["isolation_regression"] is False
    assert replay["migration_classification"] == "disjoint_nullifier_cutover"
    assert "enforce_circuit_or_domain_cutover_boundary" in replay["required_safeguards"]


def test_global_scoped_to_verifier_scoped_detects_global_anchor_overlap() -> None:
    report = nm.analyze_policy_migration(
        "global_scoped_v1",
        "verifier_scoped_v1",
        identity_count=3,
        video_count=2,
        scopes=("0", "v:verifier-a:p:default", "v:verifier-b:p:default"),
        epochs=(0, 1),
    )

    link = report["linkability"]
    replay = report["replay_boundaries"]

    # Exactly (scope="0", epoch=0) matches across all 3 * 2 = 6 (identity, video) pairs.
    assert link["cross_policy_exact_match_count"] == 6
    assert replay["overlapping_cutover_contexts"] == [{"scope": "0", "epoch": 0}]
    assert replay["migration_classification"] == "partial_overlap_anchor_transition"
    assert (
        "preserve_overlapping_global_anchor_nullifiers_across_cutover"
        in replay["required_safeguards"]
    )


def test_purpose_collapsed_to_verifier_scoped_separates_purposes_same_verifier() -> None:
    report = nm.analyze_policy_migration(
        "purpose_collapsed_v1",
        "verifier_scoped_v1",
        identity_count=2,
        video_count=2,
        scopes=(
            "v:verifier-alpha:p:default",
            "v:verifier-alpha:p:audit",
            "v:verifier-beta:p:default",
        ),
        epochs=(0, 1),
    )

    link = report["linkability"]
    replay = report["replay_boundaries"]

    assert link["old_cross_scope_collision_pairs"] > 0
    assert link["new_cross_scope_collision_pairs"] == 0
    assert link["nullifier_linkability_delta"] == "reduced"
    assert replay["isolation_regression"] is False
    assert replay["overlapping_cutover_contexts"] == [
        {"scope": "v:verifier-alpha:p:default", "epoch": 0},
        {"scope": "v:verifier-alpha:p:default", "epoch": 1},
        {"scope": "v:verifier-beta:p:default", "epoch": 0},
        {"scope": "v:verifier-beta:p:default", "epoch": 1},
    ]


def test_verifier_scoped_v1_to_v2_rotates_domain_without_overlap() -> None:
    report = nm.analyze_policy_migration(
        "verifier_scoped_v1",
        "verifier_scoped_v2",
        identity_count=2,
        video_count=2,
    )

    link = report["linkability"]
    replay = report["replay_boundaries"]

    assert link["old_cross_scope_nullifier_linkability_rate"] == 0.0
    assert link["new_cross_scope_nullifier_linkability_rate"] == 0.0
    assert link["cross_policy_exact_match_count"] == 0
    assert link["cross_policy_shared_nullifier_set_size"] == 0
    assert link["nullifier_linkability_delta"] == "unchanged"
    assert replay["isolation_regression"] is False
    assert replay["migration_classification"] == "disjoint_nullifier_cutover"


def test_identical_policy_is_classified_as_noop() -> None:
    report = nm.analyze_policy_migration(
        "verifier_scoped_v1",
        "verifier_scoped_v1",
        identity_count=2,
        video_count=2,
    )

    assert report["linkability"]["cross_policy_exact_match_rate"] == 1.0
    assert report["replay_boundaries"]["transition_dual_registration_possible"] is False
    assert report["replay_boundaries"]["isolation_regression"] is False
    assert report["replay_boundaries"]["migration_classification"] == "noop_identical_policy"


@pytest.mark.parametrize(
    ("old_pol", "new_pol"),
    [
        ("verifier_scoped_v1", "legacy_unscoped_v1"),
        ("verifier_scoped_v1", "global_scoped_v1"),
        ("verifier_scoped_v1", "scope_only_v1"),
        ("verifier_scoped_v1", "purpose_collapsed_v1"),
    ],
)
def test_downgrade_migrations_flag_isolation_regression(
    old_pol: str,
    new_pol: str,
) -> None:
    report = nm.analyze_policy_migration(old_pol, new_pol, identity_count=2, video_count=2)
    assert report["linkability"]["nullifier_linkability_delta"] == "increased"
    assert report["replay_boundaries"]["isolation_regression"] is True
    assert (
        report["replay_boundaries"]["migration_classification"]
        == "regression_weakens_isolation"
    )


def test_report_never_serializes_synthetic_secret_scalars() -> None:
    identities, _ = nm.derive_synthetic_cohort(
        cohort_label="synthetic-audit",
        identity_count=3,
        video_count=2,
    )
    report = nm.analyze_policy_migration(
        "legacy_unscoped_v1",
        "verifier_scoped_v1",
        cohort_label="synthetic-audit",
        identity_count=3,
        video_count=2,
    )
    serialized = json.dumps(report)
    for identity in identities:
        assert str(identity.credential_secret) not in serialized
        assert str(identity.nullifier_secret) not in serialized
        assert hex(identity.credential_secret) not in serialized
        assert hex(identity.nullifier_secret) not in serialized


@pytest.mark.parametrize(
    "forbidden_value",
    [
        "S" + "A" * 55,
        "0x" + "ab" * 32,
        "cd" * 32,
        "-----BEGIN PRIVATE KEY-----",
        "zk/noir/silent_witness/Prover.toml",
        ".env.production",
    ],
)
def test_secret_shaped_inputs_rejected_without_echoing_value(
    forbidden_value: str,
) -> None:
    with pytest.raises(nm.MigrationInputError) as exc_info:
        nm.validate_cohort_label(forbidden_value)
    assert exc_info.value.code == "secret_import_forbidden"
    assert forbidden_value not in exc_info.value.message


def test_scenario_mapping_rejects_secret_keys_without_echoing_secret() -> None:
    synthetic_test_token = "S" + "B" * 55
    bad_scenario = {
        "policies": {},
        "witness_override": {
            "credential_secret": synthetic_test_token,
        },
    }
    with pytest.raises(nm.MigrationInputError) as exc_info:
        nm.parse_custom_policies_from_scenario(bad_scenario)
    assert exc_info.value.code == "secret_import_forbidden"
    assert synthetic_test_token not in exc_info.value.message


def test_cli_refuses_prover_toml_or_dotenv_scenario_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    prover_toml = tmp_path / "Prover.toml"
    prover_toml.write_text('credential_secret = "12345"\n', encoding="utf-8")

    rc = nm.main(
        [
            "--old-policy",
            "legacy_unscoped_v1",
            "--new-policy",
            "verifier_scoped_v1",
            "--scenario-file",
            str(prover_toml),
            "--json",
        ]
    )
    assert rc == nm.EXIT_INVALID_INPUT
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "secret_import_forbidden"
    assert "12345" not in json.dumps(payload)


def test_boundary_validation_for_cohort_scopes_and_epochs() -> None:
    with pytest.raises(nm.MigrationInputError) as exc_bounds:
        nm.derive_synthetic_cohort(identity_count=0, video_count=2)
    assert exc_bounds.value.code == "invalid_cohort_bounds"

    with pytest.raises(nm.MigrationInputError) as exc_upper:
        nm.derive_synthetic_cohort(
            identity_count=nm.MAX_SYNTHETIC_IDENTITIES + 1,
            video_count=1,
        )
    assert exc_upper.value.code == "invalid_cohort_bounds"

    with pytest.raises(nm.MigrationInputError) as exc_scope:
        nm.analyze_policy_migration(
            "legacy_unscoped_v1",
            "verifier_scoped_v1",
            scopes=("v:UppercaseVerifier:p:default",),
        )
    assert exc_scope.value.code == "noncanonical_scope"

    with pytest.raises(nm.MigrationInputError) as exc_dup_scope:
        nm.analyze_policy_migration(
            "legacy_unscoped_v1",
            "verifier_scoped_v1",
            scopes=("0", "0"),
        )
    assert exc_dup_scope.value.code == "duplicate_scope"

    with pytest.raises(nm.MigrationInputError) as exc_epoch:
        nm.analyze_policy_migration(
            "legacy_unscoped_v1",
            "verifier_scoped_v1",
            epochs=(-1,),
        )
    assert exc_epoch.value.code == "invalid_epoch"


def test_cli_custom_scenario_json_and_fail_on_regression(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scenario_path = tmp_path / "synthetic_policies.json"
    scenario_path.write_text(
        json.dumps(
            {
                "policies": {
                    "scoped-v3-candidate": {
                        "description": "Candidate v3 domain separator",
                        "domain_separator_label": "HARPOCRATES_SCOPED_NULLIFIER_V3",
                        "bind_verifier_scope": True,
                        "bind_epoch": True,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    rc_ok = nm.main(
        [
            "--old-policy",
            "verifier_scoped_v1",
            "--new-policy",
            "scoped-v3-candidate",
            "--scenario-file",
            str(scenario_path),
            "--identities",
            "2",
            "--videos",
            "2",
            "--fail-on-regression",
            "--json",
        ]
    )
    assert rc_ok == nm.EXIT_OK
    out_ok = json.loads(capsys.readouterr().out)
    assert out_ok["policies"]["new"]["name"] == "scoped-v3-candidate"
    assert out_ok["linkability"]["cross_policy_exact_match_count"] == 0

    rc_reg = nm.main(
        [
            "--old-policy",
            "verifier_scoped_v1",
            "--new-policy",
            "legacy_unscoped_v1",
            "--identities",
            "2",
            "--videos",
            "2",
            "--fail-on-regression",
        ]
    )
    assert rc_reg == nm.EXIT_POLICY_REGRESSION
    text_out = capsys.readouterr().out
    assert "Migration classification: regression_weakens_isolation" in text_out
