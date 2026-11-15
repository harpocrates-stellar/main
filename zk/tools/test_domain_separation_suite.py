"""Focused tests for `zk/tools/domain_separation_suite.py` (#1204)."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SUITE_PATH = REPO_ROOT / "zk" / "tools" / "domain_separation_suite.py"
VERIFIER_INPUTS_PATH = REPO_ROOT / "backend" / "verifier_inputs.py"
VECTOR_PATH = REPO_ROOT / "zk" / "vectors" / "domain_separation_compatibility_v1.json"

SYNTHETIC_PROOF_HEX = "ab" * 64


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


suite = _load_module("domain_separation_suite", SUITE_PATH)
verifier_inputs = _load_module("backend_verifier_inputs", VERIFIER_INPUTS_PATH)


def _extract_noir_hex_global(source: str, name: str) -> int:
    pattern = rf"global\s+{re.escape(name)}\s*:\s*(?:Field|u32)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;"
    match = re.search(pattern, source)
    assert match is not None, f"missing Noir global {name}"
    token = match.group(1)
    return int(token, 16) if token.startswith("0x") else int(token, 10)


class TestCommittedVectorCorpusAndCli:
    """Verify deterministic corpus generation, LF line endings, and `--check` mode."""

    def test_committed_vector_file_exists_and_uses_pure_lf(self) -> None:
        assert VECTOR_PATH.is_file()
        raw = VECTOR_PATH.read_bytes()
        assert b"\r" not in raw
        assert raw.endswith(b"\n")

    def test_cli_check_passes_against_committed_corpus(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = suite.main(["--check"])
        assert rc == suite.EXIT_OK
        out = json.loads(capsys.readouterr().out.strip())
        assert out == {
            "domain_tuples": 38,
            "event": "domain_separation.check.ok",
            "rejection_cases": 21,
        }

    def test_cli_write_and_recheck_roundtrip_matches_committed_bytes(
        self, tmp_path: Path
    ) -> None:
        out_file = tmp_path / "domain_separation_compatibility_v1.json"
        assert suite.main(["--output", str(out_file)]) == suite.EXIT_OK
        assert out_file.read_bytes() == VECTOR_PATH.read_bytes()
        assert suite.main(["--output", str(out_file), "--check"]) == suite.EXIT_OK

    def test_cli_check_fails_when_file_missing_or_tampered(
        self, tmp_path: Path
    ) -> None:
        missing = tmp_path / "missing.json"
        assert suite.main(["--output", str(missing), "--check"]) == suite.EXIT_CHECK_FAILED

        tampered = tmp_path / "tampered.json"
        payload = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        orig_hex = payload["domain_tuples"][0]["wire_domain_tag_hex"]
        flipped = ("0" if orig_hex[0] != "0" else "1") + orig_hex[1:]
        payload["domain_tuples"][0]["wire_domain_tag_hex"] = flipped
        tampered.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        assert suite.main(["--output", str(tampered), "--check"]) == suite.EXIT_CHECK_FAILED


class TestCrossLayerConstantSynchronization:
    """Ensure independently derived constants match Noir circuits and backend codec."""

    def test_matches_harpocrates_common_noir_globals(self) -> None:
        common_src = (
            REPO_ROOT / "zk" / "noir" / "harpocrates_common" / "src" / "lib.nr"
        ).read_text(encoding="utf-8")
        assert (
            _extract_noir_hex_global(common_src, "DIGEST_ALGORITHM_SHA256")
            == suite.DIGEST_ALGORITHM_SHA256
        )
        assert (
            _extract_noir_hex_global(common_src, "SCOPED_NULLIFIER_V1")
            == suite.SCOPED_NULLIFIER_SEPARATORS["v1"]
        )
        assert (
            _extract_noir_hex_global(common_src, "DOMAIN_PROTOCOL_FIELD").to_bytes(32, "big")
            == suite.PROTOCOL_FIELD_HARPOCRATES
        )
        assert (
            _extract_noir_hex_global(common_src, "DOMAIN_VERSION_FIELD").to_bytes(32, "big")
            == suite.VERSION_FIELD_V1
        )
        assert (
            _extract_noir_hex_global(common_src, "DOMAIN_NETWORK_FIELD").to_bytes(32, "big")
            == suite.NETWORK_FIELD_TESTNET
        )

    def test_matches_silent_witness_and_redacted_ancestry_noir_globals(self) -> None:
        sw_src = (
            REPO_ROOT / "zk" / "noir" / "silent_witness" / "src" / "main.nr"
        ).read_text(encoding="utf-8")
        assert _extract_noir_hex_global(sw_src, "CURRENT_CIRCUIT_VERSION") == 2

        ra_src = (
            REPO_ROOT / "zk" / "noir" / "redacted_ancestry" / "src" / "main.nr"
        ).read_text(encoding="utf-8")
        assert (
            _extract_noir_hex_global(ra_src, "OPERATION_REDACT")
            == suite.OPERATION_REDACT_FIELD
        )
        assert (
            _extract_noir_hex_global(ra_src, "DOMAIN_PARENT_COMMIT")
            == suite.REDACTED_ANCESTRY_SEPARATORS["parent_commit"]
        )
        assert (
            _extract_noir_hex_global(ra_src, "DOMAIN_REDACT_PARAMS")
            == suite.REDACTED_ANCESTRY_SEPARATORS["redact_params"]
        )
        assert (
            _extract_noir_hex_global(ra_src, "DOMAIN_DERIVATIVE")
            == suite.REDACTED_ANCESTRY_SEPARATORS["derivative"]
        )
        assert (
            _extract_noir_hex_global(ra_src, "DOMAIN_ANCESTRY")
            == suite.REDACTED_ANCESTRY_SEPARATORS["ancestry"]
        )
        assert (
            _extract_noir_hex_global(ra_src, "DOMAIN_NULLIFIER")
            == suite.REDACTED_ANCESTRY_SEPARATORS["nullifier"]
        )

    def test_matches_backend_verifier_inputs_constants(self) -> None:
        assert suite.BN254_SCALAR_MODULUS == verifier_inputs.BN254_SCALAR_FIELD_MODULUS
        assert (
            suite.REVOCATION_SEPARATORS["v1"]
            == verifier_inputs.REVOCATION_DOMAIN_SEPARATOR
        )
        active_tag = suite.derive_wire_domain_tag(
            suite.PROTOCOL_FIELD_HARPOCRATES,
            suite.VERSION_FIELD_V1,
            suite.NETWORK_FIELD_TESTNET,
        )
        assert active_tag == verifier_inputs.SILENT_WITNESS_DOMAIN_TAG


class TestBackendCodecAgreementOnPublishedVectors:
    """Verify `backend/verifier_inputs.py::classify` agrees with published vectors."""

    def test_active_deployment_tuples_accepted_and_non_active_rejected_by_backend(
        self,
    ) -> None:
        corpus = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        wire_schemas = {"silent_witness/v2", "silent_witness/v1", "revocation_witness/v1"}
        checked = 0
        for entry in corpus["domain_tuples"]:
            schema = entry["schema"]
            if schema not in wire_schemas:
                continue
            checked += 1
            code = verifier_inputs.classify(
                schema, entry["public_inputs_hex"], SYNTHETIC_PROOF_HEX
            )
            if entry["active_deployment"]:
                assert code is None, f"{entry['tuple_id']} rejected with {code}"
            else:
                assert code == "domain_mismatch", (
                    f"{entry['tuple_id']} expected domain_mismatch, got {code}"
                )
        assert checked == 32

    def test_wire_level_rejection_cases_match_backend_codec(self) -> None:
        corpus = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        # Cases targeting the active (harpocrates, v1, testnet) wire codec directly:
        wire_codes = {
            "domain_mismatch",
            "version_mismatch",
            "length",
            "non_canonical_field",
        }
        wire_schemas = {"silent_witness/v2", "silent_witness/v1", "revocation_witness/v1"}
        matched = 0
        for case in corpus["rejection_cases"]:
            target = case["target"]
            if (
                target["schema"] in wire_schemas
                and target["protocol"] == "harpocrates"
                and target["protocol_version"] == "v1"
                and target["network"] == "testnet"
                and case["expected_reject_code"] in wire_codes
            ):
                matched += 1
                actual = verifier_inputs.classify(
                    target["schema"], case["public_inputs_hex"], SYNTHETIC_PROOF_HEX
                )
                assert actual == case["expected_reject_code"], (
                    f"{case['id']}: expected {case['expected_reject_code']}, got {actual}"
                )
        assert matched >= 11


class TestCrossDomainRejectionMatrix:
    """Verify rejection across networks, verifier scopes, epochs, and protocol versions."""

    def test_all_supported_dimensions_covered_and_pairwise_disjoint(self) -> None:
        corpus = suite.generate_compatibility_corpus()
        assert suite.verify_corpus_invariants(corpus) == []

        tuples = corpus["domain_tuples"]
        networks = {t["network"] for t in tuples}
        versions = {t["protocol_version"] for t in tuples}
        scopes = {t["verifier_scope"] for t in tuples if t["schema"] == "silent_witness/v2"}
        schemas = {t["schema"] for t in tuples}

        assert networks == {"testnet", "mainnet", "local"}
        assert versions == {"v1", "v2"}
        assert scopes == set(suite.SUPPORTED_VERIFIER_SCOPES)
        assert schemas == {
            "silent_witness/v2",
            "silent_witness/v1",
            "revocation_witness/v1",
            "redacted_ancestry/v1",
        }

        # Every distinct (protocol_version, verifier_scope) in silent_witness/v2 must
        # produce a distinct scoped nullifier even for identical witness secrets + media.
        sw2_testnet = [
            t
            for t in tuples
            if t["schema"] == "silent_witness/v2" and t["network"] == "testnet"
        ]
        nullifiers = [t["nullifier_hex"] for t in sw2_testnet]
        assert len(nullifiers) == 8
        assert len(set(nullifiers)) == 8

    @pytest.mark.parametrize(
        ("src_net", "dst_net"),
        [
            ("testnet", "mainnet"),
            ("mainnet", "testnet"),
            ("local", "testnet"),
            ("testnet", "local"),
            ("local", "mainnet"),
            ("mainnet", "local"),
        ],
    )
    def test_cross_network_replay_rejected_for_all_network_pairs(
        self, src_net: str, dst_net: str
    ) -> None:
        src_ctx = suite.DomainContext(
            schema="silent_witness/v2",
            protocol="harpocrates",
            protocol_version="v1",
            network=src_net,
            circuit_version=2,
            verifier_scope="v:verifier-alpha:p:default",
            epoch=5,
        )
        dst_ctx = suite.DomainContext(
            schema="silent_witness/v2",
            protocol="harpocrates",
            protocol_version="v1",
            network=dst_net,
            circuit_version=2,
            verifier_scope="v:verifier-alpha:p:default",
            epoch=5,
        )
        stmt = suite.build_statement_for_context(src_ctx)
        verdict = suite.evaluate_domain_compatibility(
            stmt["public_inputs_hex"], target=dst_ctx
        )
        assert not verdict.accepted
        assert verdict.reject_code == "domain_mismatch"
        assert verdict.circuit_assert == "unsupported"

    def test_cross_scope_and_epoch_unmodified_and_spliced_reuse_rejected(self) -> None:
        alpha_ctx = suite.DomainContext(
            schema="silent_witness/v2",
            protocol="harpocrates",
            protocol_version="v1",
            network="testnet",
            circuit_version=2,
            verifier_scope="v:verifier-alpha:p:default",
            epoch=5,
        )
        beta_ctx = suite.DomainContext(
            schema="silent_witness/v2",
            protocol="harpocrates",
            protocol_version="v1",
            network="testnet",
            circuit_version=2,
            verifier_scope="v:verifier-beta:p:default",
            epoch=5,
        )
        next_epoch_ctx = suite.DomainContext(
            schema="silent_witness/v2",
            protocol="harpocrates",
            protocol_version="v1",
            network="testnet",
            circuit_version=2,
            verifier_scope="v:verifier-alpha:p:default",
            epoch=6,
        )

        alpha_stmt = suite.build_statement_for_context(alpha_ctx)

        # Unmodified scope replay -> scope_mismatch
        v_scope = suite.evaluate_domain_compatibility(
            alpha_stmt["public_inputs_hex"], target=beta_ctx
        )
        assert not v_scope.accepted
        assert v_scope.reject_code == "scope_mismatch"

        # Unmodified epoch replay -> epoch_mismatch
        v_epoch = suite.evaluate_domain_compatibility(
            alpha_stmt["public_inputs_hex"], target=next_epoch_ctx
        )
        assert not v_epoch.accepted
        assert v_epoch.reject_code == "epoch_mismatch"

        # Spliced scope field with alpha's nullifier -> circuit nullifier_binding_mismatch
        spliced_scope = suite._splice_field(
            alpha_stmt["public_inputs_hex"],
            4,
            suite.derive_scope_field_int("v:verifier-beta:p:default").to_bytes(32, "big"),
        )
        v_spliced = suite.evaluate_domain_compatibility(spliced_scope, target=beta_ctx)
        assert not v_spliced.accepted
        assert v_spliced.reject_code == "nullifier_binding_mismatch"
        assert v_spliced.circuit_assert == "malformed"

    def test_cross_protocol_version_spliced_domain_tag_still_fails_nullifier_binding(
        self,
    ) -> None:
        """Even if an attacker swaps `domain_tag` from v2 to v1, `SCOPED_NULLIFIER_V2` != `V1`."""
        v2_ctx = suite.DomainContext(
            schema="silent_witness/v2",
            protocol="harpocrates",
            protocol_version="v2",
            network="testnet",
            circuit_version=2,
            verifier_scope="v:verifier-alpha:p:default",
            epoch=5,
        )
        v1_ctx = suite.DomainContext(
            schema="silent_witness/v2",
            protocol="harpocrates",
            protocol_version="v1",
            network="testnet",
            circuit_version=2,
            verifier_scope="v:verifier-alpha:p:default",
            epoch=5,
        )
        v2_stmt = suite.build_statement_for_context(v2_ctx)
        v1_stmt = suite.build_statement_for_context(v1_ctx)

        spliced_v1_tag = suite._splice_field(
            v2_stmt["public_inputs_hex"],
            6,
            bytes.fromhex(v1_stmt["wire_domain_tag_hex"]),
        )
        verdict = suite.evaluate_domain_compatibility(spliced_v1_tag, target=v1_ctx)
        assert not verdict.accepted
        assert verdict.reject_code == "nullifier_binding_mismatch"
        assert verdict.circuit_assert == "malformed"


class TestBoundaryAndFailureCases:
    """Exercise framing, padding, zero-field, operation, hex, and schema boundaries."""

    def test_malformed_hex_padding_zero_field_and_unknown_schema(self) -> None:
        target = suite.DomainContext(
            schema="silent_witness/v2",
            protocol="harpocrates",
            protocol_version="v1",
            network="testnet",
            circuit_version=2,
            verifier_scope="0",
            epoch=0,
        )
        base = suite.build_statement_for_context(target)["public_inputs_hex"]

        assert (
            suite.evaluate_domain_compatibility("0xdeadbeef", target=target).reject_code
            == "malformed_hex"
        )
        assert (
            suite.evaluate_domain_compatibility("abc", target=target).reject_code
            == "malformed_hex"
        )

        # Non-zero upper 16 bytes on video_hash_hi -> padding
        bad_pad = suite._splice_field(base, 0, b"\x01" + (b"\x00" * 31))
        assert (
            suite.evaluate_domain_compatibility(bad_pad, target=target).reject_code
            == "padding"
        )

        # Zero credential_root -> zero_field
        zero_root = suite._splice_field(base, 2, b"\x00" * 32)
        assert (
            suite.evaluate_domain_compatibility(zero_root, target=target).reject_code
            == "zero_field"
        )

        # Unknown schema -> unknown_schema
        unknown_ctx = suite.DomainContext(
            schema="unknown_circuit/v99",
            protocol="harpocrates",
            protocol_version="v1",
            network="testnet",
            circuit_version=1,
        )
        assert (
            suite.evaluate_domain_compatibility(base, target=unknown_ctx).reject_code
            == "unknown_schema"
        )

    def test_redacted_ancestry_wrong_operation_and_tampered_nullifier(self) -> None:
        ra_ctx = suite.DomainContext(
            schema="redacted_ancestry/v1",
            protocol="harpocrates",
            protocol_version="v1",
            network="testnet",
            circuit_version=1,
        )
        ra_stmt = suite.build_statement_for_context(ra_ctx)

        wrong_op = suite._splice_field(
            ra_stmt["public_inputs_hex"],
            3,
            int.from_bytes(b"transcode", "big").to_bytes(32, "big"),
        )
        v_op = suite.evaluate_domain_compatibility(wrong_op, target=ra_ctx)
        assert not v_op.accepted
        assert v_op.reject_code == "operation_mismatch"
        assert v_op.circuit_assert == "operation must be redact"

        wrong_nullifier = suite._splice_field(
            ra_stmt["public_inputs_hex"],
            5,
            (999).to_bytes(32, "big"),
        )
        v_nul = suite.evaluate_domain_compatibility(wrong_nullifier, target=ra_ctx)
        assert not v_nul.accepted
        assert v_nul.reject_code == "nullifier_binding_mismatch"
        assert v_nul.circuit_assert == "nullifier mismatch"

    def test_helper_input_bounds_fail_closed(self) -> None:
        with pytest.raises(ValueError, match="fit in < 32 bytes"):
            suite._ascii_padded_field_bytes("A" * 32)
        with pytest.raises(ValueError, match="canonical BN254"):
            suite.pedersen_model_hash([suite.BN254_SCALAR_MODULUS])
        with pytest.raises(ValueError, match="fit in u32"):
            suite.encode_u32_trailer(-1)
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            suite.derive_wire_domain_tag(b"short", b"0" * 32, b"0" * 32)
        with pytest.raises(ValueError, match="Unsupported statement schema"):
            suite.build_statement_for_context(
                suite.DomainContext(
                    schema="nonexistent/v1",
                    protocol="harpocrates",
                    protocol_version="v1",
                    network="testnet",
                    circuit_version=1,
                )
            )


class TestPrivacyAndSyntheticWitnessHygiene:
    """Ensure published vector corpus never embeds raw witness secrets or host paths."""

    def test_vector_corpus_excludes_raw_witness_secrets_and_host_paths(self) -> None:
        text = VECTOR_PATH.read_text(encoding="utf-8")
        data = json.loads(text)

        forbidden_keys = {
            "credential_secret",
            "nullifier_secret",
            "parent_blinding",
            "redaction_seed",
        }
        for entry in data["domain_tuples"]:
            assert forbidden_keys.isdisjoint(entry.keys())

        assert "E:\\" not in text
        assert "/Users/" not in text
        assert "/home/" not in text
        assert '"12345"' not in text
        assert '"67890"' not in text
