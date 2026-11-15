from __future__ import annotations

import json
import socket
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from c2pa import C2paTrustStatus, evaluate_c2pa_ingredient, export_c2pa_manifest
from lineage import (
    DEFAULT_INTEROP_CORPUS_PATH,
    LineageValidationError,
    evaluate_interoperability_case,
    load_interoperability_corpus,
    run_interoperability_corpus,
)


class OfflineC2paLineageCorpusTests(unittest.TestCase):
    def _block_network(self):
        def _deny(*_args, **_kwargs):
            raise AssertionError("offline interoperability corpus must never access network")

        return (
            patch.object(socket, "socket", side_effect=_deny),
            patch.object(socket, "create_connection", side_effect=_deny),
            patch.object(urllib.request, "urlopen", side_effect=_deny),
        )

    def test_corpus_runs_completely_offline_with_expected_results(self) -> None:
        p1, p2, p3 = self._block_network()
        with p1, p2, p3:
            summary = run_interoperability_corpus()

        self.assertEqual(summary["corpus_version"], 1)
        self.assertGreaterEqual(summary["total_cases"], 6)
        self.assertEqual(summary["passed_cases"], summary["total_cases"])
        self.assertTrue(summary["all_passed"], msg=json.dumps(summary, indent=2))

        for entry in summary["results"]:
            self.assertTrue(entry["matched_expected"], msg=entry["case_id"])
            self.assertNotEqual(
                entry["actual"]["c2pa_trust_status"],
                "confirmed",
                "C2PA trust status must remain distinct from on-chain confirmation",
            )

    def test_corpus_results_are_byte_for_byte_deterministic(self) -> None:
        first = json.dumps(run_interoperability_corpus(), sort_keys=True)
        second = json.dumps(run_interoperability_corpus(), sort_keys=True)
        self.assertEqual(first, second)

    def test_mixed_ingredients_separate_supported_and_unsupported_deterministically(self) -> None:
        corpus = load_interoperability_corpus()
        mixed_case = next(
            c for c in corpus["cases"]
            if c["case_id"] == "mixed_supported_and_unsupported_ingredients"
        )
        result = evaluate_interoperability_case(mixed_case)

        self.assertTrue(result["ok"])
        self.assertEqual(result["supported_ingredient_count"], 2)
        self.assertEqual(result["unsupported_ingredient_count"], 3)
        self.assertEqual(
            result["unsupported_reasons"],
            [
                "missing_harpocrates_binding",
                "unsupported_algorithm",
                "external_reference_not_fetched",
            ],
        )
        supported_ids = [
            item["ingredient_id"] for item in result["ingredients"] if item["supported"]
        ]
        self.assertEqual(supported_ids, ["ing-parent-a", "ing-parent-b"])

    def test_corpus_contains_no_network_urls_or_sensitive_media_references(self) -> None:
        raw_text = DEFAULT_INTEROP_CORPUS_PATH.read_text(encoding="utf-8")
        self.assertNotIn("http://", raw_text)
        self.assertNotIn("https://", raw_text)
        for forbidden_ext in (".mp4", ".mov", ".avi", ".mkv", ".jpg", ".png", ".wav"):
            self.assertNotIn(forbidden_ext, raw_text.lower())

    def test_ingredient_evaluator_sanitizes_unsafe_paths_and_blocks_remote_urls(self) -> None:
        unsafe_path = "/Users/journalist/Desktop/private_interview_clip"
        ev = evaluate_c2pa_ingredient(
            {
                "ingredient_id": unsafe_path,
                "remote_url": "https://cdn.example.invalid/manifest.c2pa",
            },
            index=4,
        )
        self.assertFalse(ev.supported)
        self.assertEqual(ev.ingredient_id, "ingredient[4]")
        self.assertEqual(ev.reason, "external_reference_not_fetched")
        self.assertEqual(ev.trust_status, C2paTrustStatus.PARSE_FAILED)
        serialized = json.dumps(ev.to_dict())
        self.assertNotIn("journalist", serialized)
        self.assertNotIn("https://", serialized)

    def test_output_binding_mismatch_between_c2pa_and_lineage_is_detected(self) -> None:
        parent_exp = export_c2pa_manifest(
            video_hash="11" * 32,
            metadata_hash="12" * 32,
            proof_id="a1" * 32,
            tier="source",
            network="testnet",
            contract_id="CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ",
        )
        deriv_exp = export_c2pa_manifest(
            video_hash="31" * 32,
            metadata_hash="32" * 32,
            proof_id="c3" * 32,
            tier="source",
            network="testnet",
            contract_id="CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ",
        )
        case = {
            "case_id": "mismatched_output_digest",
            "c2pa_manifest": deriv_exp.manifest,
            "ingredients": [{"ingredient_id": "ing-0", "manifest": parent_exp.manifest}],
            "lineage_manifest": {
                "parentProofIds": ["a1" * 32],
                "operationType": "crop",
                "parametersDigest": "41" * 32,
                "toolIdentity": "harpocrates-studio",
                "toolVersion": "1.0.0",
                "outputDigest": "99" * 32,
                "network": "testnet",
                "actorAddress": "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ",
            },
        }
        result = evaluate_interoperability_case(case)
        self.assertFalse(result["ok"])
        self.assertEqual(result["lineage_status"], "output_binding_mismatch")

    def test_corpus_loader_rejects_non_offline_or_duplicate_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad_offline = Path(tmp) / "non_offline.json"
            bad_offline.write_text(
                json.dumps(
                    {
                        "corpus_version": 1,
                        "offline_only": False,
                        "cases": [{"case_id": "a"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(LineageValidationError):
                load_interoperability_corpus(bad_offline)

            dup_ids = Path(tmp) / "dup.json"
            dup_ids.write_text(
                json.dumps(
                    {
                        "corpus_version": 1,
                        "offline_only": True,
                        "cases": [{"case_id": "dup"}, {"case_id": "dup"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(LineageValidationError):
                load_interoperability_corpus(dup_ids)


if __name__ == "__main__":
    unittest.main()
