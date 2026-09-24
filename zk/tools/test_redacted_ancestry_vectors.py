"""Schema guards for redacted_ancestry synthetic vectors (#356).

These tests do not execute Noir. They keep the fixture corpus versioned,
privacy-safe, and aligned with lineage operation codes so CI can catch drift
without the nargo toolchain.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[1] / "noir" / "fixtures" / "redacted_ancestry_vectors.json"

FORBIDDEN_KEYS = {
    "credential_secret_hex",
    "private_key",
    "witness_bytes",
    "proof_hex",
    "real_media",
}


class RedactedAncestryVectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with VECTORS.open(encoding="utf-8") as fh:
            cls.data = json.load(fh)

    def test_versioned_circuit_id(self) -> None:
        self.assertEqual(self.data["_circuit"], "redacted_ancestry/v1")
        self.assertEqual(self.data["_version"], "1.0.0")
        self.assertEqual(self.data["_max_ancestry_depth"], 4)
        self.assertEqual(self.data["_operation_codes"]["redact"], 3)

    def test_positive_and_negative_corpus(self) -> None:
        positives = self.data["positive_cases"]
        negatives = self.data["negative_cases"]
        self.assertGreaterEqual(len(positives), 2)
        self.assertGreaterEqual(len(negatives), 8)
        for case in positives:
            self.assertEqual(case["expect"], "pass")
            self.assertTrue(str(case["id"]).startswith("ra-pos-"))
        for case in negatives:
            self.assertIn("expect_fail_with", case)
            self.assertTrue(str(case["id"]).startswith("ra-neg-"))

    def test_depth_boundaries_documented(self) -> None:
        depths = {c.get("depth") for c in self.data["positive_cases"]}
        self.assertIn(1, depths)
        self.assertIn(4, depths)
        neg_ids = {c["id"] for c in self.data["negative_cases"]}
        self.assertIn("ra-neg-002-zero-depth", neg_ids)
        self.assertIn("ra-neg-003-oversized-depth", neg_ids)

    def test_privacy_notes_present(self) -> None:
        notes = self.data["privacy_notes"]
        self.assertGreaterEqual(len(notes), 2)
        blob = json.dumps(self.data).lower()
        for key in FORBIDDEN_KEYS:
            self.assertNotIn(key, blob)

    def test_witness_is_synthetic_integers(self) -> None:
        witness = self.data["witness"]
        for key, value in witness.items():
            self.assertIsInstance(value, int, msg=key)
            self.assertGreaterEqual(value, 0)


if __name__ == "__main__":
    unittest.main()
