from __future__ import annotations

import json
import unittest

from c2pa import export_c2pa_manifest
from lineage import LineageValidationError, compare_lineage_graphs


class LineageGraphComparisonTests(unittest.TestCase):
    ACTOR = "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ"
    CONTRACT = "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ"

    def _node(
        self,
        out_byte: str,
        *,
        parents: list[str] | None = None,
        op: str = "crop",
        param_byte: str = "55",
    ) -> dict:
        return {
            "parentProofIds": parents or ["11" * 32],
            "operationType": op,
            "parametersDigest": param_byte * 32,
            "toolIdentity": "harpocrates-studio",
            "toolVersion": "1.0.0",
            "outputDigest": out_byte * 32,
            "network": "testnet",
            "actorAddress": self.ACTOR,
        }

    def _c2pa(self, extra_assertions: list[dict] | None = None) -> dict:
        m = json.loads(
            json.dumps(
                export_c2pa_manifest(
                    video_hash="aa" * 32,
                    metadata_hash="bb" * 32,
                    proof_id="cc" * 32,
                    tier="source",
                    network="testnet",
                    contract_id=self.CONTRACT,
                ).manifest
            )
        )
        if extra_assertions:
            m["assertions"].extend(extra_assertions)
        return m

    def test_identical_graphs_report_no_changes_with_stable_digest(self) -> None:
        g1 = {
            "nodes": [self._node("a1"), self._node("b2")],
            "c2pa_manifest": self._c2pa([{"label": "c2pa.actions", "data": {"actions": []}}]),
        }
        g2 = json.loads(json.dumps(g1))

        rep_a = compare_lineage_graphs(g1, g2)
        rep_b = compare_lineage_graphs(g1, g2)
        self.assertTrue(rep_a.identical)
        self.assertFalse(rep_a.provenance_changed)
        self.assertFalse(rep_a.ordering_changed)
        self.assertEqual(rep_a.report_digest, rep_b.report_digest)
        self.assertEqual(rep_a.to_dict(), rep_b.to_dict())

    def test_ordering_differences_separated_from_provenance_changes(self) -> None:
        node_compose_ab = self._node(
            "c3",
            parents=["11" * 32, "22" * 32],
            op="compose",
        )
        node_compose_ba = self._node(
            "c3",
            parents=["22" * 32, "11" * 32],
            op="compose",
        )
        node_crop = self._node("d4", parents=["33" * 32], op="crop")

        c2pa_1 = self._c2pa(
            [
                {"label": "c2pa.actions", "data": {"v": 1}},
                {"label": "c2pa.thumbnail", "data": {"v": 2}},
            ]
        )
        c2pa_2 = self._c2pa(
            [
                {"label": "c2pa.thumbnail", "data": {"v": 2}},
                {"label": "c2pa.actions", "data": {"v": 1}},
            ]
        )

        baseline = {"nodes": [node_compose_ab, node_crop], "c2pa_manifest": c2pa_1}
        permuted = {"nodes": [node_crop, node_compose_ba], "c2pa_manifest": c2pa_2}

        report = compare_lineage_graphs(baseline, permuted)
        self.assertFalse(report.provenance_changed)
        self.assertTrue(report.ordering_changed)
        self.assertFalse(report.identical)
        self.assertEqual(report.added_assertions, ())
        self.assertEqual(report.removed_assertions, ())
        self.assertEqual(report.changed_assertions, ())

        scopes = [diff["scope"] for diff in report.ordering_differences]
        self.assertEqual(
            scopes,
            ["parent_proof_ids", "graph_nodes", "c2pa_assertions"],
        )

    def test_added_removed_and_changed_assertions_identified_by_canonical_digest(self) -> None:
        secret_before = "PRIVATE-ACTION-BEFORE-999"
        secret_after = "PRIVATE-ACTION-AFTER-888"

        baseline = {
            "nodes": [
                self._node("a1", op="crop", param_byte="41"),
                self._node("b2", op="blur", param_byte="42"),
            ],
            "c2pa_manifest": self._c2pa(
                [
                    {"label": "c2pa.actions", "data": {"secret_note": secret_before}},
                    {"label": "c2pa.legacy", "data": {"old": True}},
                ]
            ),
        }
        candidate = {
            "nodes": [
                self._node("b2", op="redact", param_byte="99"),
                self._node("c3", op="transcode", param_byte="43"),
            ],
            "c2pa_manifest": self._c2pa(
                [
                    {"label": "c2pa.actions", "data": {"secret_note": secret_after}},
                    {"label": "c2pa.added", "data": {"new": True}},
                ]
            ),
        }

        report = compare_lineage_graphs(baseline, candidate)
        self.assertTrue(report.provenance_changed)

        added_ids = [item["assertion_id"] for item in report.added_assertions]
        removed_ids = [item["assertion_id"] for item in report.removed_assertions]
        changed_ids = [item["assertion_id"] for item in report.changed_assertions]

        self.assertEqual(added_ids, ["c2pa.added", "c3" * 32])
        self.assertEqual(removed_ids, ["c2pa.legacy", "a1" * 32])
        self.assertEqual(changed_ids, ["c2pa.actions", "b2" * 32])

        lineage_change = next(
            c for c in report.changed_assertions if c["assertion_id"] == "b2" * 32
        )
        self.assertNotEqual(lineage_change["before_digest"], lineage_change["after_digest"])
        self.assertEqual(
            lineage_change["changed_fields"],
            ["operationType", "parametersDigest"],
        )

        # Privacy check: raw assertion values never appear in the comparison report
        serialized = json.dumps(report.to_dict())
        self.assertNotIn(secret_before, serialized)
        self.assertNotIn(secret_after, serialized)

    def test_rejects_conflicting_duplicates_cycles_and_oversized_graphs(self) -> None:
        # Conflicting duplicate within one graph
        dup_a = self._node("a1", op="crop")
        dup_b = self._node("a1", op="blur")
        with self.assertRaises(LineageValidationError):
            compare_lineage_graphs([dup_a, dup_b], [dup_a])

        # Transitive cycle within one graph
        cyc_1 = self._node("e1", parents=["e2" * 32])
        cyc_2 = self._node("e2", parents=["e1" * 32])
        with self.assertRaises(LineageValidationError):
            compare_lineage_graphs([cyc_1, cyc_2], [])

        # Exceeds max_nodes
        many = [self._node(f"{i:02x}") for i in range(1, 6)]
        with self.assertRaises(LineageValidationError):
            compare_lineage_graphs(many, [], max_nodes=3)


if __name__ == "__main__":
    unittest.main()
