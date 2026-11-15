from __future__ import annotations

import json
import unittest

from app import create_app
from c2pa import C2paParseError, export_c2pa_manifest, parse_c2pa_manifest
from lineage import (
    LineageDuplicateConflictError,
    LineageValidationError,
    build_lineage_graph_view,
    detect_conflicting_ancestry_nodes,
    validate_lineage_graph,
)


class LineageDuplicateConflictTests(unittest.TestCase):
    ACTOR = "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ"
    CONTRACT = "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ"

    def _lineage_node(self, output_hex: str, *, op: str = "crop", param_hex: str = "22" * 32, parent_hex: str = "11" * 32) -> dict:
        return {
            "parentProofIds": [parent_hex],
            "operationType": op,
            "parametersDigest": param_hex,
            "toolIdentity": "harpocrates-studio",
            "toolVersion": "1.0.0",
            "outputDigest": output_hex,
            "network": "testnet",
            "actorAddress": self.ACTOR,
        }

    def test_exact_canonical_duplicates_are_deduplicated_without_conflict(self) -> None:
        node_lower = self._lineage_node("aa" * 32, parent_hex="bb" * 32)
        node_upper = self._lineage_node("AA" * 32, parent_hex="BB" * 32)

        conflicts = detect_conflicting_ancestry_nodes([node_lower, node_upper])
        self.assertEqual(conflicts, [])

        view = build_lineage_graph_view([node_lower, node_upper])
        self.assertEqual(view["deduplicated_count"], 1)
        self.assertEqual(len(view["nodes"]), 1)
        self.assertEqual(len(view["edges"]), 1)
        self.assertEqual(view["nodes"][0]["node_id"], "aa" * 32)

    def test_conflicting_duplicate_lineage_nodes_reported_explicitly(self) -> None:
        node_a = self._lineage_node("cc" * 32, op="crop", param_hex="31" * 32)
        node_b = self._lineage_node("cc" * 32, op="redact", param_hex="32" * 32)

        conflicts = detect_conflicting_ancestry_nodes([node_a, node_b])
        self.assertEqual(len(conflicts), 1)
        conflict = conflicts[0]
        self.assertEqual(conflict.node_id, "cc" * 32)
        self.assertNotEqual(conflict.first_canonical_digest, conflict.conflicting_canonical_digest)
        self.assertEqual(conflict.differing_fields, ("operationType", "parametersDigest"))

    def test_build_lineage_graph_view_rejects_conflict_before_graph_construction(self) -> None:
        # Even when a self-cycle exists in one entry, duplicate conflict detection runs
        # upfront before graph edge traversal/construction.
        first = self._lineage_node("dd" * 32, op="blur", parent_hex="11" * 32)
        conflicting = self._lineage_node("dd" * 32, op="transcode", parent_hex="dd" * 32)

        with self.assertRaises(LineageDuplicateConflictError) as ctx:
            build_lineage_graph_view([first, conflicting])

        payload = ctx.exception.to_dict()
        self.assertEqual(payload["code"], "CONFLICTING_DUPLICATE_ANCESTRY_NODE")
        self.assertEqual(len(payload["conflicts"]), 1)
        self.assertEqual(payload["conflicts"][0]["node_id"], "dd" * 32)
        self.assertEqual(
            payload["conflicts"][0]["differing_fields"],
            ["operationType", "parentProofIds"],
        )

    def test_validate_lineage_graph_rejects_conflicting_ancestry_nodes(self) -> None:
        first = self._lineage_node("ee" * 32, op="crop")
        conflicting = self._lineage_node("ee" * 32, op="blur")

        with self.assertRaises(LineageDuplicateConflictError):
            validate_lineage_graph(
                parent_proof_ids=["ee" * 32],
                depth=2,
                actor_address=self.ACTOR,
                output_digest="ff" * 32,
                ancestry_nodes=[first, conflicting],
            )

    def test_conflicting_root_proof_nodes_report_field_names_without_values(self) -> None:
        secret_network_a = "private-subnet-alpha"
        secret_network_b = "private-subnet-beta"
        root_1 = {
            "proofId": "ab" * 32,
            "videoHash": "01" * 32,
            "metadataHash": "02" * 32,
            "tier": "source",
            "network": secret_network_a,
        }
        root_2 = {
            "proofId": "ab" * 32,
            "videoHash": "01" * 32,
            "metadataHash": "02" * 32,
            "tier": "seal",
            "network": secret_network_b,
        }

        with self.assertRaises(LineageDuplicateConflictError) as ctx:
            build_lineage_graph_view([root_1, root_2])

        serialized = json.dumps(ctx.exception.to_dict())
        self.assertIn("network", serialized)
        self.assertIn("tier", serialized)
        self.assertNotIn(secret_network_a, serialized)
        self.assertNotIn(secret_network_b, serialized)

    def test_manifest_digest_header_disagreement_rejected(self) -> None:
        node = {
            "manifest": self._lineage_node("aa" * 32),
            "manifest_digest": "ff" * 32,
        }
        with self.assertRaises(LineageValidationError):
            build_lineage_graph_view([node])

    def test_c2pa_duplicate_ingredient_conflict_rejected_while_identical_repeat_accepted(self) -> None:
        parent_1 = export_c2pa_manifest(
            video_hash="11" * 32,
            metadata_hash="12" * 32,
            proof_id="a1" * 32,
            tier="source",
            network="testnet",
            contract_id=self.CONTRACT,
        ).manifest
        parent_1_conflict = export_c2pa_manifest(
            video_hash="11" * 32,
            metadata_hash="99" * 32,
            proof_id="a1" * 32,
            tier="source",
            network="testnet",
            contract_id=self.CONTRACT,
        ).manifest
        top = export_c2pa_manifest(
            video_hash="21" * 32,
            metadata_hash="22" * 32,
            proof_id="b2" * 32,
            tier="seal",
            network="testnet",
            contract_id=self.CONTRACT,
        ).manifest

        # Identical duplicate ingredient succeeds
        ok_manifest = json.loads(json.dumps(top))
        ok_manifest["ingredients"] = [{"manifest": parent_1}, {"manifest": parent_1}]
        parsed = parse_c2pa_manifest(json.dumps(ok_manifest))
        self.assertEqual(parsed.binding.proof_id, "b2" * 32)

        # Conflicting duplicate ingredient fails closed with conflicting_ancestry_node
        bad_manifest = json.loads(json.dumps(top))
        bad_manifest["ingredients"] = [{"manifest": parent_1}, {"manifest": parent_1_conflict}]
        with self.assertRaises(C2paParseError) as ctx:
            parse_c2pa_manifest(json.dumps(bad_manifest))
        self.assertEqual(ctx.exception.reason, "conflicting_ancestry_node")
        self.assertEqual(ctx.exception.field, "ingredients[1].metadata_hash")

        client = create_app().test_client()
        resp = client.post("/api/c2pa/import", json={"manifest": bad_manifest})
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("conflicting_ancestry_node", body["error"]["message"])
        self.assertNotIn("99" * 32, json.dumps(body))


if __name__ == "__main__":
    unittest.main()
