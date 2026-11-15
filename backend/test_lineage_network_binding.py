from __future__ import annotations

import unittest
from unittest.mock import patch

from app import create_app
from c2pa import export_c2pa_manifest, extract_c2pa_endpoint_binding
from lineage import (
    LineageNetworkMismatchError,
    LineageValidationError,
    evaluate_lineage_network_bindings,
    validate_lineage_edge_binding,
    validate_lineage_graph,
)
from strkey import _VERSION_BYTE_CONTRACT, make_strkey


class LineageNetworkBindingTests(unittest.TestCase):
    ACTOR = "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ"
    CONTRACT_A = make_strkey(_VERSION_BYTE_CONTRACT, b"\x01" * 32)
    CONTRACT_B = make_strkey(_VERSION_BYTE_CONTRACT, b"\x02" * 32)

    def _deriv(
        self,
        out_byte: str,
        *,
        parents: list[str],
        network: str = "testnet",
        contract_id: str | None = None,
    ) -> dict:
        payload = {
            "parentProofIds": parents,
            "operationType": "crop",
            "parametersDigest": "55" * 32,
            "toolIdentity": "harpocrates-studio",
            "toolVersion": "1.0.0",
            "outputDigest": out_byte * 32,
            "network": network,
            "actorAddress": self.ACTOR,
        }
        if contract_id is not None:
            payload["contractId"] = contract_id
        return payload

    def test_compatible_network_passphrase_and_contract_bindings_accepted(self) -> None:
        c2pa_parent = export_c2pa_manifest(
            video_hash="11" * 32,
            metadata_hash="12" * 32,
            proof_id="a1" * 32,
            tier="source",
            network="Test SDF Network ; September 2015",
            contract_id=self.CONTRACT_A.lower(),
        )
        parent_ep = extract_c2pa_endpoint_binding(c2pa_parent.manifest)
        child_ep = self._deriv(
            "b2",
            parents=["a1" * 32],
            network="testnet",
            contract_id=self.CONTRACT_A,
        )

        verified = validate_lineage_edge_binding(parent_ep, child_ep)
        self.assertEqual(verified["network"], "testnet")
        self.assertEqual(verified["contract_id"], self.CONTRACT_A)

    def test_rejects_network_mismatch_contract_mismatch_and_invalid_contract(self) -> None:
        parent_testnet = {
            "proof_id": "a1" * 32,
            "network": "testnet",
            "contract_id": self.CONTRACT_A,
        }
        child_mainnet = self._deriv(
            "b2",
            parents=["a1" * 32],
            network="Public Global Stellar Network ; September 2015",
            contract_id=self.CONTRACT_A,
        )
        with self.assertRaises(LineageNetworkMismatchError) as net_ctx:
            validate_lineage_edge_binding(parent_testnet, child_mainnet)
        self.assertEqual(net_ctx.exception.reason, "network_mismatch")

        child_wrong_contract = self._deriv(
            "b3",
            parents=["a1" * 32],
            network="testnet",
            contract_id=self.CONTRACT_B,
        )
        with self.assertRaises(LineageNetworkMismatchError) as cid_ctx:
            validate_lineage_edge_binding(parent_testnet, child_wrong_contract)
        self.assertEqual(cid_ctx.exception.reason, "contract_mismatch")

        # G-address is not a valid C-contract ID
        child_bad_strkey = self._deriv(
            "b4",
            parents=["a1" * 32],
            network="testnet",
            contract_id=self.ACTOR,
        )
        with self.assertRaises(LineageValidationError):
            validate_lineage_edge_binding(parent_testnet, child_bad_strkey)

    def test_multi_branch_evaluation_preserves_valid_unrelated_branches_within_bounds(self) -> None:
        roots = [
            {
                "proof_id": "01" * 32,
                "network": "Test SDF Network ; September 2015",
                "contract_id": self.CONTRACT_A,
            },
            {
                "proof_id": "02" * 32,
                "network": "mainnet",
                "contract_id": self.CONTRACT_A,
            },
        ]

        # Valid Branch A: 01 -> a1 -> a2 (all testnet + CONTRACT_A)
        d_a1 = self._deriv("a1", parents=["01" * 32], network="testnet", contract_id=self.CONTRACT_A)
        d_a2 = self._deriv("a2", parents=["a1" * 32], network="testnet", contract_id=self.CONTRACT_A)

        # Invalid Branch B: 02 (mainnet) -> b1 (testnet) -> b2 (testnet, tainted)
        d_b1 = self._deriv("b1", parents=["02" * 32], network="testnet", contract_id=self.CONTRACT_A)
        d_b2 = self._deriv("b2", parents=["b1" * 32], network="testnet", contract_id=self.CONTRACT_A)

        # Invalid Branch C off root 01: c1 uses CONTRACT_B (must not taint Branch A)
        d_c1 = self._deriv("c1", parents=["01" * 32], network="testnet", contract_id=self.CONTRACT_B)

        report = evaluate_lineage_network_bindings(
            [d_a1, d_a2, d_b1, d_b2, d_c1],
            root_endpoints=roots,
        )
        self.assertFalse(report.all_valid)
        self.assertFalse(report.truncated)

        valid_ids = [n["node_id"] for n in report.valid_nodes]
        self.assertEqual(valid_ids, ["a1" * 32, "a2" * 32])
        self.assertEqual(len(report.valid_edges), 2)

        reasons_by_child = {e["child_id"]: e["reason"] for e in report.rejected_edges}
        self.assertEqual(reasons_by_child["b1" * 32], "network_mismatch")
        self.assertEqual(reasons_by_child["b2" * 32], "tainted_parent_branch")
        self.assertEqual(reasons_by_child["c1" * 32], "contract_mismatch")

        # Bounded truncation check
        bounded = evaluate_lineage_network_bindings(
            [d_a1, d_a2, d_b1, d_b2, d_c1],
            root_endpoints=roots,
            max_nodes=2,
        )
        self.assertTrue(bounded.truncated)
        self.assertEqual(len(bounded.valid_nodes), 2)

    def test_http_register_lineage_rejects_cross_network_parent(self) -> None:
        parent_record = {
            "manifest": self._deriv(
                "a1",
                parents=["01" * 32],
                network="mainnet",
                contract_id=self.CONTRACT_A,
            ),
            "parent_proof_ids": ["01" * 32],
        }
        child_payload = self._deriv(
            "b2",
            parents=["a1" * 32],
            network="testnet",
            contract_id=self.CONTRACT_A,
        )

        def _fake_lookup(digest: str):
            if digest.lower() == "a1" * 32:
                return parent_record
            return None

        client = create_app().test_client()
        with patch("app.find_lineage_by_output_digest", side_effect=_fake_lookup):
            resp = client.post("/api/proofs/lineage", json=child_payload)

        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("network_mismatch", body["error"])


if __name__ == "__main__":
    unittest.main()
