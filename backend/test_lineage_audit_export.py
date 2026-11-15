from __future__ import annotations

import json
import unittest

from app import create_app
from c2pa import export_c2pa_manifest, parse_c2pa_manifest, proof_statement_from_c2pa
from lineage import (
    LineageValidationError,
    compute_parent_commitment,
    compute_proof_statement_digest,
    export_lineage_audit_trail,
    lineage_manifest_digest,
)


class LineageAuditExportTests(unittest.TestCase):
    ACTOR = "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ"
    CONTRACT = "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ"

    def _make_chain(self):
        proof_a = {
            "proof_id": "a1" * 32,
            "video_hash": "11" * 32,
            "metadata_hash": "12" * 32,
            "tier": "source",
            "network": "testnet",
            "contract_id": self.CONTRACT,
            "sourceLocation": "37.7749,-122.4194",
            "upload_filename": "whistleblower_raw_take1",
        }
        proof_b = {
            "proof_id": "b2" * 32,
            "video_hash": "21" * 32,
            "metadata_hash": "22" * 32,
            "tier": "seal",
            "network": "testnet",
            "contract_id": self.CONTRACT,
            "gps_coordinates": {"lat": 51.5074, "lon": -0.1278},
            "originalFilename": "camera_b_unredacted",
        }
        deriv_1_manifest = {
            "parentProofIds": ["a1" * 32, "b2" * 32],
            "operationType": "compose",
            "parametersDigest": "33" * 32,
            "toolIdentity": "harpocrates-composer",
            "toolVersion": "1.1.0",
            "outputDigest": "c3" * 32,
            "network": "testnet",
            "actorAddress": self.ACTOR,
        }
        deriv_2_manifest = {
            "parentProofIds": ["c3" * 32],
            "operationType": "redact",
            "parametersDigest": "44" * 32,
            "toolIdentity": "/Users/editor/private_tools/redact-cli",
            "toolVersion": "2.0.0",
            "outputDigest": "d4" * 32,
            "network": "testnet",
            "actorAddress": self.ACTOR,
        }
        rec_1 = {
            "manifest": deriv_1_manifest,
            "manifest_digest": lineage_manifest_digest(deriv_1_manifest),
            "source_uri": "file:///Users/editor/uploads/raw_cam_bundle",
            "input_path": "/var/private/uploads/staging_001",
        }
        rec_2 = {
            "manifest": deriv_2_manifest,
            "manifest_digest": lineage_manifest_digest(deriv_2_manifest),
            "file_name": "final_sensitive_upload",
        }
        return [proof_a, proof_b], [rec_2, rec_1]

    def test_audit_export_includes_statement_digests_and_verified_links(self) -> None:
        proofs, records = self._make_chain()
        audit = export_lineage_audit_trail(
            "d4" * 32,
            records,
            source_proofs=proofs,
        )

        self.assertEqual(audit["schema"], "harpocrates.lineage.audit/v1")
        self.assertEqual(audit["version"], 1)
        self.assertEqual(audit["target_output_digest"], "d4" * 32)
        self.assertEqual(len(audit["proof_statements"]), 2)

        expected_stmt_a = compute_proof_statement_digest(proofs[0])
        self.assertEqual(audit["proof_statements"][0]["proof_id"], "a1" * 32)
        self.assertEqual(audit["proof_statements"][0]["statement_digest"], expected_stmt_a)

        links = audit["transformation_links"]
        self.assertEqual(len(links), 3)
        self.assertEqual([lnk["depth"] for lnk in links], [1, 1, 2])
        self.assertTrue(all(lnk["verified"] for lnk in links))

        self.assertEqual(links[0]["parent_kind"], "source_proof")
        self.assertEqual(
            links[0]["parent_commitment"],
            compute_parent_commitment("11" * 32, "12" * 32),
        )
        self.assertEqual(links[2]["parent_kind"], "derivative")
        self.assertEqual(links[2]["parent_id"], "c3" * 32)
        self.assertEqual(links[2]["child_output_digest"], "d4" * 32)
        self.assertEqual(
            links[2]["parent_commitment"],
            compute_parent_commitment(links[0]["manifest_digest"], "c3" * 32),
        )

        # Deterministic regardless of input record ordering
        audit_reordered = export_lineage_audit_trail(
            "D4" * 32,
            list(reversed(records)),
            source_proofs=list(reversed(proofs)),
        )
        self.assertEqual(audit["audit_digest"], audit_reordered["audit_digest"])
        self.assertEqual(audit, audit_reordered)

    def test_audit_export_redacts_private_locations_and_upload_filenames(self) -> None:
        proofs, records = self._make_chain()
        audit = export_lineage_audit_trail(
            "d4" * 32,
            records,
            source_proofs=proofs,
        )
        serialized = json.dumps(audit)

        for secret_token in (
            "37.7749",
            "-122.4194",
            "51.5074",
            "whistleblower_raw_take1",
            "camera_b_unredacted",
            "raw_cam_bundle",
            "staging_001",
            "final_sensitive_upload",
            "/Users/editor",
            "file://",
        ):
            self.assertNotIn(secret_token, serialized)

        self.assertEqual(
            audit["transformation_links"][2]["tool_identity"],
            "[REDACTED_TOOL_PATH]",
        )
        self.assertEqual(
            audit["redaction_summary"],
            {
                "redacted_source_location": True,
                "redacted_upload_filename": True,
                "redacted_field_categories": ["source_location", "upload_filename"],
            },
        )

    def test_c2pa_bound_source_statement_keeps_trust_status_separate(self) -> None:
        exported = export_c2pa_manifest(
            video_hash="11" * 32,
            metadata_hash="12" * 32,
            proof_id="a1" * 32,
            tier="source",
            network="testnet",
            contract_id=self.CONTRACT,
        )
        parsed = parse_c2pa_manifest(json.dumps(exported.manifest))
        c2pa_stmt = proof_statement_from_c2pa(parsed)

        deriv_manifest = {
            "parentProofIds": ["a1" * 32],
            "operationType": "crop",
            "parametersDigest": "55" * 32,
            "toolIdentity": "harpocrates-studio",
            "toolVersion": "1.0.0",
            "outputDigest": "e5" * 32,
            "network": "testnet",
            "actorAddress": self.ACTOR,
        }
        audit = export_lineage_audit_trail(
            "e5" * 32,
            [deriv_manifest],
            source_proofs=[c2pa_stmt],
        )
        self.assertEqual(
            audit["proof_statements"][0]["c2pa_trust_status"],
            "signature_not_checked",
        )

    def test_rejects_unverified_parent_tampered_digest_and_excess_depth(self) -> None:
        proofs, records = self._make_chain()

        # Missing parent proof fails closed by default
        with self.assertRaises(LineageValidationError):
            export_lineage_audit_trail("d4" * 32, records, source_proofs=[proofs[0]])

        # Tampered stored manifest_digest fails closed
        tampered = json.loads(json.dumps(records))
        tampered[0]["manifest_digest"] = "ff" * 32
        with self.assertRaises(LineageValidationError):
            export_lineage_audit_trail("d4" * 32, tampered, source_proofs=proofs)

        # Depth > MAX_LINEAGE_DEPTH (5 hops) fails closed
        chain = []
        prev = "a1" * 32
        for step in range(1, 6):
            out_hex = f"{step:02x}" * 32
            chain.append(
                {
                    "parentProofIds": [prev],
                    "operationType": "transcode",
                    "parametersDigest": "99" * 32,
                    "toolIdentity": "harpocrates-studio",
                    "toolVersion": "1.0.0",
                    "outputDigest": out_hex,
                    "network": "testnet",
                    "actorAddress": self.ACTOR,
                }
            )
            prev = out_hex
        with self.assertRaises(LineageValidationError):
            export_lineage_audit_trail(prev, chain, source_proofs=[proofs[0]])

    def test_http_audit_export_endpoint(self) -> None:
        proofs, records = self._make_chain()
        client = create_app().test_client()

        resp = client.post(
            "/api/lineage/audit-export",
            json={
                "targetOutputDigest": "d4" * 32,
                "lineageRecords": records,
                "sourceProofs": proofs,
            },
        )
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["audit"]["target_output_digest"], "d4" * 32)
        self.assertNotIn("whistleblower_raw_take1", json.dumps(payload))

        bad_resp = client.post(
            "/api/lineage/audit-export",
            json={"targetOutputDigest": "not-hex"},
        )
        self.assertEqual(bad_resp.status_code, 400)
        bad_payload = bad_resp.get_json()
        self.assertFalse(bad_payload["ok"])
        self.assertEqual(bad_payload["error"]["code"], "VALIDATION_ERROR")


if __name__ == "__main__":
    unittest.main()
