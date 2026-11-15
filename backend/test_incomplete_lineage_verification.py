from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from c2pa import (
    C2paTrustStatus,
    export_c2pa_manifest,
    extract_c2pa_ingredient_dependencies,
)
from lineage import (
    LineageVerificationStatus,
    canonical_lineage_manifest,
    lineage_manifest_digest,
    verify_lineage_completeness,
)


ACTOR_G = "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ"
CONTRACT_C = "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ"
NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"


def _hex(byte_val: int) -> str:
    return f"{byte_val:02x}" * 32


def _make_lineage_row(
    output_digest: str,
    parent_ids: list[str],
    *,
    operation: str = "crop",
    param_byte: int = 0x99,
) -> dict:
    manifest_in = {
        "parentProofIds": parent_ids,
        "operationType": operation,
        "parametersDigest": _hex(param_byte),
        "toolIdentity": "harpocrates-studio",
        "toolVersion": "1.2.3",
        "outputDigest": output_digest,
        "network": NETWORK_PASSPHRASE,
        "actorAddress": ACTOR_G,
    }
    canonical = json.loads(canonical_lineage_manifest(manifest_in))
    digest = lineage_manifest_digest(manifest_in)
    return {
        "id": 1,
        "manifest_digest": digest,
        "manifest": canonical,
        "actor_address": ACTOR_G,
        "parent_proof_ids": list(parent_ids),
    }


def _make_c2pa_with_assertions(
    *,
    proof_id: str,
    video_hash: str | None = None,
    extra_assertions: list[dict] | None = None,
    ingredients: list[dict] | None = None,
) -> dict:
    exported = export_c2pa_manifest(
        video_hash=video_hash or proof_id,
        metadata_hash=_hex(0xAA),
        proof_id=proof_id,
        tier="source",
        network=NETWORK_PASSPHRASE,
        contract_id=CONTRACT_C,
    )
    manifest = json.loads(json.dumps(exported.manifest))
    if extra_assertions:
        manifest["assertions"].extend(extra_assertions)
    if ingredients is not None:
        manifest["ingredients"] = ingredients
    return manifest


class IncompleteLineageVerificationTests(unittest.TestCase):
    def test_verified_original_root_proof(self) -> None:
        root_id = _hex(0x01)
        proofs = {root_id: [{"proof_id": root_id, "tx_status": "confirmed"}]}

        result = verify_lineage_completeness(
            root_id,
            get_lineage_fn=lambda _: None,
            get_proof_fn=proofs.get,
        )

        self.assertEqual(result.status, LineageVerificationStatus.VERIFIED_ORIGINAL)
        self.assertTrue(result.is_verified)
        self.assertTrue(result.is_original)
        self.assertTrue(result.is_complete)
        self.assertEqual(result.verified_edges, ())
        self.assertEqual(result.missing_dependencies, ())
        self.assertEqual(result.verified_roots, (root_id,))

    def test_verified_derivative_diamond_dag_is_complete_and_not_original(self) -> None:
        root_id = _hex(0x01)
        left_id = _hex(0x02)
        right_id = _hex(0x03)
        composed_id = _hex(0x04)

        lineage_store = {
            left_id: _make_lineage_row(left_id, [root_id], operation="crop"),
            right_id: _make_lineage_row(right_id, [root_id], operation="blur"),
            composed_id: _make_lineage_row(
                composed_id, [left_id, right_id], operation="compose"
            ),
        }
        proof_store = {root_id: {"proof_id": root_id, "tx_status": "confirmed"}}

        result = verify_lineage_completeness(
            composed_id,
            get_lineage_fn=lineage_store.get,
            get_proof_fn=proof_store.get,
        )

        self.assertEqual(result.status, LineageVerificationStatus.VERIFIED_DERIVATIVE)
        self.assertTrue(result.is_verified)
        self.assertFalse(result.is_original)
        self.assertTrue(result.is_complete)
        self.assertEqual(result.missing_dependencies, ())
        self.assertEqual(result.verified_roots, (root_id,))
        self.assertEqual(len(result.verified_edges), 4)

    def test_incomplete_lineage_returns_known_verified_edges_and_missing_dependencies(
        self,
    ) -> None:
        confirmed_root = _hex(0x10)
        missing_root = _hex(0x11)
        pending_root = _hex(0x12)
        mid_derivative = _hex(0x13)
        final_derivative = _hex(0x14)

        lineage_store = {
            mid_derivative: _make_lineage_row(
                mid_derivative, [confirmed_root, missing_root], operation="compose"
            ),
            final_derivative: _make_lineage_row(
                final_derivative, [mid_derivative, pending_root], operation="redact"
            ),
        }
        proof_store = {
            confirmed_root: [{"proof_id": confirmed_root, "tx_status": "confirmed"}],
            pending_root: [{"proof_id": pending_root, "tx_status": "pending"}],
            # Even if final_derivative was registered as a proof event, it is a
            # derivative with missing upstream dependencies and MUST NOT be
            # reported as a verified original.
            final_derivative: [{"proof_id": final_derivative, "tx_status": "confirmed"}],
        }

        result = verify_lineage_completeness(
            final_derivative,
            get_lineage_fn=lineage_store.get,
            get_proof_fn=proof_store.get,
        )

        self.assertEqual(result.status, LineageVerificationStatus.INCOMPLETE_LINEAGE)
        self.assertFalse(result.is_verified)
        self.assertFalse(result.is_original)
        self.assertFalse(result.is_complete)
        self.assertEqual(result.verified_roots, (confirmed_root,))

        verified_pairs = [(e.parent_id, e.child_id, e.parent_kind) for e in result.verified_edges]
        self.assertEqual(
            verified_pairs,
            [
                (mid_derivative, final_derivative, "lineage_record"),
                (confirmed_root, mid_derivative, "root_proof"),
            ],
        )

        missing_tuples = [
            (d.dependency_id, d.referenced_by, d.depth, d.reason)
            for d in result.missing_dependencies
        ]
        self.assertEqual(
            missing_tuples,
            [
                (pending_root, final_derivative, 1, "unconfirmed_parent_proof"),
                (missing_root, mid_derivative, 2, "missing_parent_proof"),
            ],
        )

    def test_confirmed_proof_with_uncovered_c2pa_ingredients_is_never_verified_original(
        self,
    ) -> None:
        target_id = _hex(0x21)
        upstream_parent = _hex(0x22)
        secret_filename = "witness_raw_camera_roll_secret.bin"

        c2pa_doc = _make_c2pa_with_assertions(
            proof_id=target_id,
            extra_assertions=[
                {
                    "label": "c2pa.ingredient.v3",
                    "data": {
                        "relationship": "parentOf",
                        "proof_id": upstream_parent,
                        "title": secret_filename,
                    },
                },
                {
                    "label": "c2pa.ingredient",
                    "data": {
                        "relationship": "componentOf",
                        "title": secret_filename,
                        "document_id": "xmp:iid:opaque-external-asset",
                    },
                },
            ],
        )

        deps = extract_c2pa_ingredient_dependencies(c2pa_doc)
        self.assertEqual(len(deps), 2)
        serialized_deps = json.dumps([d.to_dict() for d in deps])
        self.assertNotIn(secret_filename, serialized_deps)

        result = verify_lineage_completeness(
            target_id,
            get_lineage_fn=lambda _: None,
            get_proof_fn=lambda d: {"proof_id": d, "tx_status": "confirmed"}
            if d == target_id
            else None,
            c2pa_manifest=c2pa_doc,
        )

        self.assertEqual(result.status, LineageVerificationStatus.INCOMPLETE_LINEAGE)
        self.assertFalse(result.is_verified)
        self.assertFalse(result.is_original)
        self.assertFalse(result.is_complete)
        self.assertEqual(
            result.c2pa_trust_status, C2paTrustStatus.SIGNATURE_NOT_CHECKED.value
        )

        reasons = {(d.dependency_id, d.reason, d.source) for d in result.missing_dependencies}
        self.assertEqual(
            reasons,
            {
                (upstream_parent, "missing_lineage_edge", "c2pa_ingredient"),
                (None, "unverified_c2pa_ingredient", "c2pa_ingredient"),
            },
        )
        self.assertNotIn(secret_filename, json.dumps(result.to_dict()))

    def test_c2pa_ingredient_covered_by_verified_lineage_edge_succeeds(self) -> None:
        root_id = _hex(0x31)
        deriv_id = _hex(0x32)
        extra_untracked_id = _hex(0x33)

        lineage_store = {
            deriv_id: _make_lineage_row(deriv_id, [root_id], operation="transcode"),
        }
        proof_store = {
            root_id: {"proof_id": root_id, "tx_status": "confirmed"},
        }

        covered_c2pa = _make_c2pa_with_assertions(
            proof_id=deriv_id,
            extra_assertions=[
                {
                    "label": "c2pa.ingredient",
                    "data": {"relationship": "parentOf", "proof_id": root_id},
                }
            ],
        )
        ok_res = verify_lineage_completeness(
            deriv_id,
            get_lineage_fn=lineage_store.get,
            get_proof_fn=proof_store.get,
            c2pa_manifest=covered_c2pa,
        )
        self.assertEqual(ok_res.status, LineageVerificationStatus.VERIFIED_DERIVATIVE)
        self.assertTrue(ok_res.is_verified)
        self.assertFalse(ok_res.is_original)
        self.assertEqual(
            ok_res.c2pa_trust_status, C2paTrustStatus.SIGNATURE_NOT_CHECKED.value
        )

        uncovered_c2pa = _make_c2pa_with_assertions(
            proof_id=deriv_id,
            ingredients=[
                {"relationship": "parentOf", "proof_id": root_id},
                {"relationship": "componentOf", "video_hash": extra_untracked_id},
            ],
        )
        inc_res = verify_lineage_completeness(
            deriv_id,
            get_lineage_fn=lineage_store.get,
            get_proof_fn=proof_store.get,
            c2pa_manifest=uncovered_c2pa,
        )
        self.assertEqual(inc_res.status, LineageVerificationStatus.INCOMPLETE_LINEAGE)
        self.assertFalse(inc_res.is_verified)
        self.assertFalse(inc_res.is_original)
        self.assertEqual(len(inc_res.verified_edges), 1)
        self.assertEqual(
            [(d.dependency_id, d.reason) for d in inc_res.missing_dependencies],
            [(extra_untracked_id, "missing_lineage_edge")],
        )

    def test_fail_closed_on_cycles_depth_tampering_and_revocation(self) -> None:
        # 1. Cycle detection (2-node cycle)
        a_id = _hex(0x41)
        b_id = _hex(0x42)
        cycle_store = {
            a_id: _make_lineage_row(a_id, [b_id]),
            b_id: _make_lineage_row(b_id, [a_id]),
        }
        cycle_res = verify_lineage_completeness(
            a_id, get_lineage_fn=cycle_store.get, get_proof_fn=lambda _: None
        )
        self.assertEqual(cycle_res.status, LineageVerificationStatus.INVALID_LINEAGE)
        self.assertFalse(cycle_res.is_verified)
        self.assertEqual(cycle_res.error_reason, "cycle_detected")

        # 2. Depth > MAX_LINEAGE_DEPTH (5 hops)
        chain = [_hex(0x50 + i) for i in range(6)]
        deep_store = {
            chain[i]: _make_lineage_row(chain[i], [chain[i - 1]])
            for i in range(1, 6)
        }
        deep_res = verify_lineage_completeness(
            chain[5],
            get_lineage_fn=deep_store.get,
            get_proof_fn=lambda d: True if d == chain[0] else None,
        )
        self.assertEqual(deep_res.status, LineageVerificationStatus.INVALID_LINEAGE)
        self.assertEqual(deep_res.error_reason, "max_depth_exceeded")

        # 3. Tampered manifest_digest
        tampered_row = _make_lineage_row(_hex(0x61), [_hex(0x60)])
        tampered_row["manifest_digest"] = _hex(0xFF)
        tampered_res = verify_lineage_completeness(
            _hex(0x61),
            get_lineage_fn={_hex(0x61): tampered_row}.get,
            get_proof_fn=lambda _: True,
        )
        self.assertEqual(tampered_res.status, LineageVerificationStatus.INVALID_LINEAGE)
        self.assertEqual(tampered_res.error_reason, "manifest_digest_mismatch")

        # 4. Revoked parent proof
        revoked_parent = _hex(0x70)
        child_id = _hex(0x71)
        revoked_res = verify_lineage_completeness(
            child_id,
            get_lineage_fn={child_id: _make_lineage_row(child_id, [revoked_parent])}.get,
            get_proof_fn=lambda d: [{"proof_id": d, "event_type": "revoke"}]
            if d == revoked_parent
            else None,
        )
        self.assertEqual(revoked_res.status, LineageVerificationStatus.INVALID_LINEAGE)
        self.assertEqual(revoked_res.error_reason, "revoked_parent_proof")


class IncompleteLineageApiTests(unittest.TestCase):
    def setUp(self) -> None:
        from app import create_app

        self.app = create_app()
        self.client = self.app.test_client()

    def test_get_and_post_lineage_verify_endpoints(self) -> None:
        known_root = _hex(0x81)
        missing_root = _hex(0x82)
        deriv_id = _hex(0x83)
        row = _make_lineage_row(deriv_id, [known_root, missing_root], operation="compose")

        def fake_lineage_lookup(digest: str):
            return row if digest == deriv_id else None

        def fake_proof_by_id(digest: str):
            if digest == known_root:
                return [{"proof_id": known_root, "tx_status": "confirmed"}]
            return []

        with (
            patch("app.find_lineage_by_output_digest", side_effect=fake_lineage_lookup),
            patch("app.find_proof_events_by_proof_id", side_effect=fake_proof_by_id),
            patch("app.find_proof_events_by_video", return_value=([], None)),
        ):
            get_resp = self.client.get(f"/api/lineage/{deriv_id}/verify")
            self.assertEqual(get_resp.status_code, 200)
            body = get_resp.get_json()
            self.assertTrue(body["ok"])
            ver = body["verification"]
            self.assertEqual(ver["status"], "incomplete_lineage")
            self.assertFalse(ver["is_verified"])
            self.assertFalse(ver["is_original"])
            self.assertEqual(len(ver["verified_edges"]), 1)
            self.assertEqual(ver["verified_edges"][0]["parent_id"], known_root)
            self.assertEqual(len(ver["missing_dependencies"]), 1)
            self.assertEqual(ver["missing_dependencies"][0]["dependency_id"], missing_root)

            # POST /api/lineage/verify with C2PA ingredient claim on a root proof
            c2pa_doc = _make_c2pa_with_assertions(
                proof_id=known_root,
                extra_assertions=[
                    {
                        "label": "c2pa.ingredient",
                        "data": {"relationship": "parentOf", "proof_id": missing_root},
                    }
                ],
            )
            post_resp = self.client.post(
                "/api/lineage/verify",
                json={"targetDigest": known_root, "c2paManifest": c2pa_doc},
            )
            self.assertEqual(post_resp.status_code, 200)
            post_ver = post_resp.get_json()["verification"]
            self.assertEqual(post_ver["status"], "incomplete_lineage")
            self.assertFalse(post_ver["is_original"])
            self.assertFalse(post_ver["is_verified"])

    def test_verify_endpoints_reject_malformed_digest_without_echoing_input(self) -> None:
        bad_input = "not-a-valid-digest-secret-token"
        resp_get = self.client.get(f"/api/lineage/{bad_input}/verify")
        self.assertEqual(resp_get.status_code, 400)
        msg_get = resp_get.get_json()["error"]["message"]
        self.assertNotIn(bad_input, msg_get)

        resp_post = self.client.post(
            "/api/lineage/verify", json={"targetDigest": bad_input}
        )
        self.assertEqual(resp_post.status_code, 400)
        msg_post = resp_post.get_json()["error"]["message"]
        self.assertNotIn(bad_input, msg_post)


if __name__ == "__main__":
    unittest.main()
