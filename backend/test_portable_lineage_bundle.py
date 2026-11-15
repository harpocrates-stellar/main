from __future__ import annotations

import copy
import hashlib
import json
import socket
import unittest
import urllib.request
from unittest.mock import patch

from c2pa import C2paParseError, C2paTrustStatus, export_c2pa_manifest, extract_c2pa_portable_trust_reference
from lineage import (
    LineageValidationError,
    PORTABLE_LINEAGE_BUNDLE_SCHEMA,
    build_portable_lineage_bundle,
    canonical_lineage_manifest,
    compute_parent_commitment,
    lineage_manifest_digest,
    verify_portable_lineage_bundle,
)


ACTOR_G = "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ"
CONTRACT_C = "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ"
OTHER_CONTRACT_C = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"


def _hex(byte_val: int) -> str:
    return f"{byte_val:02x}" * 32


def _make_root(
    byte_val: int,
    *,
    tier: str = "source",
    network: str = NETWORK_PASSPHRASE,
    contract_id: str = CONTRACT_C,
) -> dict:
    return {
        "proof_id": _hex(byte_val),
        "video_hash": _hex(byte_val + 0x40),
        "metadata_hash": _hex(byte_val + 0x80),
        "tier": tier,
        "network": network,
        "contract_id": contract_id,
    }


def _make_lineage(
    output_digest: str,
    parent_ids: list[str],
    *,
    operation: str = "crop",
    network: str = NETWORK_PASSPHRASE,
) -> dict:
    manifest = {
        "parentProofIds": parent_ids,
        "operationType": operation,
        "parametersDigest": _hex(0xEE),
        "toolIdentity": "harpocrates-studio",
        "toolVersion": "1.2.3",
        "outputDigest": output_digest,
        "network": network,
        "actorAddress": ACTOR_G,
    }
    return {
        "manifest": json.loads(canonical_lineage_manifest(manifest)),
        "manifest_digest": lineage_manifest_digest(manifest),
        "actor_address": ACTOR_G,
        "parent_proof_ids": list(parent_ids),
    }


def _recompute_bundle_digest(bundle: dict) -> dict:
    updated = copy.deepcopy(bundle)
    body = {k: v for k, v in updated.items() if k != "bundle_digest"}
    updated["bundle_digest"] = hashlib.sha256(
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return updated


class PortableLineageBundleTests(unittest.TestCase):
    def test_packages_canonical_closure_and_trust_references_deterministically(
        self,
    ) -> None:
        r1 = _make_root(0x01, tier="silent")
        r2 = _make_root(0x02, tier="seal")
        unrelated_root = _make_root(0x09, tier="source")

        d1_id = _hex(0x11)
        d2_id = _hex(0x12)
        unrelated_deriv_id = _hex(0x19)

        d1 = _make_lineage(d1_id, [r1["proof_id"]], operation="redact")
        d2 = _make_lineage(d2_id, [d1_id, r2["proof_id"]], operation="compose")
        unrelated_deriv = _make_lineage(
            unrelated_deriv_id, [unrelated_root["proof_id"]], operation="blur"
        )

        c2pa_r2 = export_c2pa_manifest(
            video_hash=r2["video_hash"],
            metadata_hash=r2["metadata_hash"],
            proof_id=r2["proof_id"],
            tier=r2["tier"],
            network=r2["network"],
            contract_id=r2["contract_id"],
        )
        soroban_ref = {
            "kind": "soroban_registry",
            "subject_id": r1["proof_id"],
            "network": NETWORK_PASSPHRASE,
            "contract_id": CONTRACT_C,
            "anchor_digest": _hex(0xCC),
        }

        bundle_a = build_portable_lineage_bundle(
            d2_id,
            lineage_records=[unrelated_deriv, d2, d1],
            root_statements=[unrelated_root, r2, r1],
            trust_references=[soroban_ref],
            c2pa_manifests=[c2pa_r2],
        )
        bundle_b = build_portable_lineage_bundle(
            d2_id,
            lineage_records=[d1, d2, unrelated_deriv],
            root_statements=[r1, r2, unrelated_root],
            trust_references=[soroban_ref],
            c2pa_manifests=[c2pa_r2.manifest],
        )

        self.assertEqual(bundle_a["schema"], PORTABLE_LINEAGE_BUNDLE_SCHEMA)
        self.assertEqual(bundle_a["bundle_digest"], bundle_b["bundle_digest"])
        self.assertEqual(
            json.dumps(bundle_a, sort_keys=True),
            json.dumps(bundle_b, sort_keys=True),
        )

        # Unreachable records were excluded by bounded closure.
        self.assertEqual(
            [r["proof_id"] for r in bundle_a["root_statements"]],
            [r1["proof_id"], r2["proof_id"]],
        )
        self.assertEqual(
            [(a["output_digest"], a["depth"]) for a in bundle_a["ancestry_statements"]],
            [(d1_id, 1), (d2_id, 2)],
        )

        # Parent commitments match canonical domain-separated SHA-256.
        self.assertEqual(
            bundle_a["ancestry_statements"][0]["parent_commitments"],
            [compute_parent_commitment(r1["video_hash"], r1["metadata_hash"])],
        )

        report = verify_portable_lineage_bundle(json.dumps(bundle_a))
        self.assertTrue(report.valid)
        self.assertTrue(report.is_derivative)
        self.assertEqual(report.max_depth, 2)
        self.assertEqual(report.node_count, 4)
        self.assertEqual(report.trust_reference_count, 2)
        self.assertEqual(
            report.c2pa_trust_statuses,
            (C2paTrustStatus.SIGNATURE_NOT_CHECKED.value,),
        )

    def test_rejects_external_urls_offline_without_network_access_or_echo(self) -> None:
        r1 = _make_root(0x01)
        d1_id = _hex(0x21)
        d1 = _make_lineage(d1_id, [r1["proof_id"]])
        secret_url = "https://remote-manifest.invalid/private-token-998877"

        def _forbid_network(*_args, **_kwargs):
            raise AssertionError("network socket or URL fetch must never be invoked")

        with (
            patch.object(socket, "socket", side_effect=_forbid_network),
            patch.object(urllib.request, "urlopen", side_effect=_forbid_network),
        ):
            # 1. URL in trust reference
            with self.assertRaises(LineageValidationError) as ctx1:
                build_portable_lineage_bundle(
                    d1_id,
                    lineage_records=[d1],
                    root_statements=[r1],
                    trust_references=[
                        {
                            "kind": "soroban_registry",
                            "subject_id": r1["proof_id"],
                            "network": NETWORK_PASSPHRASE,
                            "contract_id": CONTRACT_C,
                            "anchor_digest": _hex(0xAA),
                            "trust_url": secret_url,
                        }
                    ],
                )
            self.assertNotIn(secret_url, str(ctx1.exception))

            # 2. URL scheme inside C2PA assertion
            c2pa_doc = export_c2pa_manifest(
                video_hash=r1["video_hash"],
                metadata_hash=r1["metadata_hash"],
                proof_id=r1["proof_id"],
                tier=r1["tier"],
                network=r1["network"],
                contract_id=r1["contract_id"],
            ).manifest
            c2pa_with_url = copy.deepcopy(c2pa_doc)
            c2pa_with_url["assertions"].append(
                {
                    "label": "c2pa.ingredient",
                    "data": {"active_manifest_uri": secret_url},
                }
            )
            with self.assertRaises(C2paParseError) as c2pa_ctx:
                extract_c2pa_portable_trust_reference(c2pa_with_url)
            self.assertEqual(c2pa_ctx.exception.reason, "remote_reference_prohibited")
            self.assertNotIn(secret_url, str(c2pa_ctx.exception))

            # 3. URL injected into serialized bundle before verify_portable_lineage_bundle
            valid_bundle = build_portable_lineage_bundle(
                d1_id, lineage_records=[d1], root_statements=[r1]
            )
            tampered_url_bundle = copy.deepcopy(valid_bundle)
            tampered_url_bundle["ancestry_statements"][0]["manifest"][
                "toolIdentity"
            ] = secret_url
            tampered_url_bundle = _recompute_bundle_digest(tampered_url_bundle)
            with self.assertRaises(LineageValidationError) as ctx3:
                verify_portable_lineage_bundle(tampered_url_bundle)
            self.assertNotIn(secret_url, str(ctx3.exception))

    def test_rejects_missing_parents_and_cycles(self) -> None:
        r1 = _make_root(0x01)
        missing_parent_id = _hex(0x77)
        d1_id = _hex(0x31)
        d2_id = _hex(0x32)

        # Missing parent on build
        d_missing = _make_lineage(d1_id, [r1["proof_id"], missing_parent_id], operation="compose")
        with self.assertRaises(LineageValidationError) as miss_ctx:
            build_portable_lineage_bundle(
                d1_id, lineage_records=[d_missing], root_statements=[r1]
            )
        self.assertIn("missing parent", str(miss_ctx.exception).lower())

        # Missing parent on verify (stripped root statement)
        valid_d1 = _make_lineage(d1_id, [r1["proof_id"]])
        bundle = build_portable_lineage_bundle(
            d1_id, lineage_records=[valid_d1], root_statements=[r1]
        )
        stripped = copy.deepcopy(bundle)
        stripped["root_statements"] = []
        stripped = _recompute_bundle_digest(stripped)
        with self.assertRaises(LineageValidationError):
            verify_portable_lineage_bundle(stripped)

        # Multi-hop cycle on build (d1 -> d2 -> d1)
        cyc_a = _make_lineage(d1_id, [d2_id])
        cyc_b = _make_lineage(d2_id, [d1_id])
        with self.assertRaises(LineageValidationError) as cyc_ctx:
            build_portable_lineage_bundle(
                d1_id, lineage_records=[cyc_a, cyc_b], root_statements=[r1]
            )
        self.assertIn("cycle", str(cyc_ctx.exception).lower())

    def test_rejects_contradictory_roots_and_silent_tier_identity_leak(self) -> None:
        r1 = _make_root(0x01)
        r1_conflicting_meta = dict(r1, metadata_hash=_hex(0xFE))
        d1_id = _hex(0x41)
        d1 = _make_lineage(d1_id, [r1["proof_id"]])

        # 1. Conflicting duplicate root statements for the same proof_id
        with self.assertRaises(LineageValidationError) as dup_ctx:
            build_portable_lineage_bundle(
                d1_id,
                lineage_records=[d1],
                root_statements=[r1, r1_conflicting_meta],
            )
        self.assertIn("contradictory", str(dup_ctx.exception).lower())

        # 2. Same digest claimed as both a root statement and a derivative
        colliding_root = dict(r1, proof_id=d1_id)
        with self.assertRaises(LineageValidationError) as role_ctx:
            build_portable_lineage_bundle(
                d1_id,
                lineage_records=[d1],
                root_statements=[r1, colliding_root],
            )
        self.assertIn("contradictory", str(role_ctx.exception).lower())

        # 3. Cross-root contract mismatch in composed closure
        r2_wrong_contract = _make_root(0x02, contract_id=OTHER_CONTRACT_C)
        d_comp = _make_lineage(
            d1_id, [r1["proof_id"], r2_wrong_contract["proof_id"]], operation="compose"
        )
        with self.assertRaises(LineageValidationError) as dom_ctx:
            build_portable_lineage_bundle(
                d1_id,
                lineage_records=[d_comp],
                root_statements=[r1, r2_wrong_contract],
            )
        self.assertIn("contradictory", str(dom_ctx.exception).lower())

        # 4. Contradictory C2PA binding for root statement
        bad_c2pa = export_c2pa_manifest(
            video_hash=r1["video_hash"],
            metadata_hash=_hex(0xFD),  # contradicts r1["metadata_hash"]
            proof_id=r1["proof_id"],
            tier=r1["tier"],
            network=r1["network"],
            contract_id=r1["contract_id"],
        )
        with self.assertRaises(LineageValidationError) as c2pa_ctx:
            build_portable_lineage_bundle(
                d1_id,
                lineage_records=[d1],
                root_statements=[r1],
                c2pa_manifests=[bad_c2pa],
            )
        self.assertIn("contradictory", str(c2pa_ctx.exception).lower())

        # 5. Silent Witness root statement leaking an actor identity
        leaky_silent_root = dict(_make_root(0x05, tier="silent"), source_address=ACTOR_G)
        with self.assertRaises(LineageValidationError) as tier_ctx:
            build_portable_lineage_bundle(
                leaky_silent_root["proof_id"],
                lineage_records=[],
                root_statements=[leaky_silent_root],
            )
        self.assertIn("silent tier", str(tier_ctx.exception).lower())

    def test_enforces_node_bounds_tamper_checks_and_orphan_rejection(self) -> None:
        r1 = _make_root(0x01)
        r2 = _make_root(0x02)
        d1_id = _hex(0x51)
        d1 = _make_lineage(d1_id, [r1["proof_id"]])

        # max_nodes bound
        with self.assertRaises(LineageValidationError):
            build_portable_lineage_bundle(
                d1_id, lineage_records=[d1], root_statements=[r1], max_nodes=1
            )

        bundle = build_portable_lineage_bundle(
            d1_id, lineage_records=[d1], root_statements=[r1]
        )

        # Tampered bundle_digest rejected
        bad_digest_bundle = dict(bundle, bundle_digest=_hex(0x99))
        with self.assertRaises(LineageValidationError):
            verify_portable_lineage_bundle(bad_digest_bundle)

        # Tampered parent_commitments rejected even if bundle_digest is recomputed
        bad_pc_bundle = copy.deepcopy(bundle)
        bad_pc_bundle["ancestry_statements"][0]["parent_commitments"] = [_hex(0x88)]
        bad_pc_bundle = _recompute_bundle_digest(bad_pc_bundle)
        with self.assertRaises(LineageValidationError):
            verify_portable_lineage_bundle(bad_pc_bundle)

        # Smuggled unreferenced root statement rejected even if bundle_digest is recomputed
        orphan_bundle = build_portable_lineage_bundle(
            r2["proof_id"], lineage_records=[], root_statements=[r2]
        )
        smuggled = copy.deepcopy(bundle)
        smuggled["root_statements"].append(orphan_bundle["root_statements"][0])
        smuggled = _recompute_bundle_digest(smuggled)
        with self.assertRaises(LineageValidationError) as smuggle_ctx:
            verify_portable_lineage_bundle(smuggled)
        self.assertIn("unreferenced", str(smuggle_ctx.exception).lower())


class PortableLineageBundleApiTests(unittest.TestCase):
    def setUp(self) -> None:
        from app import create_app

        self.app = create_app()
        self.client = self.app.test_client()

    def test_export_and_verify_bundle_endpoints(self) -> None:
        r1 = _make_root(0x01)
        d1_id = _hex(0x61)
        d1 = _make_lineage(d1_id, [r1["proof_id"]])

        export_resp = self.client.post(
            "/api/lineage/bundle/export",
            json={
                "targetDigest": d1_id,
                "lineageRecords": [d1],
                "rootStatements": [r1],
            },
        )
        self.assertEqual(export_resp.status_code, 200)
        bundle = export_resp.get_json()["bundle"]

        verify_resp = self.client.post(
            "/api/lineage/bundle/verify",
            json={"bundle": bundle},
        )
        self.assertEqual(verify_resp.status_code, 200)
        ver = verify_resp.get_json()["verification"]
        self.assertTrue(ver["valid"])
        self.assertEqual(ver["target_id"], d1_id)
        self.assertEqual(ver["max_depth"], 1)

        # Reject remote URL on verify endpoint without echoing URL
        bad_url = "https://evil.invalid/callback-secret-token"
        tampered = copy.deepcopy(bundle)
        tampered["fetch_url"] = bad_url
        bad_resp = self.client.post(
            "/api/lineage/bundle/verify",
            json={"bundle": tampered},
        )
        self.assertEqual(bad_resp.status_code, 400)
        self.assertNotIn(bad_url, bad_resp.get_json()["error"]["message"])


if __name__ == "__main__":
    unittest.main()
