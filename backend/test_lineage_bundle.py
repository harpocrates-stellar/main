import json
import unittest

from c2pa import export_c2pa_manifest, parse_c2pa_manifest
from lineage import (
    LINEAGE_BUNDLE_VERSION,
    MAX_BUNDLE_BYTES,
    MAX_LINEAGE_DEPTH,
    LineageBundleError,
    LineageMissingDependency,
    LineageVerificationStatus,
    LineageVerifiedEdge,
    build_lineage_verification_bundle,
    canonical_lineage_bundle,
    lineage_bundle_digest,
    trust_reference_from_c2pa_binding,
    verify_lineage_verification_bundle,
)


def _hex(ch: str) -> str:
    return ch * 64


def _make_statement(
    *,
    output: str,
    parents: list[str],
    operation: str = "crop",
    network: str = "testnet",
    actor: str = "GAJC123",
    tool: str = "harpocrates-studio",
) -> dict:
    return {
        "parentProofIds": parents,
        "operationType": operation,
        "parametersDigest": _hex("9"),
        "toolIdentity": tool,
        "toolVersion": "1.2.3",
        "outputDigest": output,
        "network": network,
        "actorAddress": actor,
    }


def _make_trust_ref(
    proof_id: str,
    *,
    network: str = "testnet",
    contract_id: str = "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ",
    tier: str = "silent",
    anchor_type: str = "onchain_proof",
) -> dict:
    return {
        "proofId": proof_id,
        "network": network,
        "contractId": contract_id,
        "tier": tier,
        "trustAnchorType": anchor_type,
    }


class PortableLineageBundleTests(unittest.TestCase):
    def test_build_and_verify_single_hop_bundle(self) -> None:
        root_id = _hex("a")
        leaf_id = _hex("b")
        bundle = build_lineage_verification_bundle(
            target_digest=leaf_id,
            network="testnet",
            statements=[_make_statement(output=leaf_id, parents=[root_id])],
            trust_references=[_make_trust_ref(root_id, tier="silent")],
        )

        self.assertEqual(bundle["protocol"], "harpocrates")
        self.assertEqual(bundle["bundleVersion"], LINEAGE_BUNDLE_VERSION)
        self.assertEqual(bundle["bundleDigest"], lineage_bundle_digest(bundle))

        result = verify_lineage_verification_bundle(bundle)
        self.assertTrue(result.valid)
        self.assertEqual(result.target_digest, leaf_id)
        self.assertEqual(result.statement_count, 1)
        self.assertEqual(result.root_proof_ids, (root_id,))
        self.assertEqual(result.max_depth_observed, 1)
        self.assertEqual(result.tiers, ("silent",))
        self.assertEqual(result.trust_anchor_types, ("onchain_proof",))

    def test_canonical_encoding_is_order_independent_and_roundtrips_json(self) -> None:
        root_a = _hex("a")
        root_b = _hex("b")
        mid = _hex("c")
        leaf = _hex("d")

        stmt_mid = _make_statement(output=mid, parents=[root_a], operation="blur")
        stmt_leaf = _make_statement(output=leaf, parents=[mid, root_b], operation="compose")
        ref_a = _make_trust_ref(root_a, tier="silent")
        ref_b = _make_trust_ref(root_b, tier="source")

        bundle_1 = build_lineage_verification_bundle(
            target_digest=leaf,
            network="testnet",
            statements=[stmt_mid, stmt_leaf],
            trust_references=[ref_a, ref_b],
        )
        bundle_2 = build_lineage_verification_bundle(
            target_digest=leaf,
            network="testnet",
            statements=[stmt_leaf, stmt_mid],
            trust_references=[ref_b, ref_a],
        )

        self.assertEqual(canonical_lineage_bundle(bundle_1), canonical_lineage_bundle(bundle_2))
        self.assertEqual(bundle_1["bundleDigest"], bundle_2["bundleDigest"])

        # Round-trip through JSON string and bytes
        serialized = json.dumps(bundle_1)
        res_str = verify_lineage_verification_bundle(serialized)
        res_bytes = verify_lineage_verification_bundle(serialized.encode("utf-8"))
        self.assertEqual(res_str, res_bytes)
        self.assertEqual(res_str.max_depth_observed, 2)
        self.assertEqual(res_str.root_proof_ids, (root_a, root_b))
        self.assertEqual(res_str.tiers, ("silent", "source"))

    def test_c2pa_binding_bridge_preserves_trust_separation(self) -> None:
        root_id = _hex("1")
        leaf_id = _hex("2")
        exported = export_c2pa_manifest(
            video_hash=_hex("3"),
            metadata_hash=_hex("4"),
            proof_id=root_id,
            tier="seal",
            network="testnet",
            contract_id="CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ",
        )
        parsed = parse_c2pa_manifest(json.dumps(exported.manifest))
        c2pa_ref = trust_reference_from_c2pa_binding(
            parsed.binding, c2pa_digest=exported.digest
        )

        bundle = build_lineage_verification_bundle(
            target_digest=leaf_id,
            network="testnet",
            statements=[_make_statement(output=leaf_id, parents=[root_id], operation="redact")],
            trust_references=[c2pa_ref],
        )
        result = verify_lineage_verification_bundle(bundle)
        self.assertTrue(result.valid)
        self.assertEqual(result.trust_anchor_types, ("c2pa_binding",))
        self.assertEqual(result.tiers, ("seal",))

    def test_rejects_missing_parent(self) -> None:
        root_id = _hex("a")
        missing_parent = _hex("f")
        leaf_id = _hex("b")

        with self.assertRaises(LineageBundleError) as ctx:
            build_lineage_verification_bundle(
                target_digest=leaf_id,
                network="testnet",
                statements=[_make_statement(output=leaf_id, parents=[root_id, missing_parent])],
                trust_references=[_make_trust_ref(root_id)],
            )
        self.assertEqual(ctx.exception.reason, "missing_parent")
        # Privacy check: digest must not leak in error payload
        self.assertNotIn(missing_parent, str(ctx.exception))
        self.assertNotIn(missing_parent, json.dumps(ctx.exception.to_dict()))

    def test_rejects_direct_and_transitive_cycles(self) -> None:
        # Direct self-cycle
        node_a = _hex("a")
        with self.assertRaises(LineageBundleError) as ctx_direct:
            build_lineage_verification_bundle(
                target_digest=node_a,
                network="testnet",
                statements=[_make_statement(output=node_a, parents=[node_a])],
                trust_references=[_make_trust_ref(_hex("f"))],
            )
        self.assertEqual(ctx_direct.exception.reason, "cycle_detected")

        # Multi-hop cycle: a -> b -> a
        node_b = _hex("b")
        with self.assertRaises(LineageBundleError) as ctx_multi:
            build_lineage_verification_bundle(
                target_digest=node_a,
                network="testnet",
                statements=[
                    _make_statement(output=node_a, parents=[node_b]),
                    _make_statement(output=node_b, parents=[node_a]),
                ],
                trust_references=[_make_trust_ref(_hex("f"))],
            )
        self.assertEqual(ctx_multi.exception.reason, "cycle_detected")

    def test_rejects_contradictory_roots(self) -> None:
        root_id = _hex("a")
        leaf_id = _hex("b")

        # 1. Duplicate/conflicting trust reference for same root proofId
        with self.assertRaises(LineageBundleError) as ctx_dup:
            build_lineage_verification_bundle(
                target_digest=leaf_id,
                network="testnet",
                statements=[_make_statement(output=leaf_id, parents=[root_id])],
                trust_references=[
                    _make_trust_ref(root_id, tier="silent"),
                    _make_trust_ref(root_id, tier="seal"),
                ],
            )
        self.assertEqual(ctx_dup.exception.reason, "contradictory_root")

        # 2. Root proofId also claimed as a derived statement outputDigest
        with self.assertRaises(LineageBundleError) as ctx_derived:
            build_lineage_verification_bundle(
                target_digest=leaf_id,
                network="testnet",
                statements=[
                    _make_statement(output=leaf_id, parents=[root_id]),
                    _make_statement(output=root_id, parents=[_hex("c")]),
                ],
                trust_references=[
                    _make_trust_ref(root_id),
                    _make_trust_ref(_hex("c")),
                ],
            )
        self.assertEqual(ctx_derived.exception.reason, "contradictory_root")

        # 3. Root network disagrees with bundle network
        with self.assertRaises(LineageBundleError) as ctx_net:
            build_lineage_verification_bundle(
                target_digest=leaf_id,
                network="testnet",
                statements=[_make_statement(output=leaf_id, parents=[root_id], network="testnet")],
                trust_references=[_make_trust_ref(root_id, network="mainnet")],
            )
        self.assertEqual(ctx_net.exception.reason, "contradictory_root")

    def test_rejects_arbitrary_external_urls(self) -> None:
        root_id = _hex("a")
        leaf_id = _hex("b")

        # URL in trust reference contractId
        with self.assertRaises(LineageBundleError) as ctx_url_val:
            build_lineage_verification_bundle(
                target_digest=leaf_id,
                network="testnet",
                statements=[_make_statement(output=leaf_id, parents=[root_id])],
                trust_references=[
                    _make_trust_ref(root_id, contract_id="https://evil.example/trust.json")
                ],
            )
        self.assertEqual(ctx_url_val.exception.reason, "external_url_forbidden")

        # Forbidden URL key on trust reference
        ref_with_url = _make_trust_ref(root_id)
        ref_with_url["url"] = "https://evil.example/manifest.json"
        with self.assertRaises(LineageBundleError) as ctx_url_key:
            build_lineage_verification_bundle(
                target_digest=leaf_id,
                network="testnet",
                statements=[_make_statement(output=leaf_id, parents=[root_id])],
                trust_references=[ref_with_url],
            )
        self.assertEqual(ctx_url_key.exception.reason, "external_url_forbidden")

    def test_rejects_depth_exceeding_bound(self) -> None:
        # Build a chain of depth MAX_LINEAGE_DEPTH + 1 (5 statements)
        ids = [_hex(str(i)) for i in range(MAX_LINEAGE_DEPTH + 2)]
        statements = [
            _make_statement(output=ids[i + 1], parents=[ids[i]])
            for i in range(MAX_LINEAGE_DEPTH + 1)
        ]
        with self.assertRaises(LineageBundleError) as ctx:
            build_lineage_verification_bundle(
                target_digest=ids[-1],
                network="testnet",
                statements=statements,
                trust_references=[_make_trust_ref(ids[0])],
            )
        self.assertEqual(ctx.exception.reason, "depth_exceeded")

    def test_rejects_node_limit_and_size_limit(self) -> None:
        root_id = _hex("a")
        mid_id = _hex("b")
        leaf_id = _hex("c")
        with self.assertRaises(LineageBundleError) as ctx_nodes:
            build_lineage_verification_bundle(
                target_digest=leaf_id,
                network="testnet",
                statements=[
                    _make_statement(output=mid_id, parents=[root_id]),
                    _make_statement(output=leaf_id, parents=[mid_id]),
                ],
                trust_references=[_make_trust_ref(root_id)],
                max_nodes=1,
            )
        self.assertEqual(ctx_nodes.exception.reason, "node_limit_exceeded")

        oversized = b"{" + (b" " * MAX_BUNDLE_BYTES) + b"}"
        with self.assertRaises(LineageBundleError) as ctx_size:
            verify_lineage_verification_bundle(oversized)
        self.assertEqual(ctx_size.exception.reason, "bundle_too_large")

    def test_rejects_tampered_bundle_digest_and_disconnected_nodes(self) -> None:
        root_id = _hex("a")
        leaf_id = _hex("b")
        bundle = build_lineage_verification_bundle(
            target_digest=leaf_id,
            network="testnet",
            statements=[_make_statement(output=leaf_id, parents=[root_id])],
            trust_references=[_make_trust_ref(root_id)],
        )

        tampered = dict(bundle)
        tampered["bundleDigest"] = _hex("0")
        with self.assertRaises(LineageBundleError) as ctx_tamper:
            verify_lineage_verification_bundle(tampered)
        self.assertEqual(ctx_tamper.exception.reason, "bundle_digest_mismatch")

        # Disconnected orphan statement
        with self.assertRaises(LineageBundleError) as ctx_orphan:
            build_lineage_verification_bundle(
                target_digest=leaf_id,
                network="testnet",
                statements=[
                    _make_statement(output=leaf_id, parents=[root_id]),
                    _make_statement(output=_hex("e"), parents=[root_id]),
                ],
                trust_references=[_make_trust_ref(root_id)],
            )
        self.assertEqual(ctx_orphan.exception.reason, "disconnected_statement")


class IncompleteLineageVerificationTests(unittest.TestCase):
    def _make_raw_bundle(
        self,
        *,
        target_digest: str,
        statements: list[dict],
        trust_references: list[dict],
        network: str = "testnet",
    ) -> dict:
        bundle = {
            "protocol": "harpocrates",
            "bundleVersion": LINEAGE_BUNDLE_VERSION,
            "targetDigest": target_digest,
            "network": network,
            "statements": statements,
            "trustReferences": trust_references,
        }
        bundle["bundleDigest"] = lineage_bundle_digest(bundle)
        return bundle

    def test_complete_bundle_reports_verified_status_and_edges(self) -> None:
        root_id = _hex("a")
        mid_id = _hex("b")
        leaf_id = _hex("c")
        bundle = build_lineage_verification_bundle(
            target_digest=leaf_id,
            network="testnet",
            statements=[
                _make_statement(output=mid_id, parents=[root_id], operation="blur"),
                _make_statement(output=leaf_id, parents=[mid_id], operation="crop"),
            ],
            trust_references=[_make_trust_ref(root_id, tier="silent")],
        )

        result = verify_lineage_verification_bundle(bundle, allow_incomplete=True)
        self.assertTrue(result.valid)
        self.assertTrue(result.complete)
        self.assertEqual(result.status, LineageVerificationStatus.VERIFIED)
        self.assertEqual(result.missing_dependencies, ())
        self.assertEqual(len(result.verified_edges), 2)
        self.assertEqual(
            {(e.child_digest, e.parent_id, e.parent_kind, e.operation_type) for e in result.verified_edges},
            {
                (mid_id, root_id, "trust_reference", "blur"),
                (leaf_id, mid_id, "statement", "crop"),
            },
        )
        payload = result.to_dict()
        self.assertEqual(payload["status"], "verified")
        self.assertTrue(payload["valid"])
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["missingDependencies"], [])
        self.assertEqual(len(payload["verifiedEdges"]), 2)

    def test_partial_bundle_exposes_incomplete_status_verified_edges_and_missing_deps(self) -> None:
        root_a = _hex("a")
        missing_root = _hex("f")
        mid_a = _hex("b")
        mid_b = _hex("c")
        leaf = _hex("d")

        # mid_a is anchored at root_a and also depends on missing_root;
        # mid_b depends only on missing_root; leaf composes mid_a and mid_b.
        raw_bundle = self._make_raw_bundle(
            target_digest=leaf,
            statements=[
                _make_statement(output=mid_a, parents=[root_a, missing_root], operation="compose"),
                _make_statement(output=mid_b, parents=[missing_root], operation="blur"),
                _make_statement(output=leaf, parents=[mid_a, mid_b], operation="crop"),
            ],
            trust_references=[_make_trust_ref(root_a, tier="source")],
        )

        # Default mode remains fail-closed.
        with self.assertRaises(LineageBundleError) as ctx:
            verify_lineage_verification_bundle(raw_bundle)
        self.assertEqual(ctx.exception.reason, "missing_parent")

        # Incomplete mode exposes a distinct non-valid INCOMPLETE result.
        result = verify_lineage_verification_bundle(raw_bundle, allow_incomplete=True)
        self.assertFalse(result.valid)
        self.assertFalse(result.complete)
        self.assertEqual(result.status, LineageVerificationStatus.INCOMPLETE)
        self.assertEqual(result.root_proof_ids, (root_a,))
        self.assertEqual(result.tiers, ("source",))
        self.assertEqual(result.trust_anchor_types, ("onchain_proof",))
        self.assertEqual(
            result.missing_dependencies,
            (
                LineageMissingDependency(
                    parent_id=missing_root,
                    referenced_by=(mid_a, mid_b),
                    reason="missing_parent",
                ),
            ),
        )
        self.assertEqual(
            [(e.child_digest, e.parent_id, e.parent_kind) for e in result.verified_edges],
            [
                (mid_a, root_a, "trust_reference"),
                (leaf, mid_a, "statement"),
                (leaf, mid_b, "statement"),
            ],
        )
        payload = result.to_dict()
        self.assertEqual(payload["status"], "incomplete")
        self.assertFalse(payload["valid"])
        self.assertFalse(payload["complete"])
        self.assertEqual(
            payload["missingDependencies"],
            [{"parentId": missing_root, "referencedBy": [mid_a, mid_b], "reason": "missing_parent"}],
        )

    def test_unanchored_bundle_with_no_trust_references_is_incomplete_not_verified_original(self) -> None:
        missing_parent = _hex("e")
        leaf = _hex("b")
        raw_bundle = self._make_raw_bundle(
            target_digest=leaf,
            statements=[_make_statement(output=leaf, parents=[missing_parent], operation="redact")],
            trust_references=[],
        )

        # Default mode rejects empty trustReferences.
        with self.assertRaises(LineageBundleError) as ctx:
            verify_lineage_verification_bundle(raw_bundle)
        self.assertEqual(ctx.exception.reason, "empty_trust_references")

        # Incomplete mode never presents this as a verified original.
        result = verify_lineage_verification_bundle(raw_bundle, allow_incomplete=True)
        self.assertFalse(result.valid)
        self.assertFalse(result.complete)
        self.assertEqual(result.status, LineageVerificationStatus.INCOMPLETE)
        self.assertEqual(result.root_proof_ids, ())
        self.assertEqual(result.tiers, ())
        self.assertEqual(result.trust_anchor_types, ())
        self.assertEqual(result.verified_edges, ())
        self.assertEqual(
            result.missing_dependencies,
            (LineageMissingDependency(parent_id=missing_parent, referenced_by=(leaf,)),),
        )

    def test_incomplete_mode_still_fails_closed_on_cycles_and_tampering(self) -> None:
        node_a = _hex("a")
        node_b = _hex("b")
        missing = _hex("f")

        cyclic_bundle = self._make_raw_bundle(
            target_digest=node_a,
            statements=[
                _make_statement(output=node_a, parents=[node_b, missing], operation="compose"),
                _make_statement(output=node_b, parents=[node_a], operation="crop"),
            ],
            trust_references=[],
        )
        with self.assertRaises(LineageBundleError) as ctx_cycle:
            verify_lineage_verification_bundle(cyclic_bundle, allow_incomplete=True)
        self.assertEqual(ctx_cycle.exception.reason, "cycle_detected")

        tampered = self._make_raw_bundle(
            target_digest=node_a,
            statements=[_make_statement(output=node_a, parents=[missing], operation="crop")],
            trust_references=[],
        )
        tampered["bundleDigest"] = _hex("0")
        with self.assertRaises(LineageBundleError) as ctx_tamper:
            verify_lineage_verification_bundle(tampered, allow_incomplete=True)
        self.assertEqual(ctx_tamper.exception.reason, "bundle_digest_mismatch")
