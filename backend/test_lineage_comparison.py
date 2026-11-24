import copy
import json
import unittest

from c2pa import export_c2pa_manifest, parse_c2pa_manifest
from lineage import (
    LINEAGE_COMPARISON_REPORT_VERSION,
    LineageBundleError,
    build_lineage_verification_bundle,
    canonical_lineage_comparison_report,
    compare_lineage_graphs,
    lineage_bundle_digest,
    lineage_comparison_report_digest,
    trust_reference_from_c2pa_binding,
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
    tool_version: str = "1.2.3",
    params: str | None = None,
) -> dict:
    return {
        "parentProofIds": parents,
        "operationType": operation,
        "parametersDigest": params or _hex("9"),
        "toolIdentity": tool,
        "toolVersion": tool_version,
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


class LineageGraphComparisonReportTests(unittest.TestCase):
    def test_identical_graphs_report_no_changes_and_deterministic_digest(self) -> None:
        root_a = _hex("a")
        leaf = _hex("b")
        bundle = build_lineage_verification_bundle(
            target_digest=leaf,
            network="testnet",
            statements=[_make_statement(output=leaf, parents=[root_a])],
            trust_references=[_make_trust_ref(root_a, tier="silent")],
        )

        report_1 = compare_lineage_graphs(bundle, copy.deepcopy(bundle))
        report_2 = compare_lineage_graphs(
            json.dumps(bundle), json.dumps(bundle).encode("utf-8")
        )

        self.assertEqual(report_1.protocol, "harpocrates")
        self.assertEqual(report_1.report_version, LINEAGE_COMPARISON_REPORT_VERSION)
        self.assertFalse(report_1.has_provenance_changes)
        self.assertFalse(report_1.has_ordering_differences)
        self.assertTrue(report_1.equivalent_provenance)
        self.assertFalse(report_1.target_changed)
        self.assertFalse(report_1.network_changed)
        self.assertEqual(report_1.added_assertions, ())
        self.assertEqual(report_1.removed_assertions, ())
        self.assertEqual(report_1.changed_assertions, ())
        self.assertEqual(report_1.ordering_differences, ())
        self.assertEqual(report_1.unchanged_assertion_count, 2)
        self.assertEqual(report_1.report_digest, report_2.report_digest)
        self.assertEqual(
            report_1.report_digest,
            lineage_comparison_report_digest(report_1.to_dict()),
        )
        self.assertEqual(
            canonical_lineage_comparison_report(report_1),
            canonical_lineage_comparison_report(report_1.to_dict()),
        )

    def test_separates_bundle_list_ordering_differences_from_provenance_changes(self) -> None:
        root_a = _hex("a")
        root_b = _hex("b")
        mid = _hex("c")
        leaf = _hex("d")

        before = build_lineage_verification_bundle(
            target_digest=leaf,
            network="testnet",
            statements=[
                _make_statement(output=mid, parents=[root_a], operation="blur"),
                _make_statement(output=leaf, parents=[mid, root_b], operation="compose"),
            ],
            trust_references=[
                _make_trust_ref(root_a, tier="silent"),
                _make_trust_ref(root_b, tier="source"),
            ],
        )

        # Reverse statements and trustReferences lists in raw bundle and recompute bundleDigest.
        after = copy.deepcopy(before)
        after["statements"] = list(reversed(after["statements"]))
        after["trustReferences"] = list(reversed(after["trustReferences"]))
        after["bundleDigest"] = lineage_bundle_digest(after)

        self.assertNotEqual(before["bundleDigest"], after["bundleDigest"])

        report = compare_lineage_graphs(before, after)
        self.assertFalse(report.has_provenance_changes)
        self.assertTrue(report.equivalent_provenance)
        self.assertTrue(report.has_ordering_differences)
        self.assertEqual(report.added_assertions, ())
        self.assertEqual(report.removed_assertions, ())
        self.assertEqual(report.changed_assertions, ())
        self.assertEqual(report.unchanged_assertion_count, 4)

        scopes = tuple(d.scope for d in report.ordering_differences)
        self.assertEqual(scopes, ("statements", "trust_references"))
        for diff in report.ordering_differences:
            self.assertIsNone(diff.assertion_id)
            self.assertEqual(diff.before_digest, before["bundleDigest"])
            self.assertEqual(diff.after_digest, after["bundleDigest"])

    def test_separates_statement_parent_reordering_from_provenance_changes(self) -> None:
        root_a = _hex("a")
        root_b = _hex("b")
        leaf = _hex("c")

        before = build_lineage_verification_bundle(
            target_digest=leaf,
            network="testnet",
            statements=[
                _make_statement(output=leaf, parents=[root_a, root_b], operation="compose")
            ],
            trust_references=[
                _make_trust_ref(root_a, tier="silent"),
                _make_trust_ref(root_b, tier="source"),
            ],
        )
        after = build_lineage_verification_bundle(
            target_digest=leaf,
            network="testnet",
            statements=[
                _make_statement(output=leaf, parents=[root_b, root_a], operation="compose")
            ],
            trust_references=[
                _make_trust_ref(root_a, tier="silent"),
                _make_trust_ref(root_b, tier="source"),
            ],
        )

        report = compare_lineage_graphs(before, after)
        self.assertFalse(report.has_provenance_changes)
        self.assertTrue(report.equivalent_provenance)
        self.assertTrue(report.has_ordering_differences)
        self.assertEqual(report.changed_assertions, ())
        self.assertEqual(report.unchanged_assertion_count, 3)
        self.assertEqual(len(report.ordering_differences), 1)
        diff = report.ordering_differences[0]
        self.assertEqual(diff.scope, "statement_parents")
        self.assertEqual(diff.assertion_id, leaf)
        self.assertNotEqual(diff.before_digest, diff.after_digest)

    def test_identifies_added_and_removed_assertions_by_canonical_digest(self) -> None:
        root_a = _hex("a")
        root_b = _hex("b")
        mid = _hex("c")
        leaf_before = _hex("d")
        leaf_after = _hex("e")

        before = build_lineage_verification_bundle(
            target_digest=leaf_before,
            network="testnet",
            statements=[
                _make_statement(output=mid, parents=[root_a], operation="blur"),
                _make_statement(output=leaf_before, parents=[mid], operation="crop"),
            ],
            trust_references=[_make_trust_ref(root_a, tier="silent")],
        )
        after = build_lineage_verification_bundle(
            target_digest=leaf_after,
            network="testnet",
            statements=[
                _make_statement(output=mid, parents=[root_a], operation="blur"),
                _make_statement(output=leaf_after, parents=[mid, root_b], operation="compose"),
            ],
            trust_references=[
                _make_trust_ref(root_a, tier="silent"),
                _make_trust_ref(root_b, tier="seal"),
            ],
        )

        report = compare_lineage_graphs(before, after)
        self.assertTrue(report.has_provenance_changes)
        self.assertFalse(report.equivalent_provenance)
        self.assertTrue(report.target_changed)
        self.assertFalse(report.network_changed)
        self.assertEqual(report.unchanged_assertion_count, 2)  # mid + root_a

        self.assertEqual(
            [(e.kind, e.assertion_id) for e in report.added_assertions],
            [("statement", leaf_after), ("trust_reference", root_b)],
        )
        self.assertEqual(
            [(e.kind, e.assertion_id) for e in report.removed_assertions],
            [("statement", leaf_before)],
        )
        self.assertEqual(report.changed_assertions, ())

    def test_identifies_changed_statement_and_trust_reference_without_leaking_values(self) -> None:
        root_a = _hex("a")
        leaf = _hex("b")

        exported = export_c2pa_manifest(
            video_hash=_hex("1"),
            metadata_hash=_hex("2"),
            proof_id=root_a,
            tier="source",
            network="testnet",
            contract_id="CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ",
        )
        parsed = parse_c2pa_manifest(json.dumps(exported.manifest))
        c2pa_ref = trust_reference_from_c2pa_binding(parsed.binding, c2pa_digest=exported.digest)

        before = build_lineage_verification_bundle(
            target_digest=leaf,
            network="testnet",
            statements=[
                _make_statement(
                    output=leaf,
                    parents=[root_a],
                    operation="crop",
                    actor="GSENSITIVEACTORBEFORE",
                    tool_version="1.0.0",
                )
            ],
            trust_references=[_make_trust_ref(root_a, tier="silent", anchor_type="onchain_proof")],
        )
        after = build_lineage_verification_bundle(
            target_digest=leaf,
            network="testnet",
            statements=[
                _make_statement(
                    output=leaf,
                    parents=[root_a],
                    operation="redact",
                    actor="GSENSITIVEACTORAFTER",
                    tool_version="2.0.0",
                )
            ],
            trust_references=[c2pa_ref],
        )

        report = compare_lineage_graphs(before, after)
        self.assertTrue(report.has_provenance_changes)
        self.assertFalse(report.has_ordering_differences)
        self.assertEqual(report.unchanged_assertion_count, 0)
        self.assertEqual(len(report.changed_assertions), 2)

        stmt_change = report.changed_assertions[0]
        self.assertEqual(stmt_change.kind, "statement")
        self.assertEqual(stmt_change.assertion_id, leaf)
        self.assertEqual(
            stmt_change.changed_fields,
            ("actorAddress", "operationType", "toolVersion"),
        )
        self.assertNotEqual(stmt_change.before_digest, stmt_change.after_digest)
        self.assertNotEqual(
            stmt_change.before_provenance_digest, stmt_change.after_provenance_digest
        )

        trust_change = report.changed_assertions[1]
        self.assertEqual(trust_change.kind, "trust_reference")
        self.assertEqual(trust_change.assertion_id, root_a)
        self.assertIn("tier", trust_change.changed_fields)
        self.assertIn("trustAnchorType", trust_change.changed_fields)

        # Privacy check: raw actor identifiers must never appear in the serialized report.
        serialized = json.dumps(report.to_dict())
        self.assertNotIn("GSENSITIVEACTORBEFORE", serialized)
        self.assertNotIn("GSENSITIVEACTORAFTER", serialized)

    def test_fail_closed_rejects_invalid_bundle_on_either_side(self) -> None:
        root_a = _hex("a")
        leaf = _hex("b")
        valid = build_lineage_verification_bundle(
            target_digest=leaf,
            network="testnet",
            statements=[_make_statement(output=leaf, parents=[root_a])],
            trust_references=[_make_trust_ref(root_a)],
        )

        # Tampered bundleDigest
        tampered = copy.deepcopy(valid)
        tampered["bundleDigest"] = _hex("0")
        with self.assertRaises(LineageBundleError) as ctx:
            compare_lineage_graphs(valid, tampered)
        self.assertEqual(ctx.exception.reason, "bundle_digest_mismatch")

        # External URL in before bundle
        with_url = copy.deepcopy(valid)
        with_url["remoteUrl"] = "https://attacker.example/manifest.json"
        with self.assertRaises(LineageBundleError) as ctx_url:
            compare_lineage_graphs(with_url, valid)
        self.assertEqual(ctx_url.exception.reason, "external_url_forbidden")

        # Invalid report input to canonicalizer
        with self.assertRaises(LineageBundleError) as ctx_rep:
            canonical_lineage_comparison_report("not-a-dict")  # type: ignore[arg-type]
        self.assertEqual(ctx_rep.exception.reason, "invalid_comparison_report")


if __name__ == "__main__":
    unittest.main()
