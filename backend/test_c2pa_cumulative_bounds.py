from __future__ import annotations

import json
import unittest

from app import create_app
from c2pa import (
    C2paParseError,
    export_c2pa_manifest,
    parse_c2pa_ingredient_graph,
    parse_c2pa_manifest,
)
from lineage import LineageValidationError, validate_lineage_c2pa_graph_bounds


class C2paCumulativeBoundsTests(unittest.TestCase):
    CONTRACT = "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ"

    def _manifest_dict(self, tag_byte: str = "11") -> dict:
        return json.loads(
            json.dumps(
                export_c2pa_manifest(
                    video_hash=tag_byte * 32,
                    metadata_hash="22" * 32,
                    proof_id=tag_byte * 32,
                    tier="source",
                    network="Test SDF Network ; September 2015",
                    contract_id=self.CONTRACT,
                ).manifest
            )
        )

    def test_valid_nested_ingredients_accumulate_shared_stats(self) -> None:
        ing_a = self._manifest_dict("a1")
        ing_b = self._manifest_dict("b2")
        root = self._manifest_dict("c3")
        root["ingredients"] = [
            {"manifest": ing_a},
            {"manifest": json.dumps(ing_b, separators=(",", ":"))},
        ]

        parsed = parse_c2pa_manifest(json.dumps(root, separators=(",", ":")))
        self.assertEqual(len(parsed.nested_ingredients), 2)
        self.assertEqual(parsed.expansion_stats["manifest_count"], 3)
        self.assertGreater(parsed.expansion_stats["consumed_nodes"], 30)
        self.assertGreater(parsed.expansion_stats["consumed_bytes"], 1000)

    def test_cumulative_node_limit_enforced_across_wide_nested_ingredients(self) -> None:
        # Each ingredient is shallow (depth <= 5) and tiny in bytes, with ~200 scalar
        # nodes. Individually every ingredient is well within limits, but 12 sibling
        # ingredients exceed the 2048 whole-graph node cap.
        root = self._manifest_dict("11")
        root["ingredients"] = [
            {
                "manifest": {
                    "claim_generator": "ext/1.0",
                    "assertions": [
                        {"label": "c2pa.meta", "data": list(range(200))},
                    ],
                }
            }
            for _ in range(12)
        ]

        raw = json.dumps(root, separators=(",", ":"))
        self.assertLess(len(raw.encode("utf-8")), 32 * 1024)

        with self.assertRaises(C2paParseError) as ctx:
            parse_c2pa_manifest(raw)
        self.assertEqual(ctx.exception.reason, "cumulative_nodes_exceeded")

        client = create_app().test_client()
        resp = client.post("/api/c2pa/import", json={"manifest": root})
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("cumulative_nodes_exceeded", body["error"]["message"])

    def test_cumulative_byte_limit_does_not_reset_for_nested_string_manifests(self) -> None:
        ing_1 = self._manifest_dict("a1")
        ing_1["assertions"].append({"label": "c2pa.pad", "data": "x" * 1200})
        ing_2 = self._manifest_dict("b2")
        ing_2["assertions"].append({"label": "c2pa.pad", "data": "y" * 1200})

        ing_1_str = json.dumps(ing_1, separators=(",", ":"))
        ing_2_str = json.dumps(ing_2, separators=(",", ":"))

        root = self._manifest_dict("c3")
        root["ingredients"] = [{"manifest": ing_1_str}, {"manifest": ing_2_str}]
        raw_root = json.dumps(root, separators=(",", ":"))

        # Single ingredient passes under a 7500-byte cumulative cap, while root + 2
        # expanded string-encoded nested manifests exceed 7500 bytes cumulatively.
        single_parsed = parse_c2pa_manifest(ing_1_str, max_cumulative_bytes=7500)
        self.assertEqual(single_parsed.binding.video_hash, "a1" * 32)

        with self.assertRaises(C2paParseError) as ctx:
            parse_c2pa_manifest(raw_root, max_cumulative_bytes=7500)
        self.assertEqual(ctx.exception.reason, "cumulative_bytes_exceeded")
        self.assertIn("ingredients[", ctx.exception.field or "")

    def test_multi_manifest_ingredient_graph_shares_cumulative_budget(self) -> None:
        manifests = [self._manifest_dict(f"{i:02x}") for i in range(1, 6)]
        single_size = len(json.dumps(manifests[0], separators=(",", ":")).encode("utf-8"))

        # Cap allows 2 manifests (~2x single_size) but rejects 5 manifests (~5x single_size)
        cap = single_size * 3
        ok_two = parse_c2pa_ingredient_graph(manifests[:2], max_cumulative_bytes=cap)
        self.assertEqual(len(ok_two), 2)

        with self.assertRaises(C2paParseError) as ctx:
            parse_c2pa_ingredient_graph(manifests, max_cumulative_bytes=cap)
        self.assertEqual(ctx.exception.reason, "cumulative_bytes_exceeded")

        with self.assertRaises(LineageValidationError):
            validate_lineage_c2pa_graph_bounds(manifests, max_cumulative_bytes=cap)

    def test_depth_and_manifest_count_do_not_reset_across_nested_ingredients(self) -> None:
        # Chain 8 levels of string-encoded nested ingredient manifests: each string
        # JSON has local depth ~4, but cumulative depth across the chain exceeds 16.
        current = self._manifest_dict("01")
        for step in range(2, 10):
            outer = self._manifest_dict(f"{step:02x}")
            outer["ingredients"] = [
                {"manifest": json.dumps(current, separators=(",", ":"))}
            ]
            current = outer

        with self.assertRaises(C2paParseError) as depth_ctx:
            parse_c2pa_manifest(json.dumps(current, separators=(",", ":")))
        self.assertEqual(depth_ctx.exception.reason, "depth_exceeded")

        # Exceed nested manifest count cap with flat sibling ingredients
        flat_root = self._manifest_dict("fe")
        flat_root["ingredients"] = [
            {"manifest": self._manifest_dict(f"{idx:02x}")} for idx in range(1, 35)
        ]
        with self.assertRaises(C2paParseError) as count_ctx:
            parse_c2pa_manifest(
                json.dumps(flat_root, separators=(",", ":")),
                max_cumulative_nodes=20000,
            )
        self.assertEqual(count_ctx.exception.reason, "cumulative_manifests_exceeded")


if __name__ == "__main__":
    unittest.main()
