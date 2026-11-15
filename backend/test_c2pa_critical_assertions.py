from __future__ import annotations

import json
import unittest

from app import create_app
from c2pa import (
    C2paParseError,
    evaluate_c2pa_assertion_compatibility,
    export_c2pa_manifest,
    parse_c2pa_manifest,
)
from lineage import LineageValidationError, validate_lineage_c2pa_compatibility


class C2paCriticalAssertionsTests(unittest.TestCase):
    VIDEO_HASH = "11" * 32
    META_HASH = "22" * 32
    PROOF_ID = "33" * 32
    CONTRACT = "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ"

    def _base_manifest(self) -> dict:
        return json.loads(
            json.dumps(
                export_c2pa_manifest(
                    video_hash=self.VIDEO_HASH,
                    metadata_hash=self.META_HASH,
                    proof_id=self.PROOF_ID,
                    tier="source",
                    network="Test SDF Network ; September 2015",
                    contract_id=self.CONTRACT,
                ).manifest
            )
        )

    def test_supported_and_optional_unknown_assertions_are_compatible(self) -> None:
        manifest = self._base_manifest()
        manifest["assertions"].extend(
            [
                {"label": "c2pa.actions", "data": {"actions": []}},
                {"label": "c2pa.thumbnail", "data": "thumb-ref", "critical": False},
            ]
        )

        report = evaluate_c2pa_assertion_compatibility(manifest)
        self.assertTrue(report.compatible)
        self.assertEqual(report.supported, ("harpocrates.binding/v1",))
        self.assertEqual(report.optional_unknown, ("c2pa.actions", "c2pa.thumbnail"))
        self.assertEqual(report.required_unknown, ())

        parsed = parse_c2pa_manifest(json.dumps(manifest))
        self.assertEqual(parsed.assertion_compatibility, report)
        self.assertEqual(
            validate_lineage_c2pa_compatibility(manifest),
            report.to_dict(),
        )

    def test_supported_assertion_marked_critical_remains_compatible(self) -> None:
        manifest = self._base_manifest()
        manifest["assertions"][0]["critical"] = True
        manifest["critical_assertions"] = ["harpocrates.binding/v1"]

        parsed = parse_c2pa_manifest(json.dumps(manifest))
        self.assertTrue(parsed.assertion_compatibility.compatible)
        self.assertEqual(
            parsed.assertion_compatibility.supported,
            ("harpocrates.binding/v1",),
        )
        self.assertEqual(parsed.assertion_compatibility.required_unknown, ())

    def test_unsupported_critical_assertion_reports_all_sets_and_fails_closed(self) -> None:
        secret_policy_payload = "TOP-SECRET-DRM-KEY-98765"
        manifest = self._base_manifest()
        manifest["assertions"].extend(
            [
                {"label": "c2pa.actions", "data": {"actions": []}},
                {
                    "label": "com.vendor.drm.gate/v2",
                    "critical": True,
                    "data": {"policy": secret_policy_payload},
                },
            ]
        )
        manifest["required_assertions"] = ["com.vendor.rights.lock/v1"]

        report = evaluate_c2pa_assertion_compatibility(manifest)
        self.assertFalse(report.compatible)
        self.assertEqual(report.supported, ("harpocrates.binding/v1",))
        self.assertEqual(report.optional_unknown, ("c2pa.actions",))
        self.assertEqual(
            report.required_unknown,
            ("com.vendor.drm.gate/v2", "com.vendor.rights.lock/v1"),
        )
        self.assertNotIn(secret_policy_payload, json.dumps(report.to_dict()))

        with self.assertRaises(C2paParseError) as ctx:
            parse_c2pa_manifest(json.dumps(manifest))
        self.assertEqual(ctx.exception.reason, "unsupported_critical_assertion")
        self.assertEqual(ctx.exception.field, "assertions[2]")
        self.assertEqual(ctx.exception.compatibility_report, report)
        self.assertEqual(
            ctx.exception.to_dict(),
            {"reason": "unsupported_critical_assertion", "field": "assertions[2]"},
        )
        self.assertNotIn(secret_policy_payload, str(ctx.exception))

        with self.assertRaises(LineageValidationError):
            validate_lineage_c2pa_compatibility(manifest)

    def test_non_boolean_critical_flag_and_invalid_critical_list_rejected(self) -> None:
        manifest_non_bool = self._base_manifest()
        manifest_non_bool["assertions"].append(
            {"label": "c2pa.custom", "critical": 1, "data": {}}
        )
        with self.assertRaises(C2paParseError) as ctx:
            parse_c2pa_manifest(json.dumps(manifest_non_bool))
        self.assertEqual(ctx.exception.reason, "invalid_type")
        self.assertEqual(ctx.exception.field, "assertions[1].critical")

        manifest_bad_list = self._base_manifest()
        manifest_bad_list["critical_assertions"] = "c2pa.custom"
        with self.assertRaises(C2paParseError) as ctx2:
            evaluate_c2pa_assertion_compatibility(manifest_bad_list)
        self.assertEqual(ctx2.exception.reason, "invalid_type")
        self.assertEqual(ctx2.exception.field, "critical_assertions")

    def test_http_import_fails_closed_while_compatibility_endpoint_lists_sets(self) -> None:
        manifest = self._base_manifest()
        manifest["assertions"].extend(
            [
                {"label": "c2pa.actions", "data": {}},
                {"label": "c2pa.restricted.exec", "is_critical": True, "data": {"secret": "xyz"}},
            ]
        )
        client = create_app().test_client()

        import_resp = client.post("/api/c2pa/import", json={"manifest": manifest})
        self.assertEqual(import_resp.status_code, 400)
        import_body = import_resp.get_json()
        self.assertFalse(import_body["ok"])
        self.assertIn("unsupported_critical_assertion", import_body["error"]["message"])
        self.assertNotIn("xyz", json.dumps(import_body))

        compat_resp = client.post("/api/c2pa/compatibility", json={"manifest": manifest})
        self.assertEqual(compat_resp.status_code, 200)
        compat_body = compat_resp.get_json()
        self.assertTrue(compat_body["ok"])
        self.assertEqual(compat_body["trust_status"], "parse_failed")
        self.assertEqual(
            compat_body["compatibility"],
            {
                "supported": ["harpocrates.binding/v1"],
                "optional_unknown": ["c2pa.actions"],
                "required_unknown": ["c2pa.restricted.exec"],
                "compatible": False,
            },
        )


if __name__ == "__main__":
    unittest.main()
