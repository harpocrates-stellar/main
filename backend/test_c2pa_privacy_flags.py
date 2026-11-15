from __future__ import annotations

import json
import unittest

from app import create_app
from c2pa import (
    C2paParseError,
    export_c2pa_manifest,
    parse_c2pa_manifest,
    summarize_c2pa_manifest,
)
from lineage import summarize_lineage_ingredient_privacy


class C2paPrivacyFlagsTests(unittest.TestCase):
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
                    tier="silent",
                    network="Test SDF Network ; September 2015",
                    contract_id=self.CONTRACT,
                ).manifest
            )
        )

    def test_clean_manifest_reports_no_privacy_flags_and_preserves_binding_digests(self) -> None:
        manifest = self._base_manifest()
        parsed = parse_c2pa_manifest(json.dumps(manifest))

        self.assertFalse(parsed.privacy_summary.has_source_location)
        self.assertFalse(parsed.privacy_summary.has_identifying_metadata)
        self.assertEqual(parsed.privacy_summary.flagged_categories, ())
        self.assertEqual(
            parsed.privacy_summary.asserted_digests,
            (self.VIDEO_HASH, self.META_HASH, self.PROOF_ID),
        )

    def test_source_location_and_identifying_metadata_flagged_without_leaking_values(self) -> None:
        ing_digest_upper = ("AB" * 32)
        asset_digest = ("44" * 32)
        manifest = self._base_manifest()
        manifest["ingredients"] = [
            {
                "title": "confidential_witness_raw_take_04",
                "filename": "IMG_9921_UNREDACTED",
                "source_uri": "file:///Users/journalist/Private/clip_04",
                "hash": ing_digest_upper,
                "device_serial": "SN-CANON-99887766",
            }
        ]
        manifest["assertions"].extend(
            [
                {
                    "label": "stds.exif",
                    "data": {
                        "exif:GPSLatitude": "37.7749 N",
                        "exif:GPSLongitude": "122.4194 W",
                    },
                },
                {
                    "label": "c2pa.ingredient.v3",
                    "data": {
                        "dc:creator": "Jane Doe (Protected Source)",
                        "asset_hash": asset_digest,
                    },
                },
            ]
        )

        parsed = parse_c2pa_manifest(json.dumps(manifest))
        summary = summarize_c2pa_manifest(parsed)
        lineage_summary = summarize_lineage_ingredient_privacy(manifest)
        self.assertEqual(summary, lineage_summary)

        ps = summary["privacy_summary"]
        self.assertTrue(ps["has_source_location"])
        self.assertTrue(ps["has_identifying_metadata"])
        self.assertEqual(
            ps["flagged_categories"],
            [
                "creator_identity",
                "device_identifier",
                "local_filename",
                "source_location",
                "source_uri",
            ],
        )
        self.assertEqual(
            ps["asserted_digests"],
            sorted(
                [
                    self.VIDEO_HASH,
                    self.META_HASH,
                    self.PROOF_ID,
                    ing_digest_upper.lower(),
                    asset_digest,
                ]
            ),
        )

        serialized = json.dumps(summary)
        for private_val in (
            "confidential_witness_raw_take_04",
            "IMG_9921_UNREDACTED",
            "file:///Users/journalist",
            "SN-CANON-99887766",
            "37.7749",
            "122.4194",
            "Jane Doe",
        ):
            self.assertNotIn(private_val, serialized)

    def test_non_hex_digest_values_and_blank_fields_are_excluded(self) -> None:
        manifest = self._base_manifest()
        manifest["ingredients"] = [
            {
                "hash": "not-a-valid-hex-digest-secret-token",
                "author": "   ",
                "gps": "",
                "location": [],
            }
        ]
        parsed = parse_c2pa_manifest(json.dumps(manifest))
        ps = parsed.privacy_summary
        self.assertFalse(ps.has_source_location)
        self.assertFalse(ps.has_identifying_metadata)
        self.assertNotIn("not-a-valid-hex-digest-secret-token", ps.asserted_digests)

    def test_invalid_ingredients_type_rejected_fail_closed(self) -> None:
        manifest = self._base_manifest()
        manifest["ingredients"] = "not-an-array"
        with self.assertRaises(C2paParseError) as ctx:
            parse_c2pa_manifest(json.dumps(manifest))
        self.assertEqual(ctx.exception.reason, "invalid_type")
        self.assertEqual(ctx.exception.field, "ingredients")

    def test_import_endpoint_exposes_privacy_summary_without_echoing_private_fields(self) -> None:
        manifest = self._base_manifest()
        manifest["ingredients"] = [
            {
                "title": "sensitive_source_recording",
                "gps_coordinates": "40.7128,-74.0060",
                "ingredient_digest": "55" * 32,
            }
        ]

        client = create_app().test_client()
        resp = client.post("/api/c2pa/import", json={"manifest": manifest})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["trust_status"], "signature_not_checked")
        self.assertIn("privacy_summary", body)
        self.assertTrue(body["privacy_summary"]["has_source_location"])
        self.assertTrue(body["privacy_summary"]["has_identifying_metadata"])
        self.assertIn("55" * 32, body["privacy_summary"]["asserted_digests"])

        raw_body = json.dumps(body)
        self.assertNotIn("sensitive_source_recording", raw_body)
        self.assertNotIn("40.7128", raw_body)


if __name__ == "__main__":
    unittest.main()
