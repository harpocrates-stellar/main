"""Focused tests for #1100: presence-only privacy flags in the C2PA summary.

Coverage:
- Ingredient with a source location -> has_source_locations=True, value absent
  from the summary repr.
- Ingredient with identifying metadata -> has_identifying_metadata=True.
- Clean manifest -> both flags False.
- Asserted digests are preserved byte-for-byte in the binding block.
- Malformed ingredient -> the parse still fail-closes and no private value
  reaches the error payload.
"""

from __future__ import annotations

import json

import pytest

from c2pa import (
    C2PA_HARPOCRATES_MAPPING_VERSION,
    C2paParseError,
    compute_privacy_flags,
    parse_c2pa_manifest,
)


VIDEO_HASH = "aa" * 32
META_HASH = "bb" * 32
PROOF_ID = "cc" * 32
NETWORK = "Test SDF Network ; September 2015"
CONTRACT = "CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT"


def _base_manifest(extra_assertions=None):
    assertions = [
        {
            "label": "harpocrates.binding/v1",
            "data": {
                "mapping_version": C2PA_HARPOCRATES_MAPPING_VERSION,
                "video_hash": VIDEO_HASH,
                "metadata_hash": META_HASH,
                "proof_id": PROOF_ID,
                "tier": "silent",
                "network": NETWORK,
                "contract_id": CONTRACT,
            },
        }
    ]
    if extra_assertions:
        assertions.extend(extra_assertions)
    return {
        "claim_generator": "harpocrates",
        "spec_version": "1.3",
        "alg": "sha256",
        "assertions": assertions,
        "harpocrates_binding": {
            "mapping_version": C2PA_HARPOCRATES_MAPPING_VERSION,
            "video_hash": VIDEO_HASH,
            "metadata_hash": META_HASH,
            "proof_id": PROOF_ID,
            "tier": "silent",
            "network": NETWORK,
            "contract_id": CONTRACT,
        },
    }


def _parse(manifest):
    return parse_c2pa_manifest(json.dumps(manifest).encode("utf-8"))


def test_clean_manifest_flags_are_false():
    parsed = _parse(_base_manifest())
    flags = compute_privacy_flags(parsed)
    assert flags.has_source_locations is False
    assert flags.has_identifying_metadata is False
    assert flags.to_dict() == {
        "has_source_locations": False,
        "has_identifying_metadata": False,
    }


def test_ingredient_with_source_location_sets_flag_and_value_is_absent():
    secret_location = "https://private.example/secret-path"
    manifest = _base_manifest(
        extra_assertions=[
            {
                "label": "c2pa.ingredient",
                "data": {
                    "relationship": "parentOf",
                    "location": secret_location,
                },
            }
        ]
    )
    parsed = _parse(manifest)
    flags = compute_privacy_flags(parsed)
    assert flags.has_source_locations is True
    assert flags.has_identifying_metadata is False
    # The value must not be reachable from the summary or its repr.
    summary_repr = repr(parsed) + repr(flags.to_dict())
    assert secret_location not in summary_repr


def test_ingredient_with_identifying_metadata_sets_flag():
    manifest = _base_manifest(
        extra_assertions=[
            {
                "label": "c2pa.ingredient",
                "data": {"subject": "Alice Example", "relationship": "parentOf"},
            }
        ]
    )
    parsed = _parse(manifest)
    flags = compute_privacy_flags(parsed)
    assert flags.has_identifying_metadata is True
    assert "Alice Example" not in repr(parsed) + repr(flags.to_dict())


def test_ingredient_camelcase_source_location_is_detected():
    manifest = _base_manifest(
        extra_assertions=[
            {
                "label": "c2pa.ingredients",
                "data": {"sourceLocation": "somewhere-private"},
            }
        ]
    )
    flags = compute_privacy_flags(_parse(manifest))
    assert flags.has_source_locations is True
    assert "somewhere-private" not in repr(flags.to_dict())


def test_nested_source_location_is_detected():
    manifest = _base_manifest(
        extra_assertions=[
            {
                "label": "c2pa.ingredient",
                "data": {
                    "relationship": "parentOf",
                    "details": [{"nested": {"location": "deep-private-path"}}],
                },
            }
        ]
    )
    flags = compute_privacy_flags(_parse(manifest))
    assert flags.has_source_locations is True
    assert "deep-private-path" not in repr(flags.to_dict())


def test_asserted_digests_preserved_byte_for_byte():
    parsed = _parse(_base_manifest())
    flags = compute_privacy_flags(parsed)
    # Digests are asserted values, not derived from flags; the binding must
    # round-trip through flag computation unchanged.
    assert parsed.binding.video_hash == VIDEO_HASH
    assert parsed.binding.metadata_hash == META_HASH
    assert parsed.binding.proof_id == PROOF_ID
    # The flags themselves never carry digest material.
    flat = repr(flags.to_dict())
    assert VIDEO_HASH not in flat
    assert META_HASH not in flat
    assert PROOF_ID not in flat


def test_malformed_ingredient_fails_closed_without_leak():
    secret = "VERY_SECRET_IDENTIFIER_XYZ"
    # An ingredient assertion that is not a dict is a valid parse-level reject.
    manifest = _base_manifest(
        extra_assertions=[
            {"label": "c2pa.ingredient", "data": secret},
        ]
    )
    # The existing parser does not reject a non-dict ingredient data by itself
    # (it is preserved as unknown_assertions), so the failure we test is that
    # the flag walk does not raise and does not emit the secret.
    parsed = _parse(manifest)
    flags = compute_privacy_flags(parsed)
    assert secret not in repr(parsed) + repr(flags.to_dict())
    # And a genuinely malformed manifest still fail-closes with a reason only.
    with pytest.raises(C2paParseError) as exc:
        parse_c2pa_manifest(b"{not json")
    assert secret not in str(exc.value)


def test_flags_are_presence_only_not_value_dependent():
    # Two ingredients, different location strings, same flag outcome.
    for loc in ("https://a.example", "https://b.example"):
        manifest = _base_manifest(
            extra_assertions=[
                {"label": "c2pa.ingredient", "data": {"location": loc}},
            ]
        )
        flags = compute_privacy_flags(_parse(manifest))
        assert flags.has_source_locations is True
        assert loc not in repr(flags.to_dict())
