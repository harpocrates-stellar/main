"""Cross-client conformance suite for `contracts/vectors/lifecycle_events_v1.json` (`hpx-ev/1`)."""

from __future__ import annotations

import json
from pathlib import Path
import struct
import unittest

from lifecycle_events import (
    CODEC_ID,
    EVENT_SPECS,
    LifecycleEventError,
    decode_exact_scval,
    decode_lifecycle_event,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[1] / "contracts" / "vectors" / "lifecycle_events_v1.json"
)


class LifecycleEventCorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        cls.cases = cls.corpus["cases"]

    def test_corpus_metadata_and_schema_parity(self) -> None:
        self.assertEqual(self.corpus["format"], "harpocrates.lifecycle-events")
        self.assertEqual(self.corpus["version"], 1)
        self.assertEqual(self.corpus["codec"], CODEC_ID)
        self.assertEqual(set(self.corpus["event_schemas"].keys()), set(EVENT_SPECS.keys()))

        ids = [c["id"] for c in self.cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sum(1 for c in self.cases if c["accept"]), 28)
        self.assertEqual(sum(1 for c in self.cases if not c["accept"]), 8)

    def test_all_positive_transitions_decode_and_match_typed_payloads(self) -> None:
        for case in self.cases:
            if not case["accept"]:
                continue
            with self.subTest(case_id=case["id"]):
                decoded = decode_lifecycle_event(
                    case["topics_xdr_hex"], case["data_xdr_hex"]
                )
                self.assertEqual(decoded.event_name, case["event_name"])
                self.assertEqual(decoded.topics, case["topics"])
                self.assertEqual(decoded.payload, case["payload"])
                self.assertEqual(decoded.topics_canonical, case["topics_canonical"])
                self.assertEqual(decoded.payload_canonical, case["payload_canonical"])

    def test_all_negative_boundary_cases_fail_closed_with_expected_code(self) -> None:
        for case in self.cases:
            if case["accept"]:
                continue
            with self.subTest(case_id=case["id"]):
                with self.assertRaises(LifecycleEventError) as ctx:
                    decode_lifecycle_event(case["topics_xdr_hex"], case["data_xdr_hex"])
                self.assertEqual(ctx.exception.code, case["reject_code"])

    def test_wire_decoder_scalar_and_boundary_branches(self) -> None:
        # Bool true/false, Void, and Contract Address branches
        self.assertEqual(decode_exact_scval("0000000000000001").canonical, "bool:true")
        self.assertEqual(decode_exact_scval("0000000000000000").canonical, "bool:false")
        self.assertEqual(decode_exact_scval("00000001").canonical, "void:null")
        contract_hex = "0000001200000001" + ("ab" * 32)
        self.assertEqual(
            decode_exact_scval(contract_hex).canonical,
            "address_contract:" + ("ab" * 32),
        )

        # Invalid hex & odd length
        for bad_hex in ("abc", "zzzz"):
            with self.assertRaises(LifecycleEventError) as ctx:
                decode_exact_scval(bad_hex)
            self.assertEqual(ctx.exception.code, "malformed_xdr")

        # Invalid bool, truncated u64, truncated fixed32, bad symbol, missing vec/map opt, bad disc
        malformed_Payloads = [
            "0000000000000002",  # invalid bool flag
            "0000000500000001",  # truncated u64
            "0000001200000001aabb",  # truncated fixed32
            "0000000f000000012d000000",  # invalid symbol char '-'
            "0000001000000000",  # ScVec opt=0
            "0000001100000000",  # ScMap opt=0
            "000000120000000000000009" + ("11" * 32),  # bad PublicKeyType
            "0000001200000009",  # bad ScAddress kind
            "000000ff",  # unsupported ScVal discriminant
        ]
        for hx in malformed_Payloads:
            with self.assertRaises(LifecycleEventError) as ctx:
                decode_exact_scval(hx)
            self.assertEqual(ctx.exception.code, "malformed_xdr")

        # Non-vec topics root, single-topic arity, non-map data root, unexpected extra field
        empty_map = "000000110000000100000000"
        with self.assertRaises(LifecycleEventError) as ctx:
            decode_lifecycle_event("00000001", empty_map)
        self.assertEqual(ctx.exception.code, "malformed_xdr")

        one_topic = struct.pack(">IIIII", 16, 1, 1, 15, 4) + b"test"
        with self.assertRaises(LifecycleEventError) as ctx:
            decode_lifecycle_event(one_topic.hex(), empty_map)
        self.assertEqual(ctx.exception.code, "topic_arity_mismatch")

        rev_topics = (
            struct.pack(">III", 16, 1, 3)
            + struct.pack(">II", 15, 7)
            + b"revroot\x00"
            + struct.pack(">II", 15, 3)
            + b"set\x00"
            + struct.pack(">II", 13, 32)
            + (b"\x95" * 32)
        ).hex()
        with self.assertRaises(LifecycleEventError) as ctx:
            decode_lifecycle_event(rev_topics, "00000001")
        self.assertEqual(ctx.exception.code, "payload_schema_mismatch")

        # Non-symbol map key & unexpected extra field on RevocationRootSet
        non_sym_key_map = (
            struct.pack(">III", 17, 1, 1)
            + struct.pack(">II", 3, 1)
            + struct.pack(">II", 3, 2)
        ).hex()
        with self.assertRaises(LifecycleEventError) as ctx:
            decode_lifecycle_event(rev_topics, non_sym_key_map)
        self.assertEqual(ctx.exception.code, "payload_schema_mismatch")

        extra_field_map = (
            struct.pack(">III", 17, 1, 1)
            + struct.pack(">II", 15, 5)
            + b"extra\x00\x00\x00"
            + struct.pack(">II", 3, 1)
        ).hex()
        with self.assertRaises(LifecycleEventError) as ctx:
            decode_lifecycle_event(rev_topics, extra_field_map)
        self.assertEqual(ctx.exception.code, "payload_schema_mismatch")


if __name__ == "__main__":
    unittest.main()
