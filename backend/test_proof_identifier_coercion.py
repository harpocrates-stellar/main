from __future__ import annotations

import base64
import json
import struct
from unittest import mock

import pytest

from chain_indexer import (
    classify_and_decode_event,
    decode_scval,
    fetch_contract_events,
    process_events_batch,
)
from db import insert_indexed_proof_event
from fetch_external import FetchResult
from tx_verification import (
    UnsafeProofIdentifierError,
    normalize_proof_identifier,
    parse_strict_uint,
)

CONTRACT_ID = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXGI"


def _encode_u128_scval(value: int) -> str:
    hi = (value >> 64) & 0xFFFFFFFFFFFFFFFF
    lo = value & 0xFFFFFFFFFFFFFFFF
    raw = struct.pack(">IQQ", 9, hi, lo)
    return base64.b64encode(raw).decode("ascii")


def test_preserves_exact_large_decimal_ids_across_scval_json_and_db_boundaries() -> None:
    # Beyond IEEE-754 MAX_SAFE_INTEGER (2^53 - 1 = 9007199254740991) and full u128::MAX
    beyond_js_safe = 9_007_199_254_740_993
    u128_max = (1 << 128) - 1

    assert decode_scval(_encode_u128_scval(u128_max)) == u128_max
    assert normalize_proof_identifier(beyond_js_safe) == "9007199254740993"
    assert normalize_proof_identifier("9007199254740993") == "9007199254740993"
    assert normalize_proof_identifier(u128_max) == "340282366920938463463374607431768211455"

    event = {
        "ledger": 900,
        "id": "0000000900-0000000007",
        "txHash": "61" * 32,
        "topic": ["proof", "revoke", _encode_u128_scval(beyond_js_safe)],
        "value": 2,
    }
    summary = process_events_batch([event], contract_id=CONTRACT_ID)
    assert summary["indexed"] == 1
    assert summary["rejected_identifiers"] == 0

    # Roundtrip through JSON serialization preserves exact decimal string without float loss
    row, created = insert_indexed_proof_event(
        event_type="revoke",
        tx_hash="62" * 32,
        event_index=1,
        proof_id=u128_max,
        contract_id=CONTRACT_ID,
    )
    assert created is True
    serialized = json.loads(json.dumps({"proof_id": row["proof_id"]}))
    assert serialized["proof_id"] == "340282366920938463463374607431768211455"


@pytest.mark.parametrize(
    "bad_id",
    [
        12.5,
        42.0,
        1e5,
        True,
        False,
        -1,
        "12.5",
        "42.0",
        "1e5",
        "1E+18",
        "9.007199254740993e+15",
        "-42",
        "+42",
        "0042",
        "0x1e5",
    ],
)
def test_rejects_fractional_exponent_float_and_boolean_proof_identifiers(bad_id: object) -> None:
    with pytest.raises(UnsafeProofIdentifierError):
        normalize_proof_identifier(bad_id)

    with pytest.raises(UnsafeProofIdentifierError):
        insert_indexed_proof_event(
            event_type="revoke",
            tx_hash="63" * 32,
            event_index=1,
            proof_id=bad_id,  # type: ignore[arg-type]
        )


def test_rejects_exponent_and_fractional_numbers_from_raw_rpc_json() -> None:
    # Raw RPC JSON containing unquoted exponent/fractional numbers (1e5, 10.0)
    raw_rpc_json = (
        '{"jsonrpc":"2.0","id":1,"result":{"events":['
        '{"txHash":"' + ("64" * 32) + '","ledger":100,"eventIndex":1,"topic":["proof","revoke",1e5]},'
        '{"txHash":"' + ("65" * 32) + '","ledger":100.0,"eventIndex":1,"topic":["proof","revoke","' + ("ab" * 32) + '"]},'
        '{"txHash":"' + ("66" * 32) + '","ledger":100,"eventIndex":2,"topic":["proof","revoke",9007199254740993]}'
        ']}}'
    ).encode("utf-8")

    with mock.patch(
        "chain_indexer.safe_urlopen",
        return_value=FetchResult(status=200, body=raw_rpc_json),
    ):
        rpc_res = fetch_contract_events(
            rpc_url="https://soroban-testnet.stellar.org",
            contract_id=CONTRACT_ID,
            start_ledger=100,
        )

    summary = process_events_batch(rpc_res["events"], contract_id=CONTRACT_ID)
    assert summary["scanned"] == 3
    assert summary["rejected_identifiers"] == 2
    assert summary["indexed"] == 1

    with pytest.raises(UnsafeProofIdentifierError):
        parse_strict_uint("1e3", field="event_index")
    with pytest.raises(UnsafeProofIdentifierError):
        classify_and_decode_event(
            {
                "txHash": "67" * 32,
                "eventIndex": "2.5",
                "topic": ["proof", "revoke", "cd" * 32],
            }
        )
