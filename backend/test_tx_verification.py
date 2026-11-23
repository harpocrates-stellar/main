"""Focused automated test coverage for proof identifier normalization and tx verification."""

from __future__ import annotations

from decimal import Decimal
from unittest import mock

import pytest

from tx_verification import (
    TxVerificationResult,
    normalize_proof_id,
    normalize_tx_hash,
    verify_transaction,
)

VALID_HEX_32 = "a" * 64
VALID_HEX_32_B = "b" * 64


# ---------------------------------------------------------------------------
# normalize_proof_id: Exact Decimal IDs & Valid Hex/Bytes
# ---------------------------------------------------------------------------


def test_normalize_proof_id_accepts_exact_decimal_integers():
    assert normalize_proof_id(0) == "0"
    assert normalize_proof_id(42) == "42"
    assert normalize_proof_id(1000) == "1000"

    # Beyond standard IEEE-754 double precision float (2^53 = 9007199254740992)
    large_int = 9007199254740993
    assert normalize_proof_id(large_int) == "9007199254740993"

    # Very large 128-bit and 256-bit scale integers
    u128_val = (1 << 127) + 12345
    assert normalize_proof_id(u128_val) == str(u128_val)

    u256_val = (1 << 255) + 67890
    assert normalize_proof_id(u256_val) == str(u256_val)


def test_normalize_proof_id_accepts_exact_decimal_strings():
    assert normalize_proof_id("0") == "0"
    assert normalize_proof_id("42") == "42"
    assert normalize_proof_id("9007199254740993") == "9007199254740993"
    assert normalize_proof_id("123456789012345678901234567890") == "123456789012345678901234567890"
    # Preserves leading zeros in digit strings
    assert normalize_proof_id("00123") == "00123"


def test_normalize_proof_id_accepts_hex_and_0x_prefix():
    assert normalize_proof_id(VALID_HEX_32) == VALID_HEX_32
    assert normalize_proof_id("0x" + VALID_HEX_32_B) == VALID_HEX_32_B
    assert normalize_proof_id("0X" + "C" * 64) == "c" * 64
    assert normalize_proof_id("D" * 64) == "d" * 64


def test_normalize_proof_id_accepts_raw_bytes():
    raw = bytes.fromhex(VALID_HEX_32)
    assert normalize_proof_id(raw) == VALID_HEX_32
    assert normalize_proof_id(bytearray(raw)) == VALID_HEX_32


def test_normalize_proof_id_preserves_decimal_precision_without_float_loss():
    # 9007199254740993 in float loses the lowest bit -> 9007199254740992.0
    val = 9007199254740993
    assert float(val) == 9007199254740992.0  # proves float precision loss occurs
    # normalize_proof_id must preserve exact digits without float coercion
    assert normalize_proof_id(val) == "9007199254740993"
    assert normalize_proof_id(str(val)) == "9007199254740993"


# ---------------------------------------------------------------------------
# normalize_proof_id: Rejection of Fractional Inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fractional_val",
    [
        123.45,
        1.0,
        0.0,
        -1.5,
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_normalize_proof_id_rejects_fractional_floats(fractional_val):
    with pytest.raises(ValueError, match="fractional and exponent inputs are rejected"):
        normalize_proof_id(fractional_val)


@pytest.mark.parametrize(
    "fractional_str",
    [
        "123.45",
        "1.0",
        "0.0",
        ".5",
        "1.",
        "-0.5",
        "+1.25",
    ],
)
def test_normalize_proof_id_rejects_fractional_strings(fractional_str):
    with pytest.raises(ValueError, match="cannot be fractional|non-negative"):
        normalize_proof_id(fractional_str)


# ---------------------------------------------------------------------------
# normalize_proof_id: Rejection of Exponent Notation Inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exponent_val",
    [
        1e10,
        1.5e3,
        1e-5,
        2.0e8,
    ],
)
def test_normalize_proof_id_rejects_exponent_floats(exponent_val):
    with pytest.raises(ValueError, match="fractional and exponent inputs are rejected"):
        normalize_proof_id(exponent_val)


@pytest.mark.parametrize(
    "exponent_str",
    [
        "1e10",
        "1E10",
        "1.5e3",
        "1e-5",
        "2.0E+8",
        "-1e10",
        "+1e6",
        "1e0",
    ],
)
def test_normalize_proof_id_rejects_exponent_strings(exponent_str):
    with pytest.raises(ValueError, match="exponent notation|cannot be fractional|non-negative"):
        normalize_proof_id(exponent_str)


# ---------------------------------------------------------------------------
# normalize_proof_id: Rejection of Booleans & Unsafe Integer Coercion
# ---------------------------------------------------------------------------


def test_normalize_proof_id_rejects_booleans():
    with pytest.raises(ValueError, match="boolean"):
        normalize_proof_id(True)
    with pytest.raises(ValueError, match="boolean"):
        normalize_proof_id(False)


@pytest.mark.parametrize(
    "neg_val",
    [
        -1,
        -100,
        "-1",
        "-100",
    ],
)
def test_normalize_proof_id_rejects_negative_values(neg_val):
    with pytest.raises(ValueError, match="non-negative"):
        normalize_proof_id(neg_val)


@pytest.mark.parametrize(
    "malformed_val",
    [
        "",
        "   ",
        "not-a-hash",
        "xyz",
        "0x12",
        "12a45",
        "a" * 63,
        "a" * 65,
    ],
)
def test_normalize_proof_id_rejects_malformed_strings(malformed_val):
    with pytest.raises(ValueError):
        normalize_proof_id(malformed_val)


@pytest.mark.parametrize(
    "bad_type",
    [
        None,
        [],
        {},
        {"id": 1},
        object(),
    ],
)
def test_normalize_proof_id_rejects_unsupported_types(bad_type):
    with pytest.raises(ValueError):
        normalize_proof_id(bad_type)


def test_normalize_proof_id_handles_decimal_module_values():
    assert normalize_proof_id(Decimal("12345")) == "12345"
    assert normalize_proof_id(Decimal("0")) == "0"

    with pytest.raises(ValueError):
        normalize_proof_id(Decimal("12.34"))
    with pytest.raises(ValueError):
        normalize_proof_id(Decimal("-5"))
    with pytest.raises(ValueError):
        normalize_proof_id(Decimal("1e10"))


# ---------------------------------------------------------------------------
# normalize_tx_hash tests
# ---------------------------------------------------------------------------


def test_normalize_tx_hash_valid():
    assert normalize_tx_hash(VALID_HEX_32) == VALID_HEX_32
    assert normalize_tx_hash("0x" + "B" * 64) == "b" * 64


def test_normalize_tx_hash_invalid():
    with pytest.raises(ValueError):
        normalize_tx_hash("not-a-hash")
    with pytest.raises(ValueError):
        normalize_tx_hash(123)
    with pytest.raises(ValueError):
        normalize_tx_hash(None)
