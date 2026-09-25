"""Constant-time comparison coverage for the verifier-input codec (``hpx-vi/1``).

Protocol bindings (domain tag, revocation separator, zero sentinels) must be
compared without an early exit so that rejecting a tampered value does not leak
how many leading bytes matched. These tests pin both the behaviour (every byte
position is still rejected) and the mechanism (the comparison goes through the
constant-time primitive), and confirm rejections stay privacy-safe.

All values are synthetic.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

import verifier_inputs as vi
from verifier_inputs import (
    FIELD_LEN,
    REVOCATION_DOMAIN_SEPARATOR,
    SILENT_WITNESS_DOMAIN_TAG,
    RejectCode,
    VerifierInputError,
    constant_time_equals,
    parse_revocation_witness_inputs,
    parse_silent_witness_inputs,
)

HALF = (b"\x00" * 16) + (b"\x11" * 16)
ROOT = (b"\x00" * 31) + b"\x07"
NULLIFIER = (b"\x00" * 31) + b"\x09"
REVOCATION_ROOT = (b"\x00" * 31) + b"\x05"


def silent_frame(domain: bytes = SILENT_WITNESS_DOMAIN_TAG) -> bytes:
    return HALF + HALF + ROOT + NULLIFIER + domain


def revocation_frame(domain: bytes = REVOCATION_DOMAIN_SEPARATOR) -> bytes:
    return REVOCATION_ROOT + NULLIFIER + domain + ROOT


def flip(value: bytes, index: int) -> bytes:
    mutated = bytearray(value)
    mutated[index] ^= 0x01
    return bytes(mutated)


# ── Primitive ───────────────────────────────────────────────────────────────


def test_constant_time_equals_accepts_identical_values():
    assert constant_time_equals(SILENT_WITNESS_DOMAIN_TAG, SILENT_WITNESS_DOMAIN_TAG)
    assert constant_time_equals(b"", b"")


def test_constant_time_equals_rejects_length_mismatch():
    assert not constant_time_equals(b"\x00" * 31, b"\x00" * 32)
    assert not constant_time_equals(b"", b"\x00")


@pytest.mark.parametrize("index", range(FIELD_LEN))
def test_constant_time_equals_rejects_a_flip_at_every_position(index):
    assert not constant_time_equals(SILENT_WITNESS_DOMAIN_TAG, flip(SILENT_WITNESS_DOMAIN_TAG, index))


# ── Boundary: a difference anywhere is rejected with the stable code ────────


def test_baseline_frames_are_accepted():
    parse_silent_witness_inputs(silent_frame())
    parse_revocation_witness_inputs(revocation_frame())


@pytest.mark.parametrize("index", range(FIELD_LEN))
def test_silent_witness_domain_tag_flip_is_rejected_at_every_byte(index):
    tampered = flip(SILENT_WITNESS_DOMAIN_TAG, index)
    with pytest.raises(VerifierInputError) as caught:
        parse_silent_witness_inputs(silent_frame(tampered))
    assert caught.value.code is RejectCode.DOMAIN_MISMATCH
    assert caught.value.field == "domain_tag"


@pytest.mark.parametrize("index", range(FIELD_LEN))
def test_revocation_separator_flip_is_rejected_at_every_byte(index):
    tampered = flip(REVOCATION_DOMAIN_SEPARATOR, index)
    with pytest.raises(VerifierInputError) as caught:
        parse_revocation_witness_inputs(revocation_frame(tampered))
    assert caught.value.code is RejectCode.DOMAIN_MISMATCH
    assert caught.value.field == "domain_separator"


# ── Regression: comparisons must go through the constant-time primitive ─────


def test_domain_comparisons_use_the_constant_time_primitive():
    with patch.object(vi.hmac, "compare_digest", wraps=vi.hmac.compare_digest) as spy:
        parse_silent_witness_inputs(silent_frame())
        parse_revocation_witness_inputs(revocation_frame())
    compared = [call.args for call in spy.call_args_list]
    assert (SILENT_WITNESS_DOMAIN_TAG, SILENT_WITNESS_DOMAIN_TAG) in compared
    assert (REVOCATION_DOMAIN_SEPARATOR, REVOCATION_DOMAIN_SEPARATOR) in compared


def test_zero_and_padding_checks_still_reject_with_stable_codes():
    with pytest.raises(VerifierInputError) as zero:
        parse_silent_witness_inputs(HALF + HALF + b"\x00" * 32 + NULLIFIER + SILENT_WITNESS_DOMAIN_TAG)
    assert zero.value.code is RejectCode.ZERO_FIELD

    padded = (b"\x00" * 15) + b"\x01" + (b"\x11" * 16)
    with pytest.raises(VerifierInputError) as padding:
        parse_silent_witness_inputs(padded + HALF + ROOT + NULLIFIER + SILENT_WITNESS_DOMAIN_TAG)
    assert padding.value.code is RejectCode.PADDING


# ── Privacy: rejection never carries compared bytes ─────────────────────────


def test_rejection_message_never_contains_field_material():
    tampered = flip(SILENT_WITNESS_DOMAIN_TAG, 0)
    with pytest.raises(VerifierInputError) as caught:
        parse_silent_witness_inputs(silent_frame(tampered))
    rendered = f"{caught.value} {caught.value.signal()}"
    assert tampered.hex() not in rendered
    assert SILENT_WITNESS_DOMAIN_TAG.hex() not in rendered
    assert str(caught.value) == "domain_mismatch:domain_tag"
